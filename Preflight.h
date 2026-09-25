#pragma once
#include <Windows.h>
#include <intrin.h>
#include "NtDefines.h"

//
// Safety preflight.
//
// Two of the techniques in this project can bugcheck a machine if they run in
// the wrong environment, so the environment is checked before anything kernel
// related happens and the tool refuses to start when it is not safe:
//
//   * the passive-call stub is copied into pool memory and executed. Under
//     HVCI / Memory Integrity pool pages are non-executable, so that is a
//     guaranteed kernel fault -> hard stop.
//   * exposing pages to a process by flipping U/S bits mutates page tables.
//     Kernel-half tables are shared between processes when KVA shadow is off,
//     so the change would affect every process and corrupt shared tables
//     -> hard stop unless explicitly overridden.
//
// Everything else in the chain fails soft: no elevation, no driver signature,
// no target: the tool reports and exits instead of pushing on.
//

#define SystemCodeIntegrityInformation 0x67

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
{
	ULONG Length;
	ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION;

#define CI_ENABLED              0x0001
#define CI_TESTSIGN             0x0002
#define CI_UMCI_ENABLED         0x0004
#define CI_TEST_BUILD           0x0020
#define CI_PREPRODUCTION_BUILD  0x0040
#define CI_DEBUGMODE_ENABLED    0x0080
#define CI_HVCI_KMCI_ENABLED    0x0400
#define CI_HVCI_KMCI_AUDITMODE  0x0800
#define CI_HVCI_KMCI_STRICTMODE 0x1000
#define CI_HVCI_IUM_ENABLED     0x2000

struct Mp_Preflight
{
	bool Elevated;
	bool HvciEnabled;
	bool HvciAuditOnly;
	bool TestSigning;
	bool SecureBoot;
	bool KvasLikely;        // heuristic, confirmed after the controller comes up
	bool AmdCpu;
	ULONG BuildNumber;
	ULONG CiOptions;
	bool Blocked;
	const char* BlockReason;
};

static bool Mp_IsElevated()
{
	BOOL Elevated = FALSE;
	HANDLE Token = nullptr;

	if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &Token ) )
		return false;

	TOKEN_ELEVATION Elevation = {};
	DWORD Size = 0;
	if ( GetTokenInformation( Token, TokenElevation, &Elevation, sizeof( Elevation ), &Size ) )
		Elevated = Elevation.TokenIsElevated;

	CloseHandle( Token );
	return Elevated == TRUE;
}

static bool Mp_SecureBootEnabled()
{
	// Returns 1 when Secure Boot is on, 0 when off, and fails when the variable
	// does not exist (legacy BIOS box).
	BYTE Value = 0xFF;
	DWORD Got = GetFirmwareEnvironmentVariableA( "SecureBoot",
		"{8be4df61-93ca-11d2-aa0d-00e098032b8c}", &Value, sizeof( Value ) );
	return Got == 1 && Value == 1;
}

static void Mp_CpuVendor( bool* OutAmd, bool* OutIntel )
{
	int Info[ 4 ] = {};
	__cpuid( Info, 0 );
	char Vendor[ 13 ] = {};
	memcpy( Vendor + 0, &Info[ 1 ], 4 );
	memcpy( Vendor + 4, &Info[ 3 ], 4 );
	memcpy( Vendor + 8, &Info[ 2 ], 4 );
	*OutAmd = strncmp( Vendor, "AuthenticAMD", 12 ) == 0;
	*OutIntel = strncmp( Vendor, "GenuineIntel", 12 ) == 0;
}

// Read-only: safe to run on any machine.
static Mp_Preflight Mp_RunPreflight()
{
	Mp_Preflight P = {};

	P.Elevated = Mp_IsElevated();
	P.SecureBoot = Mp_SecureBootEnabled();

	OSVERSIONINFOEXA Osvi = { sizeof( Osvi ) };
	// RtlGetVersion is the only version API that does not lie about the build.
	NTSTATUS St = __NtRoutine( "RtlGetVersion", &Osvi );
	P.BuildNumber = ( St == 0 ) ? Osvi.dwBuildNumber : 0;

	SYSTEM_CODEINTEGRITY_INFORMATION Ci = { sizeof( Ci ), 0 };
	ULONG Returned = 0;
	NTSTATUS Cs = __NtRoutine( "NtQuerySystemInformation", SystemCodeIntegrityInformation, &Ci, sizeof( Ci ), &Returned );

	if ( Cs == 0 )
		P.CiOptions = Ci.CodeIntegrityOptions;

	P.HvciEnabled = ( P.CiOptions & ( CI_HVCI_KMCI_ENABLED | CI_HVCI_IUM_ENABLED ) ) != 0;
	P.HvciAuditOnly = ( P.CiOptions & CI_HVCI_KMCI_AUDITMODE ) != 0;
	P.TestSigning = ( P.CiOptions & CI_TESTSIGN ) != 0;

	bool Intel = false;
	Mp_CpuVendor( &P.AmdCpu, &Intel );
	// KVA shadow is enabled on Meltdown-vulnerable Intel parts and off on AMD.
	// AMD therefore runs with shared kernel page tables, which is the case the
	// exposure step must not touch. Confirmed again against the live EPROCESS.
	P.KvasLikely = Intel;

	if ( P.HvciEnabled && !P.HvciAuditOnly )
	{
		P.Blocked = true;
		P.BlockReason = "HVCI / Memory Integrity is enabled: the passive-call stub is "
						"copied into pool memory and executed, and pool pages are "
						"non-executable under HVCI. That is a guaranteed kernel fault.";
	}
	else if ( !P.Elevated )
	{
		P.Blocked = true;
		P.BlockReason = "not elevated: the driver cannot be loaded, so the physical "
						"memory controller cannot come up. Run as administrator.";
	}
	else if ( P.BuildNumber && P.BuildNumber < 10240 )
	{
		P.Blocked = true;
		P.BlockReason = "unsupported build: the offsets and page-table handling here "
						"target Windows 10 x64 and later.";
	}

	return P;
}

static void Mp_PrintPreflight( const Mp_Preflight& P )
{
	printf( "[safety] elevated          : %s\n", P.Elevated ? "yes" : "NO" );
	printf( "[safety] build             : %u\n", P.BuildNumber );
	printf( "[safety] code integrity    : 0x%08x\n", P.CiOptions );
	printf( "[safety] HVCI / MemInteg   : %s%s\n",
		P.HvciEnabled ? "ENABLED" : "off",
		P.HvciAuditOnly ? " (audit only)" : "" );
	printf( "[safety] test signing      : %s\n", P.TestSigning ? "on" : "off" );
	printf( "[safety] secure boot       : %s\n", P.SecureBoot ? "on" : "off" );
	printf( "[safety] cpu               : %s\n", P.AmdCpu ? "AMD (kernel tables shared, KVA shadow off)" : "non-AMD" );
	printf( "[safety] kva shadow        : %s (heuristic, re-checked against the live EPROCESS)\n",
		P.KvasLikely ? "likely on" : "likely OFF" );

	if ( P.Blocked )
		printf( "\n[safety] REFUSING TO RUN: %s\n", P.BlockReason );
}
