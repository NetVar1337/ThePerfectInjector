// Mapper/stub verification harness: exercises Mp_MapDllAndCreateHookEntry
// against a real system DLL with an ordinary VirtualAlloc backend and checks
// the parts that would fail silently in a live injection (relocations, IAT
// resolution incl. ordinals, security cookie, header wipe, stub encoding).
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <vector>
#include <string>
#include "SimpleMapper.h"
#pragma comment(lib, "psapi.lib")

static int g_Failures = 0;

static void Check( bool Cond, const char* What )
{
	printf( "%s %s\n", Cond ? "[PASS]" : "[FAIL]", What );
	if ( !Cond )
		g_Failures++;
}

int main( int argc, char** argv )
{
	// A stand-in for the hooked function: the stub reads its first dword.
	static BYTE FakeEntry[ 16 ] = { 0xE9, 0x11, 0x22, 0x33, 0x44 };
	static BYTE FakeTarget[ 16 ] = { 0xC3 };

	std::string Dll = argc > 1 ? argv[ 1 ] : "C:\\Windows\\System32\\version.dll";
	std::vector<PVOID> Blocks;

	auto Alloc = [ & ] ( SIZE_T Size ) -> PVOID
	{
		PVOID P = VirtualAlloc( nullptr, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
		if ( P )
			memset( P, 0, Size );
		Blocks.push_back( P );
		return P;
	};

	TlsLockedHookController* Ctrl =
		Mp_MapDllAndCreateHookEntry( Dll, FakeEntry, FakeTarget, true, Alloc, true, nullptr );

	Check( Ctrl != nullptr, "map returned a controller" );
	if ( !Ctrl )
		return 1;

	BYTE* Memory = ( BYTE* ) Ctrl;

	// The stub is built twice (dry run + real), the size is stable.
	auto Dry = Mp_BuildStub( 0, 0, 0, 0, 0, 0x10000000 );
	uint32_t StubSize = ( uint32_t ) Dry.size();
	uint64_t ImageMemory = ( ( uint64_t ) Memory + StubSize + 0xFFF ) & ( ~0xFFF );

	printf( "[i] stub size %u, image at %p\n", StubSize, ( void* ) ImageMemory );

	// --- stub encoding ---
	Check( Memory[ 0 ] == 0 && Memory[ 1 ] == 0, "stub data bytes at [0],[1]" );
	Check( Memory[ 2 ] == 0xF0 && Memory[ 3 ] == 0xFE && Memory[ 4 ] == 0x05, "lock inc opcode" );

	int32_t Disp = *( int32_t* ) ( Memory + 5 );
	Check( Disp == ( int32_t ) ( 1 - ( 2 + 3 + 4 ) ), "lock inc targets NumThreadsWaiting (rip+1)" );

	// The wait loop must test IsFree at offset 0 and release when it turns
	// non-zero (this bit was wrong once: an inverted branch or a disp32 that
	// ignores the trailing imm8 makes the payload silently never run).
	BYTE* Cmp = nullptr;

	for ( uint32_t i = 2; i + 8 < StubSize; i++ )
	{
		if ( Memory[ i ] == 0x80 && Memory[ i + 1 ] == 0x3D )
		{
			Cmp = Memory + i;
			break;
		}
	}

	Check( Cmp != nullptr, "found the IsFree compare" );

	if ( Cmp )
	{
		int32_t CmpDisp = *( int32_t* ) ( Cmp + 2 );
		BYTE* InstrEnd = Cmp + 7; // 80 3D disp32 imm8

		Check( ( InstrEnd + CmpDisp ) == Memory + 0, "IsFree compare targets offset 0" );
		Check( Cmp[ 7 ] == 0x75, "wait loop releases on IsFree != 0 (jne)" );
	}

	// The `call payload_entry` must land on `mov rcx, <image base>`.
	const BYTE Sig[] = { 0x48, 0x83, 0xE4, 0xF0, 0xE8 };
	BYTE* CallSite = nullptr;

	for ( uint32_t i = 2; i + sizeof( Sig ) + 4 < StubSize; i++ )
	{
		if ( !memcmp( Memory + i, Sig, sizeof( Sig ) ) )
		{
			CallSite = Memory + i + sizeof( Sig );
			break;
		}
	}

	Check( CallSite != nullptr, "found the call to the payload entry" );

	if ( CallSite )
	{
		int32_t Rel = *( int32_t* ) CallSite;
		BYTE* Target = CallSite + 4 + Rel;

		Check( Target >= Memory && Target < Memory + StubSize, "call target inside the stub" );
		Check( Target[ 0 ] == 0x48 && Target[ 1 ] == 0xB9, "payload entry starts with mov rcx, imm64" );
		Check( *( uint64_t* ) ( Target + 2 ) == ImageMemory, "payload entry loads the image base" );

		// mov rax, <entry point>; jmp rax
		BYTE* Tail = Target + 10 + 7 + 3;
		Check( Tail[ 0 ] == 0x48 && Tail[ 1 ] == 0xB8, "entry point load" );
		Check( *( uint64_t* ) ( Tail + 2 ) == ImageMemory + 0x1000 || *( uint64_t* ) ( Tail + 2 ) > ImageMemory,
			"entry point is inside the image" );
	}

	// --- image ---
	auto Dos = ( PIMAGE_DOS_HEADER ) ImageMemory;
	Check( Dos->e_magic == 0, "PE headers wiped" );

	auto File = Mp_ReadFile( Dll );
	auto FDos = ( PIMAGE_DOS_HEADER ) File.data();
	auto FNt = ( PIMAGE_NT_HEADERS ) ( File.data() + FDos->e_lfanew );

	uint64_t Delta = ImageMemory - FNt->OptionalHeader.ImageBase;

	// Relocation: every DIR64 fixup site must have moved by Delta.
	auto& RelocDir = FNt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
	BYTE* Reloc = ( BYTE* ) Mp_RvaToPointer( File.data(), RelocDir.VirtualAddress );
	uint32_t Processed = 0, Bad = 0;

	for ( uint32_t c = 0; c < RelocDir.Size; )
	{
		auto Block = ( PIMAGE_BASE_RELOCATION ) ( Reloc + c );
		if ( !Block->SizeOfBlock )
			break;

		LPWORD Chain = ( LPWORD ) ( ( PUCHAR ) Block + sizeof( IMAGE_BASE_RELOCATION ) );
		uint32_t Count = ( Block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / 2;

		for ( uint32_t i = 0; i < Count; i++ )
		{
			if ( ( Chain[ i ] >> 12 ) == IMAGE_REL_BASED_DIR64 )
			{
				uint64_t Site = ImageMemory + Block->VirtualAddress + ( Chain[ i ] & 0xFFF );
				uint64_t Orig = *( uint64_t* ) Mp_RvaToPointer( File.data(), Block->VirtualAddress + ( Chain[ i ] & 0xFFF ) );

				if ( *( uint64_t* ) Site != Orig + Delta )
					Bad++;

				Processed++;
			}
		}
		c += Block->SizeOfBlock;
	}

	printf( "[i] checked %u DIR64 relocations\n", Processed );
	Check( Processed > 0 && Bad == 0, "relocations applied with the right delta" );

	// IAT: every resolved entry must be a plausible user-mode function pointer.
	auto& ImpDir = FNt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	auto Imp = ( PIMAGE_IMPORT_DESCRIPTOR ) Mp_RvaToPointer( File.data(), ImpDir.VirtualAddress );

	uint32_t Imports = 0, Ordinals = 0, BadIat = 0;

	for ( ; Imp->Name; Imp++ )
	{
		PCHAR Mod = ( PCHAR ) Mp_RvaToPointer( File.data(), Imp->Name );
		auto Thunk = Imp->OriginalFirstThunk ? ( PIMAGE_THUNK_DATA ) Mp_RvaToPointer( File.data(), Imp->OriginalFirstThunk )
											: ( PIMAGE_THUNK_DATA ) Mp_RvaToPointer( File.data(), Imp->FirstThunk );
		auto Func = ( PIMAGE_THUNK_DATA ) ( ImageMemory + Imp->FirstThunk );

		for ( ; Thunk->u1.AddressOfData; Thunk++, Func++ )
		{
			bool IsOrdinal = IMAGE_SNAP_BY_ORDINAL( Thunk->u1.Ordinal ) != 0;
			uint64_t Resolved = Func->u1.Function;

			if ( IsOrdinal )
				Ordinals++;

			if ( Resolved < 0x10000 || Resolved > 0x7FFFFFFEFFFFull )
			{
				printf( "    bad iat entry %s!%s = %llx\n", Mod,
					IsOrdinal ? "<ordinal>" : ( ( PIMAGE_IMPORT_BY_NAME ) Mp_RvaToPointer( File.data(), ( DWORD ) Thunk->u1.AddressOfData ) )->Name,
					Resolved );
				BadIat++;
			}

			Imports++;
		}
	}

	printf( "[i] checked %u imports (%u by ordinal)\n", Imports, Ordinals );
	Check( Imports > 0 && BadIat == 0, "IAT fully resolved at map time (incl. ordinals)" );

	// Security cookie must not survive as the default value.
	const uint64_t DefaultCookie = 0x00002B992DDFA232ull;
	bool CookieSeen = false;

	for ( uint32_t i = 0; i + 8 <= FNt->OptionalHeader.SizeOfImage; i += 8 )
	{
		if ( *( uint64_t* ) ( ImageMemory + i ) == DefaultCookie )
			CookieSeen = true;
	}

	Check( !CookieSeen, "__security_cookie no longer holds the default value" );

	for ( PVOID P : Blocks )
		VirtualFree( P, 0, MEM_RELEASE );

	printf( "\n%s (%d failures)\n", g_Failures ? "FAILED" : "ALL CHECKS PASSED", g_Failures );
	return g_Failures ? 1 : 0;
}
