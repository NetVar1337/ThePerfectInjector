#pragma once
#include <Windows.h>
#include <intrin.h>
#include <fstream>
#include <vector>
#include <functional>
#include <cstring>
#include <cstdint>

#pragma pack(push, 1)
struct TlsLockedHookController
{
	BYTE IsFree;
	BYTE NumThreadsWaiting;
	BYTE Done;
	BYTE EntryBytes;
};
#pragma pack(pop)

// Bounds of what the mapper produced: the stub block and the page-aligned
// image inside it. The image is what gets encrypted at rest; the stub has to
// stay live because the injector polls its counters.
struct Mp_Region
{
	uint64_t BlockBase;
	uint32_t BlockSize;
	uint64_t ImageBase;
	uint32_t ImageSize;
};

//
// Layout of the allocated block (kept identical to the original design):
//   [0] = IsFree              (data, written by the injector)
//   [1] = NumThreadsWaiting   (data, written by the stub)
//   [2] = Done                (data, set once the payload has returned)
//   [3] = EntryBytes          (first opcode of the stub, this is the hook target)
//   ...
//   [page aligned] = mapped image
//
// Improvements over the original:
//   * No import shellcode runs inside the target. Imports are resolved at map
//     time from the injector (per-boot ASLR => identical module/function
//     addresses in every process), so there is no LoadLibrary/GetProcAddress
//     telemetry, no module list growth and no call stack with a kernel return
//     address inside the target.
//   * Ordinal imports are supported (the original asserted and then crashed).
//   * __security_cookie is randomized so /GS payloads do not die in
//     __report_gsfailure.
//   * PE headers are wiped after mapping so the kernel allocation does not
//     carry a resident MZ/PE signature.
//   * The stub is built with a small assembler so every RIP-relative
//     displacement is computed, not hand-encoded.
//   * Bounded spin-locks: if the injector dies, threads fall through to the
//     original function instead of hanging the game forever.
//   * The call/ret pair around the payload entry stays balanced so hardware
//     shadow stacks (CET) do not trip a #CP.
//

static std::vector<BYTE> Mp_ReadFile( const std::string& Path )
{
	std::ifstream Stream( Path, std::ios::binary | std::ios::ate );
	std::ifstream::pos_type Pos = Stream.tellg();

	if ( Pos == ( std::ifstream::pos_type ) - 1 )
		return {};

	std::vector<BYTE> Data( Pos );
	Stream.seekg( 0, std::ios::beg );
	Stream.read( ( char* ) &Data[ 0 ], Pos );

	return Data;
}

static void * Mp_RvaToPointer( BYTE* Image, DWORD Va )
{
	PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER ) Image;
	PIMAGE_NT_HEADERS FileHeader = ( PIMAGE_NT_HEADERS ) ( ( uint64_t ) DosHeader + DosHeader->e_lfanew );

	PIMAGE_SECTION_HEADER SectionHeader = ( PIMAGE_SECTION_HEADER )
		( ( ( ULONG_PTR ) &FileHeader->OptionalHeader ) + FileHeader->FileHeader.SizeOfOptionalHeader );

	for ( int i = 0; i < FileHeader->FileHeader.NumberOfSections; i++ )
	{
		char * Name = ( char* ) SectionHeader[ i ].Name;
		DWORD RawData = SectionHeader[ i ].PointerToRawData;
		DWORD VirtualAddress = SectionHeader[ i ].VirtualAddress;
		DWORD RawSize = SectionHeader[ i ].SizeOfRawData;
		DWORD VirtualSize = SectionHeader[ i ].Misc.VirtualSize;

		if ( Va >= VirtualAddress &&
			 Va < ( VirtualAddress + VirtualSize ) )
		{
			return Image + Va - VirtualAddress + RawData;
		}
	}
	return Image + Va;
}

// Tiny assembler: everything RIP-relative is patched, nothing is hand-computed.
struct Mp_Asm
{
	std::vector<BYTE> B;

	size_t Pos() const { return B.size(); }

	void Raw( std::initializer_list<BYTE> Bytes ) { B.insert( B.end(), Bytes ); }
	void Skip( size_t N ) { B.resize( B.size() + N ); }
	void U32( uint32_t V ) { size_t P = B.size(); B.resize( P + 4 ); memcpy( &B[ P ], &V, 4 ); }
	void U64( uint64_t V ) { size_t P = B.size(); B.resize( P + 8 ); memcpy( &B[ P ], &V, 8 ); }

	void PatchRel32( size_t At, size_t Target )
	{
		*( int32_t* ) ( &B[ At ] ) = ( int32_t ) ( Target - ( At + 4 ) );
	}

	void PatchRel8( size_t At, size_t Target )
	{
		int32_t D = ( int32_t ) ( Target - ( At + 1 ) );
		if ( D < -128 || D > 127 )
		{
			printf( "[!] Mp_Asm: rel8 out of range (%d), stub layout changed?\n", D );
			D = 0;
		}
		B[ At ] = ( BYTE ) ( int8_t ) D;
	}
};

// rip-relative helpers, target = offset inside the same buffer
static void Mp_X_RipIncByte( Mp_Asm& A, size_t Target )
{
	A.Raw( { 0xF0, 0xFE, 0x05 } );
	size_t At = A.Pos();
	A.Skip( 4 );
	A.PatchRel32( At, Target );
}

static void Mp_X_RipDecByte( Mp_Asm& A, size_t Target )
{
	A.Raw( { 0xF0, 0xFE, 0x0D } );
	size_t At = A.Pos();
	A.Skip( 4 );
	A.PatchRel32( At, Target );
}

static void Mp_X_RipCmpByteImm8( Mp_Asm& A, size_t Target, BYTE Imm )
{
	A.Raw( { 0x80, 0x3D } );
	size_t At = A.Pos();
	A.Skip( 4 );
	A.Raw( { Imm } );
	// the trailing imm8 shifts the rip base by one byte compared to a bare disp32
	*( int32_t* ) ( &A.B[ At ] ) = ( int32_t ) ( Target - ( At + 5 ) );
}

//
// Stub layout:
//   [0] IsFree
//   [1] NumThreadsWaiting
//   [2] code...
//
static std::vector<BYTE> Mp_BuildStub
(
	uint64_t ValCheck,     // &TlsGetValue (hooked entry), data-sync polls this
	uint32_t ValCheckOrig, // first dword of the unhooked entry
	uint64_t HookOut,      // original implementation, tail-jumped to
	uint64_t ImageBase,    // mapped image base
	uint64_t EntryPoint,   // image entry point (DllMain)
	uint32_t SpinCap       // bounded wait, prevents a dead injector from hanging the game
)
{
	Mp_Asm A;

	// data
	A.Raw( { 0x00, 0x00, 0x00 } );

	const size_t IsFree = 0;
	const size_t NumWaiting = 1;
	const size_t DoneFlag = 2;

	// lock inc byte [NumWaiting]
	Mp_X_RipIncByte( A, NumWaiting );

	// mov ecx, SpinCap
	A.Raw( { 0xB9 } );
	A.U32( SpinCap );

	// wait_lock:
	size_t WaitLock = A.Pos();
	Mp_X_RipCmpByteImm8( A, IsFree, 0x00 );      // cmp byte [IsFree], 0
	A.Raw( { 0x75 } ); size_t JneFree = A.Pos(); A.Skip( 1 );   // jne got_free (exit when released)
	A.Raw( { 0xF3, 0x90 } );                      // pause
	A.Raw( { 0xFF, 0xC9 } );                      // dec ecx
	A.Raw( { 0x75 } ); size_t JnzWait = A.Pos(); A.Skip( 1 );  // jnz wait_lock
	A.PatchRel8( JnzWait, WaitLock );
	A.Raw( { 0xEB } ); size_t JmpTimeout = A.Pos(); A.Skip( 1 );

	// got_free: spin until the hooked bytes are restored (data visibility barrier)
	size_t GotFree = A.Pos();
	A.PatchRel8( JneFree, GotFree );

	A.Raw( { 0x48, 0xB8 } ); A.U64( ValCheck );   // mov rax, &TlsGetValue

	// data_sync_lock:
	size_t SyncLock = A.Pos();
	A.Raw( { 0x0F, 0x0D, 0x08 } );                 // prefetchw [rax]
	A.Raw( { 0x81, 0x38 } ); A.U32( ValCheckOrig );// cmp dword [rax], orig
	A.Raw( { 0x74 } ); size_t JeSync = A.Pos(); A.Skip( 1 );
	A.Raw( { 0xF3, 0x90 } );                       // pause
	A.Raw( { 0xFF, 0xC9 } );                       // dec ecx (bounded)
	A.Raw( { 0x75 } ); size_t JnzSync = A.Pos(); A.Skip( 1 );
	A.PatchRel8( JnzSync, SyncLock );

	// exactly one thread runs the payload (atomic test of the counter hitting zero)
	size_t SyncDone = A.Pos();
	A.PatchRel8( JeSync, SyncDone );

	Mp_X_RipDecByte( A, NumWaiting );              // lock dec byte [NumWaiting]
	A.Raw( { 0x75 } ); size_t JnzCont = A.Pos(); A.Skip( 1 );

	// --- payload invocation on a legitimate game thread ---
	A.Raw( { 0x53 } );                             // push rbx
	A.Raw( { 0x51 } );                             // push rcx
	A.Raw( { 0x52 } );                             // push rdx
	A.Raw( { 0x56 } );                             // push rsi
	A.Raw( { 0x57 } );                             // push rdi
	A.Raw( { 0x55 } );                             // push rbp
	A.Raw( { 0x41, 0x50 } );                       // push r8
	A.Raw( { 0x41, 0x51 } );                       // push r9
	A.Raw( { 0x41, 0x52 } );                       // push r10
	A.Raw( { 0x41, 0x53 } );                       // push r11
	A.Raw( { 0x41, 0x54 } );                       // push r12
	A.Raw( { 0x41, 0x55 } );                       // push r13
	A.Raw( { 0x41, 0x56 } );                       // push r14
	A.Raw( { 0x41, 0x57 } );                       // push r15
	A.Raw( { 0x9C } );                             // pushfq
	A.Raw( { 0x48, 0x89, 0xE5 } );                 // mov rbp, rsp
	A.Raw( { 0x48, 0x83, 0xEC, 0x28 } );           // sub rsp, 0x28
	A.Raw( { 0x48, 0x83, 0xE4, 0xF0 } );           // and rsp, ~0xF  (ABI align before call)

	A.Raw( { 0xE8 } ); size_t CallStub = A.Pos(); A.Skip( 4 );  // call payload_entry

	Mp_X_RipIncByte( A, DoneFlag );                // lock inc [Done] once the payload returned

	A.Raw( { 0x48, 0x89, 0xEC } );                 // mov rsp, rbp
	A.Raw( { 0x9D } );                             // popfq
	A.Raw( { 0x41, 0x5F } );
	A.Raw( { 0x41, 0x5E } );
	A.Raw( { 0x41, 0x5D } );
	A.Raw( { 0x41, 0x5C } );
	A.Raw( { 0x41, 0x5B } );
	A.Raw( { 0x41, 0x5A } );
	A.Raw( { 0x41, 0x59 } );
	A.Raw( { 0x41, 0x58 } );
	A.Raw( { 0x5D } );
	A.Raw( { 0x5F } );
	A.Raw( { 0x5E } );
	A.Raw( { 0x5A } );
	A.Raw( { 0x59 } );
	A.Raw( { 0x5B } );

	// continue_exec: tail call into the original implementation
	size_t Cont = A.Pos();
	A.PatchRel8( JnzCont, Cont );

	A.Raw( { 0x48, 0xB8 } ); A.U64( HookOut );     // mov rax, HookOut
	A.Raw( { 0xFF, 0xE0 } );                       // jmp rax

	// timeout path: bail out and let the game continue untouched
	size_t Timeout = A.Pos();
	A.PatchRel8( JmpTimeout, Timeout );
	A.Raw( { 0xEB } ); size_t JmpCont2 = A.Pos(); A.Skip( 1 );
	A.PatchRel8( JmpCont2, Cont );

	// payload_entry: called from the aligned frame above, returns with `ret`
	// (call/ret stays balanced => hardware shadow stacks are happy)
	size_t PayloadEntry = A.Pos();
	A.PatchRel32( CallStub, PayloadEntry );

	A.Raw( { 0x48, 0xB9 } ); A.U64( ImageBase );   // mov rcx, ImageBase
	A.Raw( { 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00 } ); // mov rdx, 1 (DLL_PROCESS_ATTACH)
	A.Raw( { 0x4D, 0x31, 0xC0 } );                 // xor r8, r8
	A.Raw( { 0x48, 0xB8 } ); A.U64( EntryPoint );  // mov rax, EntryPoint
	A.Raw( { 0xFF, 0xE0 } );                       // jmp rax (DllMain `ret`s to the call above)

	return A.B;
}

// Resolve the IAT at map time. Nothing runs inside the target: module bases and
// export addresses are identical in every process of a boot session (per-boot
// ASLR), so the addresses resolved here are valid in the target as well.
static bool Mp_ResolveImports( BYTE* Image, PVOID MappedAdr, bool AllowLoad )
{
	PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER ) Image;
	PIMAGE_NT_HEADERS FileHeader = ( PIMAGE_NT_HEADERS ) ( ( uint64_t ) DosHeader + DosHeader->e_lfanew );

	if ( FileHeader->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT )
		return true;

	IMAGE_DATA_DIRECTORY& Dir = FileHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	if ( !Dir.VirtualAddress || !Dir.Size )
		return true;

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor =
		( PIMAGE_IMPORT_DESCRIPTOR ) Mp_RvaToPointer( Image, Dir.VirtualAddress );

	for ( ; ImportDescriptor && ImportDescriptor->Name; ImportDescriptor++ )
	{
		PCHAR ModuleName = ( PCHAR ) Mp_RvaToPointer( Image, ImportDescriptor->Name );

		HMODULE Module = GetModuleHandleA( ModuleName );
		if ( !Module && AllowLoad )
			Module = LoadLibraryExA( ModuleName, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32 );

		if ( !Module )
		{
			printf( "[!] Import module '%s' is not loaded in the injector, IAT left unresolved!\n", ModuleName );
			printf( "    (imports must resolve here: per-boot ASLR is what makes them valid in the target)\n" );
			continue;
		}

		PIMAGE_THUNK_DATA Thunk = NULL;
		PIMAGE_THUNK_DATA Func = NULL;

		if ( ImportDescriptor->OriginalFirstThunk )
		{
			Thunk = ( PIMAGE_THUNK_DATA ) Mp_RvaToPointer( Image, ImportDescriptor->OriginalFirstThunk );
			Func = ( PIMAGE_THUNK_DATA ) ( ( PUCHAR ) MappedAdr + ImportDescriptor->FirstThunk );
		}
		else
		{
			Thunk = ( PIMAGE_THUNK_DATA ) Mp_RvaToPointer( Image, ImportDescriptor->FirstThunk );
			Func = ( PIMAGE_THUNK_DATA ) ( ( PUCHAR ) MappedAdr + ImportDescriptor->FirstThunk );
		}

		for ( ; Thunk->u1.AddressOfData; Thunk++, Func++ )
		{
			FARPROC Address = NULL;
			PCHAR ImportName = 0;

			if ( IMAGE_SNAP_BY_ORDINAL( Thunk->u1.Ordinal ) )
			{
				WORD Ordinal = ( WORD ) IMAGE_ORDINAL( Thunk->u1.Ordinal );
				Address = GetProcAddress( Module, MAKEINTRESOURCEA( Ordinal ) );
				if ( !Address )
					printf( "[!] Unresolved import: %s!#%u\n", ModuleName, Ordinal );
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME ImageImportByName =
					( PIMAGE_IMPORT_BY_NAME ) Mp_RvaToPointer( Image, ( DWORD ) Thunk->u1.AddressOfData );
				ImportName = ( PCHAR ) ImageImportByName->Name;

				if ( !strcmpi( ImportName, "AddVectoredExceptionHandler" ) )
					printf( "\n[+] WARNING: Vectored Exception Handling IS NOT SUPPORTED!\n\n" );

				Address = GetProcAddress( Module, ImportName );
				if ( !Address )
					printf( "[!] Unresolved import: %s!%s\n", ModuleName, ImportName );
			}

			if ( !Address )
				return false;

			Func->u1.Function = ( ULONGLONG ) Address;
		}
	}

	return true;
}

// /GS payloads die in __report_gsfailure unless the loader ran; reproduce the
// only part of it that matters: a non-default, per-map randomized cookie.
static void Mp_RandomizeSecurityCookie( BYTE* Image, SIZE_T Size )
{
	const uint64_t DefaultCookie = 0x00002B992DDFA232ull;
	const uint64_t DefaultComplement = ~DefaultCookie;

	uint64_t NewCookie = __rdtsc();
	NewCookie ^= ( uint64_t ) GetCurrentProcessId() << 32;
	NewCookie ^= ( uint64_t ) GetCurrentThreadId() * 0x9E3779B97F4A7C15ull;
	NewCookie |= 0xA5ull;                       // never a zero low byte

	if ( NewCookie == DefaultCookie )
		NewCookie ^= 0x12345678ull;

	bool Patched = false;

	for ( SIZE_T i = 0; i + 8 <= Size; i += 8 )
	{
		uint64_t Value = *( uint64_t* ) ( Image + i );

		if ( Value == DefaultCookie )
		{
			*( uint64_t* ) ( Image + i ) = NewCookie;
			Patched = true;
		}
		else if ( Value == DefaultComplement )
		{
			*( uint64_t* ) ( Image + i ) = ~NewCookie;
			Patched = true;
		}
	}

	if ( Patched )
		printf( "[+] __security_cookie randomized\n" );
}

// The mapped image keeps a full PE header page in the kernel allocation, which
// is a resident MZ/PE signature for anything that scans pool memory. The stub
// already captured the entry point at map time, so the headers can go.
static void Mp_WipeHeaders( BYTE* Image )
{
	PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER ) Image;
	PIMAGE_NT_HEADERS FileHeader = ( PIMAGE_NT_HEADERS ) ( ( uint64_t ) DosHeader + DosHeader->e_lfanew );

	SIZE_T HeaderSize = FileHeader->OptionalHeader.SizeOfHeaders;
	if ( HeaderSize == 0 || HeaderSize > 0x1000 )
		HeaderSize = 0x1000;

	ZeroMemory( Image, HeaderSize );
	printf( "[+] PE headers wiped (%llX bytes)\n", ( uint64_t ) HeaderSize );
}

static void Mp_RelocateImage( BYTE* Image, BYTE* Target )
{
	PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER ) Image;
	PIMAGE_NT_HEADERS FileHeader = ( PIMAGE_NT_HEADERS ) ( ( uint64_t ) DosHeader + DosHeader->e_lfanew );
	PIMAGE_SECTION_HEADER SectionHeader = ( PIMAGE_SECTION_HEADER )
		( ( ( ULONG_PTR ) &FileHeader->OptionalHeader ) + FileHeader->FileHeader.SizeOfOptionalHeader );

	// Copy sections
	memcpy( Target, Image, 0x1000 ); // Pe Header (wiped again at the end of mapping)

	for ( int i = 0; i < FileHeader->FileHeader.NumberOfSections; i++ )
	{
		char * Name = ( char* ) SectionHeader[ i ].Name;
		uint64_t RawData = SectionHeader[ i ].PointerToRawData;
		uint64_t VirtualAddress = SectionHeader[ i ].VirtualAddress;
		uint64_t RawSize = SectionHeader[ i ].SizeOfRawData;
		uint64_t VirtSize = SectionHeader[ i ].Misc.VirtualSize;
		ZeroMemory( Target + VirtualAddress, VirtSize );
		memcpy( Target + VirtualAddress, Image + RawData, RawSize );

		if ( !strcmpi( Name, ".pdata" ) )
			printf( "\n[+] WARNING: Structured Exception Handling IS NOT SUPPORTED!\n\n" );
		if ( !strcmpi( Name, ".tls" ) )
			printf( "\n[+] WARNING: Thread-local Storage IS NOT SUPPORTED!\n\n" );
	}

	// Reloc sections
	if ( FileHeader->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC &&
		 FileHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress != 0 )
	{

		PIMAGE_BASE_RELOCATION Reloc = ( PIMAGE_BASE_RELOCATION ) ( Target + FileHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress );
		DWORD RelocSize = FileHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size;
		uint64_t Delta = (uint64_t)Target - FileHeader->OptionalHeader.ImageBase;
		int c = 0;
		while ( c < RelocSize )
		{
			size_t p = sizeof( IMAGE_BASE_RELOCATION );
			LPWORD Chains = ( LPWORD ) ( ( PUCHAR ) Reloc + p );
			while ( p < Reloc->SizeOfBlock )
			{
				uint64_t Base = ( uint64_t ) ( Target + Reloc->VirtualAddress );
				switch ( *Chains >> 12 )
				{
					case IMAGE_REL_BASED_HIGHLOW:
						*( uint32_t* ) ( Base + ( *Chains & 0xFFF ) ) += ( uint32_t ) Delta;
						break;
	 				case IMAGE_REL_BASED_DIR64:
						*( uint64_t* ) ( Base + ( *Chains & 0xFFF ) ) += Delta;
						break;
				}
				Chains++;
				p += sizeof( WORD );
			}
			c += Reloc->SizeOfBlock;
			Reloc = ( PIMAGE_BASE_RELOCATION ) ( ( PBYTE ) Reloc + Reloc->SizeOfBlock );
		}
	}

}

static TlsLockedHookController* Mp_MapDllAndCreateHookEntry
(
	const std::string& Path,
	PVOID ValCheck,
	PVOID HookOut,
	bool AllowLoad,
	const std::function<PVOID( SIZE_T )>& MemoryAllocator,
	bool WipeHeaders = true,
	std::vector<BYTE>* OutPageFlags = nullptr,
	Mp_Region* OutRegion = nullptr
)
{
	auto File = Mp_ReadFile( Path );

	if ( File.empty() )
	{
		printf( "[!] Could not read '%s'\n", Path.c_str() );
		return nullptr;
	}

	PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER ) File.data();

	if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE )
	{
		printf( "[!] Not a PE file\n" );
		return nullptr;
	}

	PIMAGE_NT_HEADERS FileHeader = ( PIMAGE_NT_HEADERS ) ( ( uint64_t ) DosHeader + DosHeader->e_lfanew );

	if ( FileHeader->Signature != IMAGE_NT_SIGNATURE ||
		 FileHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
		 FileHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 )
	{
		printf( "[!] Not a x64 PE image\n" );
		return nullptr;
	}

	PIMAGE_OPTIONAL_HEADER OptionalHeader = &FileHeader->OptionalHeader;

	if ( OptionalHeader->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT &&
		 OptionalHeader->DataDirectory[ IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT ].VirtualAddress )
		printf( "[!] WARNING: delay-load imports are NOT SUPPORTED and will fire loader telemetry!\n" );

	// Dry run to learn the stub size, the addresses are patched in the real build.
	auto DryRun = Mp_BuildStub( 0, 0, 0, 0, 0, 0x10000000 );
	uint32_t StubSize = ( uint32_t ) DryRun.size();

	BYTE* Memory = ( BYTE* ) MemoryAllocator( OptionalHeader->SizeOfImage + StubSize + 0xFFF );

	if ( !Memory )
	{
		printf( "[!] Memory allocation failed\n" );
		return nullptr;
	}

	uint64_t ImageMemory = ( ( uint64_t ) Memory + StubSize + 0xFFF ) & ( ~0xFFF );

	printf( "[+] Relocating image...\n" );
	Mp_RelocateImage( File.data(), PBYTE( ImageMemory ) );

	printf( "[+] Resolving imports at map time (no loader calls in the target)...\n" );
	if ( !Mp_ResolveImports( File.data(), PVOID( ImageMemory ), AllowLoad ) )
	{
		printf( "[!] Import resolution failed\n" );
		return nullptr;
	}

	Mp_RandomizeSecurityCookie( PBYTE( ImageMemory ), OptionalHeader->SizeOfImage );

	uint32_t OrigDword = *( DWORD* ) ValCheck;

	printf( "[+] Creating hook stub...\n" );
	auto Stub = Mp_BuildStub
	(
		( uint64_t ) ValCheck,
		OrigDword,
		( uint64_t ) HookOut,
		ImageMemory,
		ImageMemory + OptionalHeader->AddressOfEntryPoint,
		0x10000000
	);

	memcpy( Memory, Stub.data(), Stub.size() );

	// Per-page permissions straight from the section characteristics: the
	// exposed pages never need to be writable+executable at the same time, the
	// injector writes through the physical map regardless of these flags.
	if ( OutPageFlags )
	{
		const BYTE MpfExec = 0x1;
		const BYTE MpfWrite = 0x2;

		SIZE_T StubBytes = ( SIZE_T ) ( ImageMemory - ( uint64_t ) Memory );
		SIZE_T TotalPages = ( StubBytes + OptionalHeader->SizeOfImage + 0xFFF ) / 0x1000;

		OutPageFlags->assign( TotalPages, MpfWrite );

		for ( SIZE_T i = 0; i < ( StubBytes / 0x1000 ); i++ )
			( *OutPageFlags )[ i ] = MpfExec;

		PIMAGE_SECTION_HEADER SectionHeader = ( PIMAGE_SECTION_HEADER )
			( ( ( ULONG_PTR ) &FileHeader->OptionalHeader ) + FileHeader->FileHeader.SizeOfOptionalHeader );

		for ( int i = 0; i < FileHeader->FileHeader.NumberOfSections; i++ )
		{
			BYTE Flags = 0;
			if ( SectionHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE )
				Flags |= MpfExec;
			if ( SectionHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE )
				Flags |= MpfWrite;
			if ( !Flags )
				Flags = MpfWrite;

			SIZE_T First = ( StubBytes + SectionHeader[ i ].VirtualAddress ) / 0x1000;
			SIZE_T Count = ( SectionHeader[ i ].Misc.VirtualSize + 0xFFF ) / 0x1000;

			for ( SIZE_T p = First; p < ( First + Count ) && p < TotalPages; p++ )
				( *OutPageFlags )[ p ] = Flags;
		}
	}

	if ( WipeHeaders )
		Mp_WipeHeaders( PBYTE( ImageMemory ) );

	if ( OutRegion )
	{
		OutRegion->BlockBase = ( uint64_t ) Memory;
		OutRegion->BlockSize = ( uint32_t ) ( ( ImageMemory - ( uint64_t ) Memory ) + OptionalHeader->SizeOfImage );
		OutRegion->ImageBase = ImageMemory;
		OutRegion->ImageSize = OptionalHeader->SizeOfImage;
	}

	printf( "[+] Image mapping done!\n" );
	return ( TlsLockedHookController* ) Memory;
}
