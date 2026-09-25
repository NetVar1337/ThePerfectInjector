#pragma once
#include <iostream>
#include <intrin.h>
#include <inttypes.h>
#include <functional>
#include "Error.h"
#include "LockedMemory.h"
#include "KernelRoutines.h"
#include "CapcomLoader.h"
#include "KernelHelper.h"

#define PFN_TO_PAGE(pfn) ( pfn << 12 )
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_CASE_INSENSITIVE                0x00000040L

#pragma pack(push, 1)
typedef union CR3_
{
	uint64_t value;
	struct
	{
		uint64_t ignored_1 : 3;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t ignored_2 : 7;
		uint64_t pml4_p : 40;
		uint64_t reserved : 12;
	};
} PTE_CR3;

typedef union VIRT_ADDR_
{
	uint64_t value;
	void *pointer;
	struct
	{
		uint64_t offset : 12;
		uint64_t pt_index : 9;
		uint64_t pd_index : 9;
		uint64_t pdpt_index : 9;
		uint64_t pml4_index : 9;
		uint64_t reserved : 16;
	};
} VIRT_ADDR;

typedef uint64_t PHYS_ADDR;

typedef union PML4E_
{
	uint64_t value;
	struct
	{
		uint64_t present : 1;
		uint64_t rw : 1;
		uint64_t user : 1;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t accessed : 1;
		uint64_t ignored_1 : 1;
		uint64_t reserved_1 : 1;
		uint64_t ignored_2 : 4;
		uint64_t pdpt_p : 40;
		uint64_t ignored_3 : 11;
		uint64_t xd : 1;
	};
} PML4E;

typedef union PDPTE_
{
	uint64_t value;
	struct
	{
		uint64_t present : 1;
		uint64_t rw : 1;
		uint64_t user : 1;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t accessed : 1;
		uint64_t dirty : 1;
		uint64_t page_size : 1;
		uint64_t ignored_2 : 4;
		uint64_t pd_p : 40;
		uint64_t ignored_3 : 11;
		uint64_t xd : 1;
	};
} PDPTE;

typedef union PDE_
{
	uint64_t value;
	struct
	{
		uint64_t present : 1;
		uint64_t rw : 1;
		uint64_t user : 1;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t accessed : 1;
		uint64_t dirty : 1;
		uint64_t page_size : 1;
		uint64_t ignored_2 : 4;
		uint64_t pt_p : 40;
		uint64_t ignored_3 : 11;
		uint64_t xd : 1;
	};
} PDE;

typedef union PTE_
{
	uint64_t value;
	VIRT_ADDR vaddr;
	struct
	{
		uint64_t present : 1;
		uint64_t rw : 1;
		uint64_t user : 1;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t accessed : 1;
		uint64_t dirty : 1;
		uint64_t pat : 1;
		uint64_t global : 1;
		uint64_t ignored_1 : 3;
		uint64_t page_frame : 40;
		uint64_t ignored_3 : 11;
		uint64_t xd : 1;
	};
} PTE;
#pragma pack(pop)

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PVOID		     ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

typedef struct _PHYSICAL_MEMORY_RANGE
{
	PHYSICAL_ADDRESS BaseAddress;
	LARGE_INTEGER NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

struct MemoryController
{
	template<typename T>
	T& ReadPhysicalUnsafe( uint64_t Pa )
	{
		return *( T* ) ( PhysicalMemoryBegin + Pa );
	}

	PUCHAR PhysicalMemoryBegin;
	SIZE_T PhysicalMemorySize;

	uint64_t TargetDirectoryBase;

	uint64_t CurrentDirectoryBase;
	uint64_t CurrentEProcess;

	uint64_t UniqueProcessIdOffset;
	uint64_t DirectoryTableBaseOffset;
	uint64_t ActiveProcessLinksOffset;

	// Discovered lazily, see below.
	uint64_t ImageFileNameOffset;
	uint64_t UserDirectoryTableBaseOffset;

	NTSTATUS CreationStatus;

	uint64_t FindEProcess( uint64_t Pid )
	{
		uint64_t EProcess = this->CurrentEProcess;

		do
		{
			if ( this->ReadVirtual<uint64_t>( ( PUCHAR ) EProcess + this->UniqueProcessIdOffset ) == Pid )
				return EProcess;

			LIST_ENTRY Le = this->ReadVirtual<LIST_ENTRY>( ( PUCHAR ) EProcess + this->ActiveProcessLinksOffset );
			EProcess = ( uint64_t ) Le.Flink - this->ActiveProcessLinksOffset;
		}
		while ( EProcess != this->CurrentEProcess );

		return 0;
	}

	// EPROCESS.ImageFileName is a 15 byte buffer. Discover its offset from our own
	// process so the target can be found by walking the kernel process list instead
	// of CreateToolhelp32Snapshot (which every AC logs as reconnaissance).
	uint64_t DiscoverImageFileNameOffset( const char* SelfName )
	{
		if ( this->ImageFileNameOffset )
			return this->ImageFileNameOffset;

		uint64_t Saved = this->TargetDirectoryBase;
		this->AttachTo( this->CurrentEProcess );

		for ( uint32_t i = 0x20; i < 0x800; i += 8 )
		{
			char Buf[ 16 ] = {};
			this->ReadVirtual( ( PUCHAR ) this->CurrentEProcess + i, Buf, sizeof( Buf ) - 1 );

			if ( Buf[ 0 ] && !strnicmp( Buf, SelfName, 14 ) )
			{
				this->ImageFileNameOffset = i;
				break;
			}
		}

		this->TargetDirectoryBase = Saved;
		return this->ImageFileNameOffset;
	}

	uint64_t FindEProcessByName( const char* Name )
	{
		if ( !this->ImageFileNameOffset )
			return 0;

		char Want[ 16 ] = {};
		strncpy_s( Want, Name, 15 );

		uint64_t Saved = this->TargetDirectoryBase;
		this->AttachTo( this->CurrentEProcess );

		uint64_t Start = this->CurrentEProcess;
		uint64_t It = Start;
		uint64_t Found = 0;

		do
		{
			char Buf[ 16 ] = {};
			this->ReadVirtual( ( PUCHAR ) It + this->ImageFileNameOffset, Buf, sizeof( Buf ) - 1 );

			if ( Buf[ 0 ] && !strnicmp( Buf, Want, 14 ) )
			{
				Found = It;
				break;
			}

			LIST_ENTRY Le = this->ReadVirtual<LIST_ENTRY>( ( PUCHAR ) It + this->ActiveProcessLinksOffset );
			It = ( uint64_t ) Le.Flink - this->ActiveProcessLinksOffset;
		}
		while ( It != Start );

		this->TargetDirectoryBase = Saved;
		return Found;
	}

	static constexpr uint64_t Mp_Present = 1ull << 0;
	static constexpr uint64_t Mp_Rw = 1ull << 1;
	static constexpr uint64_t Mp_User = 1ull << 2;
	static constexpr uint64_t Mp_Large = 1ull << 7;
	static constexpr uint64_t Mp_Xd = 1ull << 63;
	static constexpr uint64_t Mp_PfnMask = 0x000FFFFFFFFFF000ull;

	void ZeroPhysPage( uint64_t Pa )
	{
		if ( ( Pa + 0x1000 ) <= this->PhysicalMemorySize )
			memset( this->PhysicalMemoryBegin + Pa, 0, 0x1000 );
	}

	// Under KVA shadow the user CR3 (KPROCESS.DirectoryTableBase) and the kernel
	// CR3 (KernelDirectoryTableBase) are separate page tables: the user CR3 only
	// carries a minimal kernel mapping, so flipping U/S bits in the kernel tables
	// does nothing for CPL3. Discover the user CR3 as a value that is not the
	// kernel CR3 but still maps the user-visible shared page.
	uint64_t DiscoverUserDirectoryTableBase( uint64_t EProcess, uint64_t KernelCr3 )
	{
		if ( this->UserDirectoryTableBaseOffset )
			return this->ReadVirtual<uint64_t>( ( PUCHAR ) EProcess + this->UserDirectoryTableBaseOffset );

		for ( uint64_t i = 0x20; i < 0x600; i += 8 )
		{
			uint64_t Candidate = this->ReadVirtual<uint64_t>( ( PUCHAR ) EProcess + i );

			if ( !Candidate || Candidate == KernelCr3 )
				continue;
			if ( ( Candidate & Mp_PfnMask ) < 0x1000 || ( Candidate & Mp_PfnMask ) > this->PhysicalMemorySize )
				continue;

			uint64_t Saved = this->TargetDirectoryBase;
			this->TargetDirectoryBase = Candidate;
			bool MapsShared = this->VirtToPhys( ( PVOID ) 0x7FFE0000 ) != 0;
			this->TargetDirectoryBase = Saved;

			if ( MapsShared )
			{
				this->UserDirectoryTableBaseOffset = i;
				return Candidate;
			}
		}

		return KernelCr3;
	}

	// Make Va map Pa in the currently attached page tables with the user bit set,
	// creating any missing page-table level out of caller-owned frames. Frames
	// must stay resident and alive for as long as the mapping is used.
	bool MapUserPage( PVOID Va, uint64_t Pa, bool Executable, bool Writable, const std::function<uint64_t()>& AllocTableFrame )
	{
		VIRT_ADDR Addr = { ( uint64_t ) Va };
		PTE_CR3 Cr3 = { TargetDirectoryBase };

		uint64_t Levels[ 4 ] = { Addr.pml4_index, Addr.pdpt_index, Addr.pd_index, Addr.pt_index };
		uint64_t TablePa = PFN_TO_PAGE( Cr3.pml4_p );

		for ( int Level = 0; Level < 4; Level++ )
		{
			uint64_t EntryPa = TablePa + Levels[ Level ] * 8;

			if ( ( EntryPa + 8 ) > this->PhysicalMemorySize )
				return false;

			uint64_t Entry = this->ReadPhysicalUnsafe<uint64_t>( EntryPa );
			bool Leaf = ( Level == 3 );

			if ( !Leaf && ( Entry & Mp_Present ) && ( Entry & Mp_Large ) )
				return false; // large page in the middle of the chain, refuse instead of splitting

			if ( Leaf )
			{
				Entry &= ~Mp_PfnMask;
				Entry |= ( Pa & Mp_PfnMask );
				Entry |= Mp_Present | Mp_User;
				if ( Writable )
					Entry |= Mp_Rw;
				else
					Entry &= ~Mp_Rw;
				if ( Executable )
					Entry &= ~Mp_Xd;
				else
					Entry |= Mp_Xd;
			}
			else
			{
				if ( !( Entry & Mp_Present ) )
				{
					uint64_t Frame = AllocTableFrame();
					if ( !Frame )
						return false;
					this->ZeroPhysPage( Frame );
					Entry = ( Frame & Mp_PfnMask ) | Mp_Present;
				}
				Entry |= Mp_Rw | Mp_User;
			}

			this->ReadPhysicalUnsafe<uint64_t>( EntryPa ) = Entry;
			TablePa = PFN_TO_PAGE( Entry & Mp_PfnMask );
		}

		return true;
	}

	void AttachTo( uint64_t EProcess )
	{
		this->TargetDirectoryBase = this->ReadVirtual<uint64_t>( ( PUCHAR ) EProcess + this->DirectoryTableBaseOffset );
	}

	void Detach()
	{
		this->TargetDirectoryBase = this->CurrentDirectoryBase;
	}

	


	struct PageTableInfo
	{
		PML4E* Pml4e;
		PDPTE* Pdpte;
		PDE* Pde;
		PTE* Pte;
	};

	PageTableInfo QueryPageTableInfo( PVOID Va )
	{
		PageTableInfo Pi = { 0,0,0,0 };

		VIRT_ADDR Addr = { ( uint64_t ) Va };
		PTE_CR3 Cr3 = { TargetDirectoryBase };

		{
			uint64_t a = PFN_TO_PAGE( Cr3.pml4_p ) + sizeof( PML4E ) * Addr.pml4_index;
			if ( a > this->PhysicalMemorySize )
				return Pi;
			PML4E& e = ReadPhysicalUnsafe<PML4E>( a );
			if ( !e.present )
				return Pi;
			Pi.Pml4e = &e;
		}
		{
			uint64_t a = PFN_TO_PAGE( Pi.Pml4e->pdpt_p ) + sizeof( PDPTE ) * Addr.pdpt_index;
			if ( a > this->PhysicalMemorySize )
				return Pi;
			PDPTE& e = ReadPhysicalUnsafe<PDPTE>( a );
			if ( !e.present )
				return Pi;
			Pi.Pdpte = &e;
		}
		{
			uint64_t a = PFN_TO_PAGE( Pi.Pdpte->pd_p ) + sizeof( PDE ) * Addr.pd_index;
			if ( a > this->PhysicalMemorySize )
				return Pi;
			PDE& e = ReadPhysicalUnsafe<PDE>( a );
			if ( !e.present )
				return Pi;
			Pi.Pde = &e;
			if ( Pi.Pde->page_size )
				return Pi;
		}
		{
			uint64_t a = PFN_TO_PAGE( Pi.Pde->pt_p ) + sizeof( PTE ) * Addr.pt_index;
			if ( a > this->PhysicalMemorySize )
				return Pi;
			PTE& e = ReadPhysicalUnsafe<PTE>( a );
			if ( !e.present )
				return Pi;
			Pi.Pte = &e;
		}
		return Pi;
	}

	uint64_t VirtToPhys( PVOID Va )
	{
		auto Info = QueryPageTableInfo( Va );

		if ( !Info.Pde )
			return 0;

		uint64_t Pa = 0;

		if ( Info.Pde->page_size )
		{
			Pa = PFN_TO_PAGE( Info.Pde->pt_p );
			Pa += ( uint64_t ) Va & ( 0x200000 - 1 );
		}
		else
		{
			if ( !Info.Pte )
				return 0;
			Pa = PFN_TO_PAGE( Info.Pte->page_frame );
			Pa += ( uint64_t ) Va & ( 0x1000 - 1 );
		}
		return Pa;
	}

	void IterPhysRegion( PVOID StartVa, SIZE_T Size, std::function<void( PVOID Va, uint64_t, SIZE_T )> Fn )
	{
		PUCHAR It = ( PUCHAR ) StartVa;
		PUCHAR End = It + Size;

		while ( It < End )
		{
			SIZE_T Size = ( PUCHAR ) ( ( ( uint64_t ) It + 0x1000 ) & ( ~0xFFF ) ) - It;

			if ( ( It + Size ) > End )
				Size = End - It;

			uint64_t Pa = VirtToPhys( It );

			Fn( It, Pa, Size );

			It += Size;
		}
	}

	void AttachIfCanRead( uint64_t EProcess, PVOID Adr )
	{
		this->AttachTo( EProcess );
		if ( !this->VirtToPhys( Adr ) )
			this->Detach();
	}

	SIZE_T ReadVirtual( PVOID Src, PVOID Dst, SIZE_T Size )
	{
		PUCHAR It = ( PUCHAR ) Dst;
		SIZE_T BytesRead = 0;

		this->IterPhysRegion( Src, Size, [ & ] ( PVOID Va, uint64_t Pa, SIZE_T Sz )
		{
			if ( Pa )
			{
				BytesRead += Sz;
				memcpy( It, PhysicalMemoryBegin + Pa, Sz );
				It += Sz;
			}
		} );

		return BytesRead;
	}

	SIZE_T WriteVirtual( PVOID Src, PVOID Dst, SIZE_T Size )
	{
		PUCHAR It = ( PUCHAR ) Src;
		SIZE_T BytesRead = 0;

		this->IterPhysRegion( Dst, Size, [ & ] ( PVOID Va, uint64_t Pa, SIZE_T Sz )
		{
			if ( Pa )
			{
				BytesRead += Sz;
				memcpy( PhysicalMemoryBegin + Pa, It, Sz );
				It += Sz;
			}
		} );

		return BytesRead;
	}

	template<typename T>
	T ReadVirtual( PVOID From )
	{
		char Buffer[ sizeof( T ) ];
		this->ReadVirtual( From, Buffer, sizeof( T ) );
		return *( T* ) ( Buffer );
	}

	template<typename T>
	void WriteVirtual( PVOID To, const T& Data )
	{
		this->WriteVirtual( ( PVOID ) &Data, To, sizeof( T ) );
	}
};

static MemoryController Mc_InitContext( CapcomContext** CpCtxReuse = 0, KernelContext** KrCtxReuse = 0 )
{
	assert( Np_LockSections() );

	KernelContext* KrCtx = Kr_InitContext();
	CapcomContext* CpCtx = Cl_InitContext();

	assert( CpCtx );
	assert( KrCtx );

	Khu_Init( CpCtx, KrCtx );
	printf( "[+] Mapping physical memory to user-mode!\n" );


	NON_PAGED_DATA static MemoryController Controller = { 0 };

	NON_PAGED_DATA static auto k_ZwOpenSection = KrCtx->GetProcAddress<>( "ZwOpenSection" );
	NON_PAGED_DATA static auto k_ZwMapViewOfSection = KrCtx->GetProcAddress<>( "ZwMapViewOfSection" );
	NON_PAGED_DATA static auto k_ZwClose = KrCtx->GetProcAddress<>( "ZwClose" );
	NON_PAGED_DATA static auto k_PsGetCurrentProcess = KrCtx->GetProcAddress<>( "PsGetCurrentProcess" );
	NON_PAGED_DATA static auto k_PsGetCurrentProcessId = KrCtx->GetProcAddress<>( "PsGetCurrentProcessId" );
	NON_PAGED_DATA static auto k_PsGetProcessId = KrCtx->GetProcAddress<>( "PsGetProcessId" );
	NON_PAGED_DATA static auto k_MmGetPhysicalMemoryRanges = KrCtx->GetProcAddress<PPHYSICAL_MEMORY_RANGE( *)( )>( "MmGetPhysicalMemoryRanges" );

	NON_PAGED_DATA static wchar_t PhysicalMemoryName[] = L"\\Device\\PhysicalMemory";
	NON_PAGED_DATA static OBJECT_ATTRIBUTES PhysicalMemoryAttributes;
	NON_PAGED_DATA static UNICODE_STRING PhysicalMemoryNameUnicode;

	PhysicalMemoryNameUnicode.Buffer = PhysicalMemoryName;
	PhysicalMemoryNameUnicode.Length = sizeof( PhysicalMemoryName ) - 2;
	PhysicalMemoryNameUnicode.MaximumLength = sizeof( PhysicalMemoryName );

	PhysicalMemoryAttributes.Length = sizeof( PhysicalMemoryAttributes );
	PhysicalMemoryAttributes.Attributes = OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE;
	PhysicalMemoryAttributes.ObjectName = &PhysicalMemoryNameUnicode;
	PhysicalMemoryAttributes.RootDirectory = 0;
	PhysicalMemoryAttributes.SecurityDescriptor = 0;
	PhysicalMemoryAttributes.SecurityQualityOfService = 0;

	CpCtx->ExecuteInKernel( NON_PAGED_LAMBDA()
	{
		auto Range = k_MmGetPhysicalMemoryRanges();

		while ( Range->NumberOfBytes.QuadPart )
		{
			Controller.PhysicalMemorySize = max( Controller.PhysicalMemorySize, Range->BaseAddress.QuadPart + Range->NumberOfBytes.QuadPart );
			Range++;
		}

		HANDLE PhysicalMemoryHandle = 0;
		Controller.CreationStatus = Khk_CallPassive( k_ZwOpenSection, &PhysicalMemoryHandle, uint64_t( SECTION_ALL_ACCESS ), &PhysicalMemoryAttributes );

		if ( !Controller.CreationStatus )
		{
			Controller.CreationStatus = Khk_CallPassive
			(
				k_ZwMapViewOfSection,
				PhysicalMemoryHandle,
				NtCurrentProcess(),
				&Controller.PhysicalMemoryBegin,
				0ull,
				0ull,
				0ull,
				&Controller.PhysicalMemorySize,
				1ull,
				0,
				PAGE_READWRITE
			);

			if ( !Controller.CreationStatus )
			{
				Controller.CurrentEProcess = k_PsGetCurrentProcess();
				Controller.CurrentDirectoryBase = __readcr3();

				uint64_t Pid = k_PsGetProcessId( Controller.CurrentEProcess );

				uint32_t PidOffset = *( uint32_t* ) ( ( PUCHAR ) k_PsGetProcessId + 3 );
				if ( PidOffset < 0x600 && *( uint64_t* ) ( Controller.CurrentEProcess + PidOffset ) == Pid )
				{
					Controller.UniqueProcessIdOffset = PidOffset;
					Controller.ActiveProcessLinksOffset = Controller.UniqueProcessIdOffset + 0x8;
				}

				for ( int i = 0; i < 0x600; i += 0x8 )
				{
					uint64_t* Ptr = (uint64_t*)(Controller.CurrentEProcess + i);
					if ( !Controller.UniqueProcessIdOffset && Ptr[ 0 ] & 0xFFFFFFFF == Pid && ( Ptr[ 1 ] > 0xffff800000000000 ) && ( Ptr[ 2 ] > 0xffff800000000000 ) && ( ( Ptr[ 1 ] & 0xF ) == ( Ptr[ 2 ] & 0xF ) ) )
					{
						Controller.UniqueProcessIdOffset = i;
						Controller.ActiveProcessLinksOffset = Controller.UniqueProcessIdOffset + 0x8;
					}
					else if ( !Controller.DirectoryTableBaseOffset && Ptr[ 0 ] == __readcr3() )
					{
						Controller.DirectoryTableBaseOffset = i;
					}
				}
			}

			k_ZwClose( PhysicalMemoryHandle );
		}
	} );

	if ( !Controller.UniqueProcessIdOffset )
		Controller.CreationStatus = 1;
	if ( !Controller.DirectoryTableBaseOffset )
		Controller.CreationStatus = 2;

	printf( "[+] PhysicalMemoryBegin: %16llx\n", Controller.PhysicalMemoryBegin );
	printf( "[+] PhysicalMemorySize:  %16llx\n", Controller.PhysicalMemorySize );

	printf( "[+] CurrentProcessCr3:   %16llx\n", Controller.CurrentDirectoryBase );
	printf( "[+] CurrentEProcess:     %16llx\n", Controller.CurrentEProcess );

	printf( "[+] DirectoryTableBase@  %16llx\n", Controller.DirectoryTableBaseOffset );
	printf( "[+] UniqueProcessId@     %16llx\n", Controller.UniqueProcessIdOffset );
	printf( "[+] ActiveProcessLinks@  %16llx\n", Controller.ActiveProcessLinksOffset );

	printf( "[+] Status:              %16llx\n", Controller.CreationStatus );

	Controller.TargetDirectoryBase = Controller.CurrentDirectoryBase;

	if ( !CpCtxReuse )
		Cl_FreeContext( CpCtx );
	else
		*CpCtxReuse = CpCtx;

	if ( !KrCtxReuse )
		Kr_FreeContext( KrCtx );
	else
		*KrCtxReuse = KrCtx;

	return Controller;
}