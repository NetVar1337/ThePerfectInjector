// Behavioral test of the generated hook stub: this actually executes the
// shellcode on real threads instead of only checking its encodings.
//
// Contract under test:
//   * while IsFree == 0 the callers block (bounded, they must not hang)
//   * release requires both gates: IsFree != 0 AND the hooked bytes restored
//   * exactly one caller runs the payload entry, the rest fall through to HookOut
//   * the Done flag is set only after the payload returned
//   * a never-released gate times out and falls through without running anything
#include <Windows.h>
#include <stdio.h>
#include <thread>
#include <vector>
#include <atomic>
#include "SimpleMapper.h"

static int g_Failures = 0;

static void Check( bool Cond, const char* What )
{
	printf( "%s %s\n", Cond ? "[PASS]" : "[FAIL]", What );
	if ( !Cond )
		g_Failures++;
}

// Fake payload entry: atomically increments a counter and returns to the caller
// of the stub. `lock` matters: without it concurrent callers lose updates and
// the test cannot count them exactly.
static const BYTE kCountingStub[] = { 0xF0, 0xFF, 0x05, 0, 0, 0, 0, 0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3 };

static void PlaceCountingStub( BYTE* Where, volatile LONG* Counter )
{
	memcpy( Where, kCountingStub, sizeof( kCountingStub ) );
	*( int32_t* ) ( Where + 3 ) = ( int32_t ) ( ( ( BYTE* ) Counter ) - ( Where + 7 ) );
}

int main()
{
	// Placed payload counter and fall-through counter, in executable memory so
	// the stub can reach them.
	volatile LONG* PayloadRuns = ( volatile LONG* ) VirtualAlloc( nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	volatile LONG* FallThrough = ( volatile LONG* ) VirtualAlloc( nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	*PayloadRuns = 0;
	*FallThrough = 0;

	// Fake "hooked entry" whose first dword the stub's data-sync gate polls.
	BYTE* FakeEntry = ( BYTE* ) VirtualAlloc( nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	const uint32_t OrigDword = 0x11223344;
	*( uint32_t* ) FakeEntry = OrigDword;           // restored = gate satisfied

	BYTE* Exec = ( BYTE* ) VirtualAlloc( nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

	// fall-through target: inc [FallThrough]; mov eax, 0x1337; ret
	BYTE* HookOut = Exec;
	PlaceCountingStub( HookOut, FallThrough );

	// payload entry: inc [PayloadRuns]; mov eax, 0x1337; ret
	BYTE* PayloadEntry = HookOut + 0x40;
	PlaceCountingStub( PayloadEntry, PayloadRuns );

	// Build the stub: image base is unused by these fakes, entry point unused.
	const uint32_t SpinCap = 0x20000000;
	auto Stub = Mp_BuildStub( ( uint64_t ) FakeEntry, OrigDword, ( uint64_t ) HookOut,
							  0x1000000, ( uint64_t ) PayloadEntry, SpinCap );

	BYTE* Mem = ( BYTE* ) VirtualAlloc( nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	memcpy( Mem, Stub.data(), Stub.size() );

	TlsLockedHookController* Ctrl = ( TlsLockedHookController* ) Mem;
	void ( *Entry )( ) = ( void ( * )() ) ( Mem + 3 );   // EntryBytes

	printf( "[i] stub %u bytes, entry at %p\n", ( unsigned ) Stub.size(), ( void* ) Entry );

	// ---- test 1: released gate runs the payload exactly once ----
	Ctrl->IsFree = 0;
	Ctrl->NumThreadsWaiting = 0;
	Ctrl->Done = 0;

	const int N = 8;
	std::atomic<int> Returned( 0 );
	std::vector<std::thread> Threads;

	for ( int i = 0; i < N; i++ )
		Threads.emplace_back( [ & ] { Entry(); Returned++; } );

	// all callers must be parked inside the stub
	Sleep( 300 );
	Check( Ctrl->NumThreadsWaiting == N, "all callers parked in the wait gate" );
	Check( *PayloadRuns == 0, "payload has not run while the gate is closed" );

	// data-sync gate is already satisfied (FakeEntry holds OrigDword); release
	Ctrl->IsFree = 1;

	for ( auto& T : Threads )
		T.join();

	Check( Returned == N, "every caller returned to its own return address" );
	Check( Ctrl->NumThreadsWaiting == 0, "counter drained" );
	Check( *FallThrough == N, "every caller completed the original function (hook contract)" );
	Check( *PayloadRuns == 1, "exactly one caller ran the payload" );
	Check( Ctrl->Done == 1, "Done flag set after the payload returned" );

	// ---- test 2: data-sync gate holds until the hooked bytes are restored ----
	*PayloadRuns = 0;
	*FallThrough = 0;
	Returned = 0;
	Ctrl->IsFree = 0;
	Ctrl->NumThreadsWaiting = 0;
	Ctrl->Done = 0;
	*( uint32_t* ) FakeEntry = 0xAAAAAAAA;          // still hooked: sync gate closed

	std::thread T2( [ & ] { Entry(); Returned++; } );
	Sleep( 300 );
	Check( Ctrl->NumThreadsWaiting == 1 && Returned == 0, "caller waits while the hook is still installed" );

	Ctrl->IsFree = 1;
	Sleep( 200 );
	Check( Returned == 0, "release alone is not enough while the hook is installed" );

	*( uint32_t* ) FakeEntry = OrigDword;           // injector restored the bytes
	T2.join();
	Check( Returned == 1 && *PayloadRuns == 1, "caller proceeds once the hooked bytes are restored" );

	// ---- test 3: bounded wait, a dead injector must not hang the game ----
	*PayloadRuns = 0;
	*FallThrough = 0;
	Returned = 0;

	auto ShortStub = Mp_BuildStub( ( uint64_t ) FakeEntry, OrigDword, ( uint64_t ) HookOut,
								   0x1000000, ( uint64_t ) PayloadEntry, 0x1000 );
	BYTE* Mem2 = ( BYTE* ) VirtualAlloc( nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	memcpy( Mem2, ShortStub.data(), ShortStub.size() );
	TlsLockedHookController* Ctrl2 = ( TlsLockedHookController* ) Mem2;
	void ( *Entry2 )( ) = ( void ( * )() ) ( Mem2 + 3 );

	Ctrl2->IsFree = 0;
	Ctrl2->NumThreadsWaiting = 0;
	Ctrl2->Done = 0;

	std::thread T3( [ & ] { Entry2(); Returned++; } );
	uint64_t Start = GetTickCount64();
	T3.join();
	uint64_t Elapsed = GetTickCount64() - Start;

	printf( "[i] timeout path returned after %llu ms\n", Elapsed );
	Check( Returned == 1, "caller escaped the wait gate instead of hanging" );
	Check( *FallThrough == 1 && *PayloadRuns == 0, "timeout fell through without running the payload" );
	Check( Elapsed < 5000, "timeout is bounded" );

	printf( "\n%s (%d failures)\n", g_Failures ? "FAILED" : "ALL CHECKS PASSED", g_Failures );
	return g_Failures ? 1 : 0;
}
