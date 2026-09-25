#pragma once
#include <Windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

//
// ChaCha20 (RFC 8439) for payload-at-rest encryption.
//
// The mapped image stays resident in the target until the machine reboots, so
// a pool/page scanner that walks it at any idle moment finds a complete PE
// layout with a stable signature. Keeping the image encrypted except for the
// brief execution window turns a standing artifact into a transient one: the
// plaintext exists only while the payload actually runs.
//
// The key lives in the injector only. Encryption and decryption are done
// through the injector's own mapping of the region, so the target never sees
// key material or crypto code.
//

static uint32_t Mp_Rotl32( uint32_t X, int N )
{
	return ( X << N ) | ( X >> ( 32 - N ) );
}

static void Mp_ChaChaQuarter( uint32_t S[ 16 ], int A, int B, int C, int D )
{
	S[ A ] += S[ B ]; S[ D ] = Mp_Rotl32( S[ D ] ^ S[ A ], 16 );
	S[ C ] += S[ D ]; S[ B ] = Mp_Rotl32( S[ B ] ^ S[ C ], 12 );
	S[ A ] += S[ B ]; S[ D ] = Mp_Rotl32( S[ D ] ^ S[ A ], 8 );
	S[ C ] += S[ D ]; S[ B ] = Mp_Rotl32( S[ B ] ^ S[ C ], 7 );
}

static void Mp_ChaChaBlock( const uint8_t Key[ 32 ], const uint8_t Nonce[ 12 ], uint32_t Counter, uint8_t Out[ 64 ] )
{
	uint32_t S[ 16 ] =
	{
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		0, 0, 0, 0, 0, 0, 0, 0,
		Counter,
		0, 0, 0
	};

	for ( int i = 0; i < 8; i++ )
		S[ 4 + i ] = ( uint32_t ) Key[ i * 4 ] | ( ( uint32_t ) Key[ i * 4 + 1 ] << 8 ) |
					( ( uint32_t ) Key[ i * 4 + 2 ] << 16 ) | ( ( uint32_t ) Key[ i * 4 + 3 ] << 24 );

	for ( int i = 0; i < 3; i++ )
		S[ 13 + i ] = ( uint32_t ) Nonce[ i * 4 ] | ( ( uint32_t ) Nonce[ i * 4 + 1 ] << 8 ) |
					  ( ( uint32_t ) Nonce[ i * 4 + 2 ] << 16 ) | ( ( uint32_t ) Nonce[ i * 4 + 3 ] << 24 );

	uint32_t W[ 16 ];
	memcpy( W, S, sizeof( W ) );

	for ( int i = 0; i < 10; i++ )
	{
		Mp_ChaChaQuarter( W, 0, 4, 8, 12 );
		Mp_ChaChaQuarter( W, 1, 5, 9, 13 );
		Mp_ChaChaQuarter( W, 2, 6, 10, 14 );
		Mp_ChaChaQuarter( W, 3, 7, 11, 15 );
		Mp_ChaChaQuarter( W, 0, 5, 10, 15 );
		Mp_ChaChaQuarter( W, 1, 6, 11, 12 );
		Mp_ChaChaQuarter( W, 2, 7, 8, 13 );
		Mp_ChaChaQuarter( W, 3, 4, 9, 14 );
	}

	for ( int i = 0; i < 16; i++ )
	{
		uint32_t V = W[ i ] + S[ i ];
		Out[ i * 4 + 0 ] = ( uint8_t ) ( V & 0xFF );
		Out[ i * 4 + 1 ] = ( uint8_t ) ( ( V >> 8 ) & 0xFF );
		Out[ i * 4 + 2 ] = ( uint8_t ) ( ( V >> 16 ) & 0xFF );
		Out[ i * 4 + 3 ] = ( uint8_t ) ( ( V >> 24 ) & 0xFF );
	}
}

// XOR a buffer with the ChaCha20 keystream. Applying it twice is the identity,
// so the same call encrypts and decrypts.
static void Mp_ChaChaApply( void* Buffer, SIZE_T Size, const uint8_t Key[ 32 ], const uint8_t Nonce[ 12 ], uint32_t StartCounter = 0 )
{
	uint8_t* It = ( uint8_t* ) Buffer;
	uint32_t Counter = StartCounter;

	while ( Size )
	{
		uint8_t Block[ 64 ];
		Mp_ChaChaBlock( Key, Nonce, Counter++, Block );

		SIZE_T Chunk = ( Size < 64 ) ? Size : 64;
		for ( SIZE_T i = 0; i < Chunk; i++ )
			It[ i ] ^= Block[ i ];

		It += Chunk;
		Size -= Chunk;
	}
}

// Per-map key material from the system RNG.
static void Mp_GenerateKey( uint8_t Key[ 32 ], uint8_t Nonce[ 12 ] )
{
	BCryptGenRandom( nullptr, Key, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG );
	BCryptGenRandom( nullptr, Nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG );
}
