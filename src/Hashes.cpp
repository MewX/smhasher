#include "Hashes.h"

#include "Random.h"

#define SMHASHER


#include <stdlib.h>
//#include <stdint.h>
#include <assert.h>
//#include <emmintrin.h>
//#include <xmmintrin.h>

//----------------------------------------------------------------------------
#include "ourhash/xtea.h"
void xtea_md               ( const void * key, int len, uint32_t seed, void * out ) {
    HASH_XTEA_PFMD((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void xtea_mmo               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_XTEA_MMO((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void xtea_mp               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_XTEA_MP((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}

#include "ourhash/speck-64-128_marquet.h"
void speck_md               ( const void * key, int len, uint32_t seed, void * out ) {
    HASH_SPECK_PFMD((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void speck_mmo               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_SPECK_MMO((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void speck_mp               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_SPECK_MP((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}

#include "ourhash/simon-64-128_marquet.h"
void simon_md               ( const void * key, int len, uint32_t seed, void * out ) {
    HASH_SIMON_PFMD((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void simon_mmo               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_SIMON_MMO((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void simon_mp               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_SIMON_MP((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}

#include "ourhash/prince.h"
void prince_md               ( const void * key, int len, uint32_t seed, void * out ) {
    HASH_PRINCE_PFMD((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void prince_mmo               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_PRINCE_MMO((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void prince_mp               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_PRINCE_MP((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}

#include "ourhash/lblockv2.h"
void lblock_md               ( const void * key, int len, uint32_t seed, void * out ) {
    HASH_LBLOCK_PFMD((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void lblock_mmo               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_LBLOCK_MMO((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void lblock_mp               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_LBLOCK_MP((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}

#include "ourhash/sea.h"
void sea_md               ( const void * key, int len, uint32_t seed, void * out ) {
    *(uint128_t*)out = 0;
    HASH_SEA_PFMD((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void sea_mmo               ( const void * key, int len, uint32_t seed, void * out ){
    *(uint128_t*)out = 0;
    HASH_SEA_MMO((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void sea_mp               ( const void * key, int len, uint32_t seed, void * out ){
    *(uint128_t*)out = 0;
    HASH_SEA_MP((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}

#include "ourhash/lea.h"
void lea_md               ( const void * key, int len, uint32_t seed, void * out ) {
    HASH_LEA_PFMD((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void lea_mmo               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_LEA_MMO((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void lea_mp               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_LEA_MP((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}

#include "ourhash/clefia.h"
void clefia_md               ( const void * key, int len, uint32_t seed, void * out ) {
    HASH_CLEFIA_PFMD((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void clefia_mmo               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_CLEFIA_MMO((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void clefia_mp               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_CLEFIA_MP((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}

#include "ourhash/camellia.h"
void camellia_md               ( const void * key, int len, uint32_t seed, void * out ) {
    HASH_CAMELLIA_PFMD((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void camellia_mmo               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_CAMELLIA_MMO((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void camellia_mp               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_CAMELLIA_MP((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}

#include "ourhash/aessoft.h"
void aes_md               ( const void * key, int len, uint32_t seed, void * out ) {
    HASH_AES_PFMD((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void aes_mmo            ( const void * key, int len, uint32_t seed, void * out ){
    HASH_AES_MMO((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}
void aes_mp               ( const void * key, int len, uint32_t seed, void * out ){
    HASH_AES_MP((uint64_t)seed, (uint8_t *)key, (uint16_t) len, (uint8_t *)out);
}


//----------------------------------------------------------------------------
// fake / bad hashes

void BadHash ( const void * key, int len, uint32_t seed, void * out )
{
  uint32_t h = seed;

  const uint8_t * data = (const uint8_t*)key;

  for(int i = 0; i < len; i++)
  {
    h ^= h >> 3;
    h ^= h << 5;
    h ^= data[i];
  }

  *(uint32_t*)out = h;
}

void sumhash ( const void * key, int len, uint32_t seed, void * out )
{
  uint32_t h = seed;

  const uint8_t * data = (const uint8_t*)key;

  for(int i = 0; i < len; i++)
  {
    h += data[i];
  }

  *(uint32_t*)out = h;
}

void sumhash32 ( const void * key, int len, uint32_t seed, void * out )
{
  uint32_t h = seed;

  const uint32_t * data = (const uint32_t*)key;

  for(int i = 0; i < len/4; i++)
  {
    h += data[i];
  }

  *(uint32_t*)out = h;
}

void DoNothingHash ( const void *, int, uint32_t, void * )
{
}

//-----------------------------------------------------------------------------
// One-byte-at-a-time hash based on Murmur's mix

uint32_t MurmurOAAT ( const void * key, int len, uint32_t seed )
{
  const uint8_t * data = (const uint8_t*)key;

  uint32_t h = seed;

  for(int i = 0; i < len; i++)
  {
    h ^= data[i];
    h *= 0x5bd1e995;
    h ^= h >> 15;
  }

  return h;
}

void MurmurOAAT_test ( const void * key, int len, uint32_t seed, void * out )
{
	*(uint32_t*)out = MurmurOAAT(key,len,seed);
}

//----------------------------------------------------------------------------

void FNV ( const void * key, int len, uint32_t seed, void * out )
{
  unsigned int h = seed;

  const uint8_t * data = (const uint8_t*)key;

  h ^= BIG_CONSTANT(2166136261);

  for(int i = 0; i < len; i++)
  {
    h ^= data[i];
    h *= 16777619;
  }

  *(uint32_t*)out = h;
}

//-----------------------------------------------------------------------------

uint32_t x17 ( const void * key, int len, uint32_t h ) 
{
  const uint8_t * data = (const uint8_t*)key;
    
  for(int i = 0; i < len; ++i) 
  {
        h = 17 * h + (data[i] - ' ');
    }

    return h ^ (h >> 16);
}

//-----------------------------------------------------------------------------

void Bernstein ( const void * key, int len, uint32_t seed, void * out ) 
{
  const uint8_t * data = (const uint8_t*)key;
    
  for(int i = 0; i < len; ++i) 
  {
        seed = 33 * seed + data[i];
    }

  *(uint32_t*)out = seed;
}

//-----------------------------------------------------------------------------
// Crap8 hash from http://www.team5150.com/~andrew/noncryptohashzoo/Crap8.html

uint32_t Crap8( const uint8_t *key, uint32_t len, uint32_t seed ) {
  #define c8fold( a, b, y, z ) { p = (uint32_t)(a) * (uint64_t)(b); y ^= (uint32_t)p; z ^= (uint32_t)(p >> 32); }
  #define c8mix( in ) { h *= m; c8fold( in, m, k, h ); }

  const uint32_t m = 0x83d2e73b, n = 0x97e1cc59, *key4 = (const uint32_t *)key;
  uint32_t h = len + seed, k = n + len;
  uint64_t p;

  while ( len >= 8 ) { c8mix(key4[0]) c8mix(key4[1]) key4 += 2; len -= 8; }
  if ( len >= 4 ) { c8mix(key4[0]) key4 += 1; len -= 4; }
  if ( len ) { c8mix( key4[0] & ( ( 1 << ( len * 8 ) ) - 1 ) ) }
  c8fold( h ^ k, n, k, k )
  return k;
}

void Crap8_test ( const void * key, int len, uint32_t seed, void * out )
{
  *(uint32_t*)out = Crap8((const uint8_t*)key,len,seed);
}
