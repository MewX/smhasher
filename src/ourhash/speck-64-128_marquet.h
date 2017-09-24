#ifndef SPECK_H_
#define SPECK_H_

/** @file       main.c
 *  @brief      XTEA encode
 *
 *  @author     Yang Su, Auto-ID Lab, The University of Adelaide
 */

/**
 * as a unique ID.
 */
#include <stdint.h>
#include "tools.h"

#ifndef SMHASHER
#include <msp430.h>
#else
#include <stdio.h>
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

#define KeyExpansion SPECK_KeyExpansion
void KeyExpansion ( u32 l[], u32 k[] )
{
    u8 i;
    for ( i=0 ; i<26 ; i++ )
    {
        l[i+3] = ( k[i] + ROTATE_RIGHT_32(l[i], 8) ) ^ i;
        k[i+1] = ROTATE_LEFT_32(k[i], 3) ^ l[i+3];
    }
}

#define Decrypt SPECK_Decrypt
void __attribute__ ((noinline)) Decrypt ( u32 text[], u32 crypt[], u32 key[] )
{
    u8 i;
    crypt[0] = text[0];
    crypt[1] = text[1];

    for ( i=0 ; i<27 ; i++ )
    {
        crypt[1] = ROTATE_RIGHT_32( crypt[0] ^ crypt[1], 3);
        crypt[0] = ROTATE_LEFT_32( (crypt[0] ^ key[25-i]) - crypt[1], 8 );
    }
}

/**
 * FOR: 64b block, 128b key
 * Prefix-free Merkle Damgard construction:
 * message length is the first block, and the block size is key-size.
 */
void HASH_SPECK_PFMD(uint64_t nonce, const u8 firmware[], const uint16_t size, u8 state[8])
{
    u16 idx = 0;
    u16 residual = size; // message length in bytes
    u8 key[16] = {0}; // not necessary but make can it safer
    u32 l[28] = {0};
    u32 k[27] = {0};

    // decrypt "length" first
    *(uint64_t *)state = nonce;
    memcpy(l, &size, 2); // copy length into key to make it prefix-free
    KeyExpansion ( l, k );
    Decrypt ( (u32 *)state, (u32 *)state, k );

    // decrypt main message
#undef ROUND_SIZE
#define ROUND_SIZE 16 // key size in bytes
    for (; idx + ROUND_SIZE < size; idx += ROUND_SIZE)
    {
        memcpy(l, firmware + idx, 12); // 12 bytes message
        memcpy(k, firmware + idx + 12, 4); // 4 bytes message

        KeyExpansion ( l, k );
        Decrypt ( (u32 *)state, (u32 *)state, k );
    }
    residual = size - idx; //how many bytes left not hashed
    //printf("Last idx = %d; residual = %d.\n", idx, residual);

    // last block
    memcpy(key, firmware + idx, residual);
    if (ROUND_SIZE - residual >= 1)
    {
        memset(key + residual, 0x80, 1); // padding, first byte 0b10000000
        memset(key + residual + 1, 0, ROUND_SIZE - residual - 1); // then all 0x00
    }
    memcpy(l, key, 12);
    memcpy(k, key + 12, 4);
    KeyExpansion ( l, k );
    Decrypt ( (u32 *)state, (u32 *)state, k );
}

/**
 * FOR: 64b block, 128b key
 * write codes here: Miyaguchi¨CPreneel
 * input:
 * nonce 8 bytes -> key 16 bytes (padding zeros)
 * message 8 bytes -> message 8 bytes
 */
void HASH_SPECK_MP(uint64_t nonce, const u8 firmware[], const uint16_t size, u8 state[8])
{
    u16 idx = 0;
    u32 key[4]; // not necessary but make can it safer
    u16 residual = size;
    u8 nextState[8] = {0};
    u32 l[28] = {0};
    u32 k[27] = {0};

    memcpy(key, &nonce, 8); // first 64b
    memset(&key[2], 0, 8); // last 64b ->
    memcpy(l, key, 12);
    memcpy(k, key + 12, 4);


#undef ROUND_SIZE
#define ROUND_SIZE 8 // message size
    for (; idx + ROUND_SIZE < size; idx += ROUND_SIZE)
    {
        // prepare ctext
        memcpy(state, firmware + idx, 8);

        // decipher
        KeyExpansion ( l, k );
        Decrypt ( (u32 *)state, (u32 *)nextState, k );

        // calc next state
        *(uint64_t *) state ^= *(uint64_t *) key ^ *(uint64_t *) nextState;

        // update key
        memcpy(key, &state, 8); // first 64b
        memset(&key[2], 0, 8); // last 64b ->
        memcpy(l, key, 12);
        memcpy(k, key + 12, 4);
    }
    residual = size - idx; //how many bytes left not hashed
    //printf("Last idx = %d; residual = %d.\n", idx, residual);

    // last block
    memcpy(state, firmware + idx, residual);
    memset(state + residual, 0, ROUND_SIZE - residual); // fill the missing bytes with 0
    KeyExpansion ( l, k );
    Decrypt ( (u32 *)state, (u32 *)nextState, k );
    *(uint64_t *) state ^= *(uint64_t *) key ^ *(uint64_t *) nextState;
}

/**
 * FOR: 64b block, 128b key
 * write codes here: Matyas-Meyer-Osea
 * input:
 * nonce 8 bytes -> key 16 bytes (padding zeros)
 * message 8 bytes -> message 8 bytes
 */
void HASH_SPECK_MMO(uint64_t nonce, const u8 firmware[], const uint16_t size, u8 state[8])
{
    u16 idx = 0;
    u32 key[4]; // not necessary but make can it safer
    u16 residual = size;
    u8 nextState[8] = {0};
    u32 l[28] = {0};
    u32 k[27] = {0};

    memcpy(key, &nonce, 8); // first 64b
    memset(&key[2], 0, 8); // last 64b ->
    memcpy(l, key, 12);
    memcpy(k, key + 12, 4);


#undef ROUND_SIZE
#define ROUND_SIZE 8 // message size
    for (; idx + ROUND_SIZE < size; idx += ROUND_SIZE)
    {
        // prepare ctext
        memcpy(state, firmware + idx, 8);

        // decipher
        KeyExpansion ( l, k );
        Decrypt ( (u32 *)state, (u32 *)nextState, k );

        // calc next state
        *(uint64_t *) state ^= *(uint64_t *) nextState;

        // update key
        memcpy(key, &state, 8); // first 64b
        memset(&key[2], 0, 8); // last 64b ->
        memcpy(l, key, 12);
        memcpy(k, key + 12, 4);
    }
    residual = size - idx; //how many bytes left not hashed
    //printf("Last idx = %d; residual = %d.\n", idx, residual);

    // last block
    memcpy(state, firmware + idx, residual);
    memset(state + residual, 0, ROUND_SIZE - residual); // fill the missing bytes with 0
    KeyExpansion ( l, k );
    Decrypt ( (u32 *)state, (u32 *)nextState, k );
    *(uint64_t *) state ^= *(uint64_t *) nextState;
}

#undef KeyExpansion 
#undef Decrypt 

#endif
