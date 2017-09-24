/*
 * lblock.h
 *
 *  Created on: Sep 7, 2017
 *      Author: MewX
 *
 * This version takes 4 bytes as scheduled subkeys from input each time,
 * in the original cipher algorithm, 10-byte key is converted into 128 bytes subkeys,
 * and then run decipher. This is faster than using key schedule function,
 * however, when the input is less than 128 bytes, it's not safe enough.
 */

#ifndef XTEA_H_
#define XTEA_H_

/** @file       main.c
 *  @brief      XTEA encode
 *
 *  @author     Yang Su, Auto-ID Lab, The University of Adelaide
 */

/**
 * as a unique ID.
 */
#include <stdint.h>

#ifndef SMHASHER
#include <msp430.h>
#else
#include <stdio.h>
#endif

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

/* XTEA is a version of slightly improved tea.
   The plain or cypher text is in v[0], v[1].
   The key is in k[n], where n = 0 - 3,
   The number of coding cycles is given by N and
   the number of decoding cycles given by -N     */
void tean(uint32_t *v, uint32_t *k,uint32_t ncycles)      /* replaces TEA's code and decode */
{
  register uint32_t
    y = v[0],
    z = v[1],
    DELTA = 0x9e3779b9,
    sum, A,B;
        sum = DELTA * (ncycles);
         sum = 0x9e3779b9 * 64;
         while (sum)
         {   z   -= (y << 4 ^ y >> 5) + y ^ sum + k[sum >> 11 & 3];
            sum -= DELTA;
             y   -= (z << 4 ^ z >> 5) + z ^ sum + k[sum & 3];
         }

    v[0] = y;
    v[1] = z;

    return;
}

/**
 * FOR: 64b block, 128b key
 * Prefix-free Merkle Damgard construction:
 * message length is the first block, and the block size is key-size.
 */
void HASH_XTEA_PFMD(uint64_t nonce, const u8 firmware[], const uint16_t size, u8 state[8])
{
    u16 idx = 0;
    u8 key[16] = { 0 }; // temp key
    u16 residual = size; // message length in bytes
    *(uint64_t *)state = nonce;

    // decrypt "length" first
    memcpy(key, &size, 2); // copy length into key to make it prefix-free
    tean((uint32_t *) state, (u32 *)key, 64);

    // decrypt main message
#undef ROUND_SIZE
#define ROUND_SIZE 16 // key size in bytes
    for (; idx + ROUND_SIZE < size; idx += ROUND_SIZE)
    {     //first n blocks
        //printf("Processing idx = %d: ", idx);
        //for (i = 0; i < ROUND_SIZE; i ++) printf("0x%02X ", firmware[idx + i]);
        //printf("\n");
        memcpy(key, firmware + (idx), ROUND_SIZE);
        tean((u32 *) state, (u32 *)key, 64);
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
    tean((uint32_t *) state, (u32 *)key, 64);
}

/**
 * FOR: 64b block, 128b key
 * write codes here: Miyaguchi�CPreneel
 * input:
 * nonce 8 bytes -> key 16 bytes (padding zeros)
 * message 8 bytes -> message 8 bytes
 */
void __attribute__ ((noinline)) HASH_XTEA_MP(uint64_t nonce, const u8 firmware[], const uint16_t size, u8 state[8])
{
    u16 idx = 0;
    u32 key[4];
    u16 residual = size;
    u8 nextState[8] = {0};
    memcpy(key, &nonce, 8); // first 64b
    memset(&key[2], 0, 8); // last 64b ->
#undef ROUND_SIZE
#define ROUND_SIZE 8 // message size
    for (; idx + ROUND_SIZE < size; idx += ROUND_SIZE)
    {
        // prepare ctext
        memcpy(nextState, firmware + idx, 8);
        memcpy(state, nextState, 8);

        // decipher
        tean((uint32_t *) nextState, key, 64);

        // calc next state
        *(uint64_t *) state ^= *(uint64_t *) key ^ *(uint64_t *) nextState;

        // update key
        memcpy(key, state, 8);
        memset(&key[2], 0, 8); // last 64b
    }
    residual = size - idx; //how many bytes left not hashed
    //printf("Last idx = %d; residual = %d.\n", idx, residual);

    // last block
    memcpy(nextState, firmware + idx, residual);
    memset(nextState + residual, 0, ROUND_SIZE - residual); // fill the missing bytes with 0
    memcpy(state, nextState, 8);
    tean((uint32_t *) nextState, key, 64);
    *(uint64_t *) state ^= *(uint64_t *) key ^ *(uint64_t *) nextState;
}

/**
 * FOR: 64b block, 128b key
 * write codes here: Matyas-Meyer-Osea
 * input:
 * nonce 8 bytes -> key 16 bytes (padding zeros)
 * message 8 bytes -> message 8 bytes
 */
void __attribute__ ((noinline)) HASH_XTEA_MMO(uint64_t nonce, const u8 firmware[], const uint16_t size, u8 state[8])
{
    u16 idx = 0;
    u32 key[4];
    u16 residual = size;
    u8 nextState[8] = {0};
    memcpy(key, &nonce, 8); // first 64b
    memset(&key[2], 0, 8); // last 64b ->

#undef ROUND_SIZE
#define ROUND_SIZE 8 // message size
    for (; idx + ROUND_SIZE < size; idx += ROUND_SIZE)
    {
        // prepare ctext
        memcpy(nextState, firmware + idx, 8);
        memcpy(state, nextState, 8);

        // decipher
        tean((uint32_t *) nextState, key, 64);

        // calc next state
        *(uint64_t *) state ^= *(uint64_t *) nextState; // simply remove key from MP

        // update key
        memcpy(key, state, 8);
        memset(&key[2], 0, 8); // last 64b
    }
    residual = size - idx; //how many bytes left not hashed
    //printf("Last idx = %d; residual = %d.\n", idx, residual);

    // last block
    memcpy(nextState, firmware + idx, residual);
    memset(nextState + residual, 0, ROUND_SIZE - residual); // fill the missing bytes with 0
    memcpy(state, nextState, 8);
    tean((uint32_t *) nextState, key, 64);
    *(uint64_t *) state ^= *(uint64_t *) nextState;
}

#endif /* XTEA_H_ */
