#ifndef SEA_H_
#define SEA_H_

#include <stdint.h>

#ifndef SMHASHER
#include <msp430.h>
#else
#include <stdio.h>
#endif

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

#define SIZE 96//n : plaintext size, key size. k*6B
#define B 16 //processor (or word) size.
#define NB (SIZE/(2*B)) //nb = n/2b : number of words per Feistel branch.
#undef NBROUND
#define NBROUND 95 // odd number

#define MASK 0xFFFF

/**********************************************************************/
#define XOR SEA_XOR
 void XOR(u16 x[NB],u16 y[NB])
{
    u16 i;
    for(i=0;i<NB;i++)
    {
        x[i]^=y[i];
    }
    return;
}

#define Sub SEA_Sub
 void Sub(u16 x[NB])
{
    u16 i;
    for(i=0;i<(SIZE/(6*B));i++)
    {
        x[3*i]   ^= x[3*i+1] & x[3*i+2];
        x[3*i+1] ^= x[3*i]   & x[3*i+2];
        x[3*i+2] ^= x[3*i+1] | x[3*i];
    }
    return;
}

 void WordRot(u16 x[NB])
{
    u16 i;
    u16 temp=x[NB-1];
    for(i=NB-1;i>0;i--)
    {
        x[i]=x[i-1];
    }
    x[0]=temp;
    return;
}

 void InvWordRot(u16 x[NB])
{
    u16 i;
    u16 temp=x[0];
    for(i=0;i<NB-1;i++)
    {
        x[i]=x[i+1];
    }
    x[NB-1]=temp;
    return;
}

 void BitRot(u16 x[NB])
{
    u16 i;
    for(i=0;i<NB/3;i++)
    {
        x[3*i]=(x[3*i]>>1)^(x[3*i]<<(B-1));
        x[3*i+2]=(x[3*i+2]<<1)^(x[3*i+2]>>(B-1));
    }
    return;
}

#define Add SEA_Add
 void Add(u16 x[NB],u16 y[NB])
{
    u16 i;
    for(i=0;i<NB;i++)
    {
        x[i]=(x[i]+y[i])&MASK;
    }
    return;
}

/**********************************************************************/
 void fk(u16 kr[NB],u16 kl[NB],u16 krDest[NB],u16 klDest[NB],u16 c[NB])
{
    u16 i;
    for(i=0;i<NB;i++) krDest[i]=kr[i];
    for(i=0;i<NB;i++) klDest[i]=kr[i];

    Add(krDest,c);
    Sub(krDest);
    BitRot(krDest);
    WordRot(krDest);
    XOR(krDest,kl);
    return;
}

 void fd(u16 r[NB],u16 l[NB],u16 k[NB])
{
    u16 temp[NB],i;
    for(i=0;i<NB;i++) temp[i]=r[i];

    Add(r,k);
    Sub(r);
    BitRot(r);
    XOR(r,l);
    InvWordRot(r);
    for(i=0;i<NB;i++) l[i]=temp[i];

    return;
}

#define KeySchedul SEA_KeySchedul
 void KeySchedul(u16 mkey[2*NB],u16 rkey[NBROUND][2*NB])
{
    u16 i,j,temp,c[NB];
    for(i=1;i<NB;i++) c[i]=0;
    for(i=0;i<2*NB;i++) rkey[0][i]=mkey[i];
    for(i=1;i<=(NBROUND>>2);i++)
    {
        c[0]=i;
        //[KLi , KRi ] = FK (KLi−1 , KRi−1 , C(i));
        fk(rkey[i-1],rkey[i-1]+3,rkey[i],rkey[i]+3,c);
    }

    for(j=0;j<NB;j++)
    {
        temp=rkey[NBROUND>>2][j];
        rkey[NBROUND>>2][j]=rkey[NBROUND>>2][j+3];
        rkey[NBROUND>>2][j+3]=temp;
    }

    for(;i<NBROUND;i++)
    {
        c[0]=NBROUND-i;
        //[KLi , KRi ] = FK (KLi−1 , KRi−1 , C(r − i));
        fk(rkey[i-1],rkey[i-1]+3,rkey[i],rkey[i]+3,c);
    }
    return;
}

#define Decrypt SEA_Decrypt
 void Decrypt(u16 state[2*NB],u16 rkey[NBROUND][2*NB])
{
    u16 i,temp;

    for(i=NBROUND;i>((NBROUND+1)>>2);i--)
    {
        fd(state,state+3,rkey[i-1]+3);
    }
    for(;i>=1;i--)
    {
        fd(state,state+3,rkey[i-1]);
    }
    for(i=0;i<NB;i++)
    {
        temp=state[i];
        state[i]=state[i+3];
        state[i+3]=temp;
    }

    return;
}

#define dec SEA_dec
 void __attribute__ ((noinline)) dec(u16 mkey[2*NB], u16 rkey[NBROUND][2*NB], u16 state[2*NB]) {
     KeySchedul(mkey,rkey);
     Decrypt(state,rkey);
 }

// int main()
// {
//     WDTCTL = WDTPW | WDTHOLD;   // Stop watchdog timer
//     PM5CTL0 &= ~LOCKLPM5;       // Lock LPM5.
//
//     u16 i;
//     u16 state[2*NB];
//     u16 mkey[2*NB];
//     u16 rkey[NBROUND][2*NB];
//
//     for(i=0;i<2*NB;i++) state[i]=i;
//     for(i=0;i<2*NB;i++) mkey[i]=2*i;
//
//     START_DECRYPT();
//     KeySchedul(mkey,rkey);
//     dec(mkey, rkey, state);
//     END_EXPE();
//     return 0;
// }


/**
 * FOR: 64b block, 128b key
 * Prefix-free Merkle Damgard construction:
 * message length is the first block, and the block size is key-size.
 */
void HASH_SEA_PFMD(uint64_t nonce, const u8 firmware[], const uint16_t size, u8 state[12])
{
    u16 idx = 0;
    u16 residual = size; // message length in bytes
    u8 mkey[4*NB] = {0}; // 2 * 6 = 12
    u16 rkey[NBROUND][2*NB];

    *(uint64_t *)state = nonce; // first 64b
//    *(uint32_t *)&state[4] = 0; // last 32b

    // decrypt "length" first
    memcpy(mkey, &size, 2); // copy length into key to make it prefix-free
    dec((u16 *)mkey, rkey, (u16 *)state);

    // decrypt main message
#undef ROUND_SIZE
#define ROUND_SIZE 12 // key size in bytes
    for (; idx + ROUND_SIZE < size; idx += ROUND_SIZE)
    {     //first n blocks
        //printf("Processing idx = %d: ", idx);
        //for (i = 0; i < ROUND_SIZE; i ++) printf("0x%02X ", firmware[idx + i]);
        //printf("\n");
        memcpy(mkey, firmware + (idx), ROUND_SIZE);
        dec((u16 *)mkey, rkey, (u16 *)state);
    }
    residual = size - idx; //how many bytes left not hashed
    //printf("Last idx = %d; residual = %d.\n", idx, residual);

    // last block
    memcpy(mkey, firmware + idx, residual);
    if (ROUND_SIZE - residual >= 1)
    {
        memset(mkey + residual, 0x80, 1); // padding, first byte 0b10000000
        memset(mkey + residual + 1, 0, ROUND_SIZE - residual - 1); // then all 0x00
    }
    dec((u16 *)mkey, rkey, (u16 *)state);
}

/**
 * FOR: 64b block, 128b key
 * write codes here: Miyaguchi锟紺Preneel
 * input:
 * nonce 8 bytes -> key 16 bytes (padding zeros)
 * message 8 bytes -> message 8 bytes
 */
void __attribute__ ((noinline)) HASH_SEA_MP(uint64_t nonce, const u8 firmware[], const uint16_t size, u8 state[12])
{
    u16 idx = 0;
    u16 residual = size;
    u8 nextState[4*NB] = {0};
    u8 mkey[4*NB] = {0}; // 2 * 6 = 12
    u16 rkey[NBROUND][2*NB];

    memcpy(mkey, &nonce, 8); // first 64b
    memset(&mkey[8], 0, 4); // last 32b ->

#undef ROUND_SIZE
#define ROUND_SIZE 12 // message size
    for (; idx + ROUND_SIZE < size; idx += ROUND_SIZE)
    {
        // prepare ctext
        memcpy(nextState, firmware + idx, ROUND_SIZE);
        memcpy(state, nextState, ROUND_SIZE);

        // decipher
        dec((u16 *)mkey, rkey, (u16 *)nextState);

        // calc next state
        *(uint64_t *) state ^= *(uint64_t *) mkey ^ *(uint64_t *) nextState;
        *((uint32_t *)&state[8]) ^= *((uint32_t *)&mkey[8]) ^ *((uint32_t *)&nextState[8]);

        // update key
        memcpy(mkey, state, 8);
        memset(&mkey[8], 0, 4); // last 32b ->
    }
    residual = size - idx; //how many bytes left not hashed
    //printf("Last idx = %d; residual = %d.\n", idx, residual);

    // last block
    memcpy(nextState, firmware + idx, residual);
    memset(nextState + residual, 0, ROUND_SIZE - residual); // fill the missing bytes with 0
    memcpy(state, nextState, ROUND_SIZE);
    dec((u16 *)mkey, rkey, (u16 *)nextState);
    *(uint64_t *) state ^= *(uint64_t *) mkey ^ *(uint64_t *) nextState;
    *((uint32_t *)&state[8]) ^= *((uint32_t *)&mkey[8]) ^ *((uint32_t *)&nextState[8]);
}

/**
 * FOR: 64b block, 128b key
 * write codes here: Matyas-Meyer-Osea
 * input:
 * nonce 8 bytes -> key 16 bytes (padding zeros)
 * message 8 bytes -> message 8 bytes
 */
void __attribute__ ((noinline)) HASH_SEA_MMO(uint64_t nonce, const u8 firmware[], const uint16_t size, u8 state[12])
{
    u16 idx = 0;
    u16 residual = size;
    u8 nextState[4*NB] = {0};
    u8 mkey[4*NB] = {0}; // 2 * 6 = 12
    u16 rkey[NBROUND][2*NB];

    memcpy(mkey, &nonce, 8); // first 64b
    memset(&mkey[8], 0, 4); // last 32b ->

#undef ROUND_SIZE
#define ROUND_SIZE 12 // message size
    for (; idx + ROUND_SIZE < size; idx += ROUND_SIZE)
    {
        // prepare ctext
        memcpy(nextState, firmware + idx, ROUND_SIZE);
        memcpy(state, nextState, ROUND_SIZE);

        // decipher
        dec((u16 *)mkey, rkey, (u16 *)nextState);

        // calc next state
        *(uint64_t *) state ^= *(uint64_t *) nextState;
        *((uint32_t *)&state[8]) ^= *((uint32_t *)&nextState[8]);

        // update key
        memcpy(mkey, state, 8);
        memset(&mkey[8], 0, 4); // last 32b ->
    }
    residual = size - idx; //how many bytes left not hashed
    //printf("Last idx = %d; residual = %d.\n", idx, residual);

    // last block
    memcpy(nextState, firmware + idx, residual);
    memset(nextState + residual, 0, ROUND_SIZE - residual); // fill the missing bytes with 0
    memcpy(state, nextState, ROUND_SIZE);
    dec((u16 *)mkey, rkey, (u16 *)nextState);
    *(uint64_t *) state ^= *(uint64_t *) nextState;
    *((uint32_t *)&state[8]) ^= *((uint32_t *)&nextState[8]);
}

#undef KeySchedul
#undef Decrypt
#undef XOR
#undef Sub
#undef Add
#undef dec

#endif
