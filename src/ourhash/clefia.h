#ifndef CLEFIA_H_
#define CLEFIA_H_

#include <stdint.h>

#ifndef SMHASHER
#include <msp430.h>
#else
#include <stdio.h>
#endif

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

void ByteCpy(u8 *dst, const u8 *src, int bytelen);
void ByteXor(u8 *dst, const u8 *a, const u8 *b, int bytelen);

u8 ClefiaMul2(u8 x);
void ClefiaF0Xor(u8 *y, const u8 *x, const u8 *rk);
void ClefiaF1Xor(u8 *y, const u8 *x, const u8 *rk);
void ClefiaGfn4(u8 *y, const u8 *x, const u8 *rk, int r);
void ClefiaGfn8(u8 *y, const u8 *x, const u8 *rk, int r);
void ClefiaGfn4Inv(u8 *y, const u8 *x, const u8 *rk, int r);

void ClefiaDoubleSwap(u8 *lk);
void ClefiaConSet(u8 *con, const u8 *iv, int lk);
void ClefiaKeySet128(u8 *rk, const u8 *skey);
void ClefiaKeySet192(u8 *rk, const u8 *skey);
void ClefiaKeySet256(u8 *rk, const u8 *skey);

int ClefiaKeySet(u8 *rk, const u8 *skey, const int key_bitlen);
void ClefiaEncrypt(u8 *ct, const u8 *pt, const u8 *rk, const int r);
void ClefiaDecrypt(u8 *pt, const u8 *ct, const u8 *rk, const int r);


/* S0 (8-bit S-box based on four 4-bit S-boxes) */
const u8 clefia_s0[256] = {
  0x57U, 0x49U, 0xd1U, 0xc6U, 0x2fU, 0x33U, 0x74U, 0xfbU,
  0x95U, 0x6dU, 0x82U, 0xeaU, 0x0eU, 0xb0U, 0xa8U, 0x1cU,
  0x28U, 0xd0U, 0x4bU, 0x92U, 0x5cU, 0xeeU, 0x85U, 0xb1U,
  0xc4U, 0x0aU, 0x76U, 0x3dU, 0x63U, 0xf9U, 0x17U, 0xafU,
  0xbfU, 0xa1U, 0x19U, 0x65U, 0xf7U, 0x7aU, 0x32U, 0x20U,
  0x06U, 0xceU, 0xe4U, 0x83U, 0x9dU, 0x5bU, 0x4cU, 0xd8U,
  0x42U, 0x5dU, 0x2eU, 0xe8U, 0xd4U, 0x9bU, 0x0fU, 0x13U,
  0x3cU, 0x89U, 0x67U, 0xc0U, 0x71U, 0xaaU, 0xb6U, 0xf5U,
  0xa4U, 0xbeU, 0xfdU, 0x8cU, 0x12U, 0x00U, 0x97U, 0xdaU,
  0x78U, 0xe1U, 0xcfU, 0x6bU, 0x39U, 0x43U, 0x55U, 0x26U,
  0x30U, 0x98U, 0xccU, 0xddU, 0xebU, 0x54U, 0xb3U, 0x8fU,
  0x4eU, 0x16U, 0xfaU, 0x22U, 0xa5U, 0x77U, 0x09U, 0x61U,
  0xd6U, 0x2aU, 0x53U, 0x37U, 0x45U, 0xc1U, 0x6cU, 0xaeU,
  0xefU, 0x70U, 0x08U, 0x99U, 0x8bU, 0x1dU, 0xf2U, 0xb4U,
  0xe9U, 0xc7U, 0x9fU, 0x4aU, 0x31U, 0x25U, 0xfeU, 0x7cU,
  0xd3U, 0xa2U, 0xbdU, 0x56U, 0x14U, 0x88U, 0x60U, 0x0bU,
  0xcdU, 0xe2U, 0x34U, 0x50U, 0x9eU, 0xdcU, 0x11U, 0x05U,
  0x2bU, 0xb7U, 0xa9U, 0x48U, 0xffU, 0x66U, 0x8aU, 0x73U,
  0x03U, 0x75U, 0x86U, 0xf1U, 0x6aU, 0xa7U, 0x40U, 0xc2U,
  0xb9U, 0x2cU, 0xdbU, 0x1fU, 0x58U, 0x94U, 0x3eU, 0xedU,
  0xfcU, 0x1bU, 0xa0U, 0x04U, 0xb8U, 0x8dU, 0xe6U, 0x59U,
  0x62U, 0x93U, 0x35U, 0x7eU, 0xcaU, 0x21U, 0xdfU, 0x47U,
  0x15U, 0xf3U, 0xbaU, 0x7fU, 0xa6U, 0x69U, 0xc8U, 0x4dU,
  0x87U, 0x3bU, 0x9cU, 0x01U, 0xe0U, 0xdeU, 0x24U, 0x52U,
  0x7bU, 0x0cU, 0x68U, 0x1eU, 0x80U, 0xb2U, 0x5aU, 0xe7U,
  0xadU, 0xd5U, 0x23U, 0xf4U, 0x46U, 0x3fU, 0x91U, 0xc9U,
  0x6eU, 0x84U, 0x72U, 0xbbU, 0x0dU, 0x18U, 0xd9U, 0x96U,
  0xf0U, 0x5fU, 0x41U, 0xacU, 0x27U, 0xc5U, 0xe3U, 0x3aU,
  0x81U, 0x6fU, 0x07U, 0xa3U, 0x79U, 0xf6U, 0x2dU, 0x38U,
  0x1aU, 0x44U, 0x5eU, 0xb5U, 0xd2U, 0xecU, 0xcbU, 0x90U,
  0x9aU, 0x36U, 0xe5U, 0x29U, 0xc3U, 0x4fU, 0xabU, 0x64U,
  0x51U, 0xf8U, 0x10U, 0xd7U, 0xbcU, 0x02U, 0x7dU, 0x8eU
};

/* S1 (8-bit S-box based on inverse function) */
const u8 clefia_s1[256] = {
  0x6cU, 0xdaU, 0xc3U, 0xe9U, 0x4eU, 0x9dU, 0x0aU, 0x3dU,
  0xb8U, 0x36U, 0xb4U, 0x38U, 0x13U, 0x34U, 0x0cU, 0xd9U,
  0xbfU, 0x74U, 0x94U, 0x8fU, 0xb7U, 0x9cU, 0xe5U, 0xdcU,
  0x9eU, 0x07U, 0x49U, 0x4fU, 0x98U, 0x2cU, 0xb0U, 0x93U,
  0x12U, 0xebU, 0xcdU, 0xb3U, 0x92U, 0xe7U, 0x41U, 0x60U,
  0xe3U, 0x21U, 0x27U, 0x3bU, 0xe6U, 0x19U, 0xd2U, 0x0eU,
  0x91U, 0x11U, 0xc7U, 0x3fU, 0x2aU, 0x8eU, 0xa1U, 0xbcU,
  0x2bU, 0xc8U, 0xc5U, 0x0fU, 0x5bU, 0xf3U, 0x87U, 0x8bU,
  0xfbU, 0xf5U, 0xdeU, 0x20U, 0xc6U, 0xa7U, 0x84U, 0xceU,
  0xd8U, 0x65U, 0x51U, 0xc9U, 0xa4U, 0xefU, 0x43U, 0x53U,
  0x25U, 0x5dU, 0x9bU, 0x31U, 0xe8U, 0x3eU, 0x0dU, 0xd7U,
  0x80U, 0xffU, 0x69U, 0x8aU, 0xbaU, 0x0bU, 0x73U, 0x5cU,
  0x6eU, 0x54U, 0x15U, 0x62U, 0xf6U, 0x35U, 0x30U, 0x52U,
  0xa3U, 0x16U, 0xd3U, 0x28U, 0x32U, 0xfaU, 0xaaU, 0x5eU,
  0xcfU, 0xeaU, 0xedU, 0x78U, 0x33U, 0x58U, 0x09U, 0x7bU,
  0x63U, 0xc0U, 0xc1U, 0x46U, 0x1eU, 0xdfU, 0xa9U, 0x99U,
  0x55U, 0x04U, 0xc4U, 0x86U, 0x39U, 0x77U, 0x82U, 0xecU,
  0x40U, 0x18U, 0x90U, 0x97U, 0x59U, 0xddU, 0x83U, 0x1fU,
  0x9aU, 0x37U, 0x06U, 0x24U, 0x64U, 0x7cU, 0xa5U, 0x56U,
  0x48U, 0x08U, 0x85U, 0xd0U, 0x61U, 0x26U, 0xcaU, 0x6fU,
  0x7eU, 0x6aU, 0xb6U, 0x71U, 0xa0U, 0x70U, 0x05U, 0xd1U,
  0x45U, 0x8cU, 0x23U, 0x1cU, 0xf0U, 0xeeU, 0x89U, 0xadU,
  0x7aU, 0x4bU, 0xc2U, 0x2fU, 0xdbU, 0x5aU, 0x4dU, 0x76U,
  0x67U, 0x17U, 0x2dU, 0xf4U, 0xcbU, 0xb1U, 0x4aU, 0xa8U,
  0xb5U, 0x22U, 0x47U, 0x3aU, 0xd5U, 0x10U, 0x4cU, 0x72U,
  0xccU, 0x00U, 0xf9U, 0xe0U, 0xfdU, 0xe2U, 0xfeU, 0xaeU,
  0xf8U, 0x5fU, 0xabU, 0xf1U, 0x1bU, 0x42U, 0x81U, 0xd6U,
  0xbeU, 0x44U, 0x29U, 0xa6U, 0x57U, 0xb9U, 0xafU, 0xf2U,
  0xd4U, 0x75U, 0x66U, 0xbbU, 0x68U, 0x9fU, 0x50U, 0x02U,
  0x01U, 0x3cU, 0x7fU, 0x8dU, 0x1aU, 0x88U, 0xbdU, 0xacU,
  0xf7U, 0xe4U, 0x79U, 0x96U, 0xa2U, 0xfcU, 0x6dU, 0xb2U,
  0x6bU, 0x03U, 0xe1U, 0x2eU, 0x7dU, 0x14U, 0x95U, 0x1dU
};


void ByteCpy(u8 *dst, const u8 *src, int bytelen)
{
  while(bytelen-- > 0){
    *dst++ = *src++;
  }
}

void ByteXor(u8 *dst, const u8 *a, const u8 *b, int bytelen)
{
  while(bytelen-- > 0){
    *dst++ = *a++ ^ *b++;
  }
}

u8 ClefiaMul2(u8 x)
{
  /* multiplication over GF(2^8) (p(x) = '11d') */
  if(x & 0x80U){
    x ^= 0x0eU;
  }
  return ((x << 1) | (x >> 7));
}

#define ClefiaMul4(_x) (ClefiaMul2(ClefiaMul2((_x))))
#define ClefiaMul6(_x) (ClefiaMul2((_x)) ^ ClefiaMul4((_x)))
#define ClefiaMul8(_x) (ClefiaMul2(ClefiaMul4((_x))))
#define ClefiaMulA(_x) (ClefiaMul2((_x)) ^ ClefiaMul8((_x)))

void ClefiaF0Xor(u8 *dst, const u8 *src, const u8 *rk)
{
  u8 x[4], y[4], z[4];

  /* F0 */
  /* Key addition */
  ByteXor(x, src, rk, 4);
  /* Substitution layer */
  z[0] = clefia_s0[x[0]];
  z[1] = clefia_s1[x[1]];
  z[2] = clefia_s0[x[2]];
  z[3] = clefia_s1[x[3]];
  /* Diffusion layer (M0) */
  y[0] =            z[0]  ^ ClefiaMul2(z[1]) ^ ClefiaMul4(z[2]) ^ ClefiaMul6(z[3]);
  y[1] = ClefiaMul2(z[0]) ^            z[1]  ^ ClefiaMul6(z[2]) ^ ClefiaMul4(z[3]);
  y[2] = ClefiaMul4(z[0]) ^ ClefiaMul6(z[1]) ^            z[2]  ^ ClefiaMul2(z[3]);
  y[3] = ClefiaMul6(z[0]) ^ ClefiaMul4(z[1]) ^ ClefiaMul2(z[2]) ^            z[3] ;

  /* Xoring after F0 */
  ByteCpy(dst + 0, src + 0, 4);
  ByteXor(dst + 4, src + 4, y, 4);
}

void ClefiaF1Xor(u8 *dst, const u8 *src, const u8 *rk)
{
  u8 x[4], y[4], z[4];

  /* F1 */
  /* Key addition */
  ByteXor(x, src, rk, 4);
  /* Substitution layer */
  z[0] = clefia_s1[x[0]];
  z[1] = clefia_s0[x[1]];
  z[2] = clefia_s1[x[2]];
  z[3] = clefia_s0[x[3]];
  /* Diffusion layer (M1) */
  y[0] =            z[0]  ^ ClefiaMul8(z[1]) ^ ClefiaMul2(z[2]) ^ ClefiaMulA(z[3]);
  y[1] = ClefiaMul8(z[0]) ^            z[1]  ^ ClefiaMulA(z[2]) ^ ClefiaMul2(z[3]);
  y[2] = ClefiaMul2(z[0]) ^ ClefiaMulA(z[1]) ^            z[2]  ^ ClefiaMul8(z[3]);
  y[3] = ClefiaMulA(z[0]) ^ ClefiaMul2(z[1]) ^ ClefiaMul8(z[2]) ^            z[3] ;

  /* Xoring after F1 */
  ByteCpy(dst + 0, src + 0, 4);
  ByteXor(dst + 4, src + 4, y, 4);
}

void ClefiaGfn4(u8 *y, const u8 *x, const u8 *rk, int r)
{
  u8 fin[16], fout[16];

  ByteCpy(fin, x, 16);
  while(r-- > 0){
    ClefiaF0Xor(fout + 0, fin + 0, rk + 0);
    ClefiaF1Xor(fout + 8, fin + 8, rk + 4);
    rk += 8;
    if(r){ /* swapping for encryption */
      ByteCpy(fin + 0,  fout + 4, 12);
      ByteCpy(fin + 12, fout + 0, 4);
    }
  }
  ByteCpy(y, fout, 16);
}

void ClefiaGfn4Inv(u8 *y, const u8 *x, const u8 *rk, int r)
{
  u8 fin[16], fout[16];

  rk += (r - 1) * 8;
  ByteCpy(fin, x, 16);
  while(r-- > 0){
    ClefiaF0Xor(fout + 0, fin + 0, rk + 0);
    ClefiaF1Xor(fout + 8, fin + 8, rk + 4);
    rk -= 8;
    if(r){ /* swapping for decryption */
      ByteCpy(fin + 0, fout + 12, 4);
      ByteCpy(fin + 4, fout + 0,  12);
    }
  }
  ByteCpy(y, fout, 16);
}

void ClefiaDoubleSwap(u8 *lk)
{
  u8 t[16];

  t[0]  = (lk[0] << 7) | (lk[1]  >> 1);
  t[1]  = (lk[1] << 7) | (lk[2]  >> 1);
  t[2]  = (lk[2] << 7) | (lk[3]  >> 1);
  t[3]  = (lk[3] << 7) | (lk[4]  >> 1);
  t[4]  = (lk[4] << 7) | (lk[5]  >> 1);
  t[5]  = (lk[5] << 7) | (lk[6]  >> 1);
  t[6]  = (lk[6] << 7) | (lk[7]  >> 1);
  t[7]  = (lk[7] << 7) | (lk[15] & 0x7fU);

  t[8]  = (lk[8]  >> 7) | (lk[0]  & 0xfeU);
  t[9]  = (lk[9]  >> 7) | (lk[8]  << 1);
  t[10] = (lk[10] >> 7) | (lk[9]  << 1);
  t[11] = (lk[11] >> 7) | (lk[10] << 1);
  t[12] = (lk[12] >> 7) | (lk[11] << 1);
  t[13] = (lk[13] >> 7) | (lk[12] << 1);
  t[14] = (lk[14] >> 7) | (lk[13] << 1);
  t[15] = (lk[15] >> 7) | (lk[14] << 1);

  ByteCpy(lk, t, 16);
}

void ClefiaConSet(u8 *con, const u8 *iv, int lk)
{
  u8 t[2];
  u8 tmp;

  ByteCpy(t, iv, 2);
  while(lk-- > 0){
    con[0] = t[0] ^ 0xb7U; /* P_16 = 0xb7e1 (natural logarithm) */
    con[1] = t[1] ^ 0xe1U;
    con[2] = ~((t[0] << 1) | (t[1] >> 7));
    con[3] = ~((t[1] << 1) | (t[0] >> 7));
    con[4] = ~t[0] ^ 0x24U; /* Q_16 = 0x243f (circle ratio) */
    con[5] = ~t[1] ^ 0x3fU;
    con[6] = t[1];
    con[7] = t[0];
    con += 8;

    /* updating T */
    if(t[1] & 0x01U){
      t[0] ^= 0xa8U;
      t[1] ^= 0x30U;
    }
    tmp = t[0] << 7;
    t[0] = (t[0] >> 1) | (t[1] << 7);
    t[1] = (t[1] >> 1) | tmp;
  }
}

void ClefiaKeySet128(u8 *rk, const u8 *skey)
{
  const u8 iv[2] = {0x42U, 0x8aU}; /* cubic root of 2 */
  u8 lk[16];
  u8 con128[4 * 60];
  int i;

  /* generating CONi^(128) (0 <= i < 60, lk = 30) */
  ClefiaConSet(con128, iv, 30);
  /* GFN_{4,12} (generating L from K) */
  ClefiaGfn4(lk, skey, con128, 12);

  ByteCpy(rk, skey, 8); /* initial whitening key (WK0, WK1) */
  rk += 8;
  for(i = 0; i < 9; i++){ /* round key (RKi (0 <= i < 36)) */
    ByteXor(rk, lk, con128 + i * 16 + (4 * 24), 16);
    if(i % 2){
      ByteXor(rk, rk, skey, 16); /* Xoring K */
    }
    ClefiaDoubleSwap(lk); /* Updating L (DoubleSwap function) */
    rk += 16;
  }
  ByteCpy(rk, skey + 8, 8); /* final whitening key (WK2, WK3) */
}

void ClefiaDecrypt(u8 *pt, const u8 *ct, const u8 *rk, const int r)
{
  u8 rin[16], rout[16];

  ByteCpy(rin, ct, 16);

  ByteXor(rin + 4,  rin + 4,  rk + r * 8 + 8,  4); /* initial key whitening */
  ByteXor(rin + 12, rin + 12, rk + r * 8 + 12, 4);
  rk += 8;

  ClefiaGfn4Inv(rout, rin, rk, r); /* GFN^{-1}_{4,r} */

  ByteCpy(pt, rout, 16);
  ByteXor(pt + 4,  pt + 4,  rk - 8, 4); /* final key whitening */
  ByteXor(pt + 12, pt + 12, rk - 4, 4);
}


/**
 * FOR: 128b block, 128b key
 * Prefix-free Merkle Damgard construction:
 * message length is the first block, and the block size is key-size.
 */
void HASH_CLEFIA_PFMD(uint64_t nonce, const u8 firmware[], const uint16_t size, u8 state[16])
{
    u16 idx = 0;
    u16 residual = size; // message length in bytes
    u8 mkey[16] = {0};
    u8 rk[8 * 26 + 16]; /* 8 bytes x 26 rounds(max) + whitening keys */

    *(uint64_t *)state = nonce; // first 64b

    // decrypt "length" first
    memcpy(mkey, &size, 2); // copy length into key to make it prefix-free
    ClefiaKeySet128(rk, mkey);
    ClefiaDecrypt(state, state, rk, 18);

    // decrypt main message
#undef ROUND_SIZE
#define ROUND_SIZE 16 // key size in bytes
    for (; idx + ROUND_SIZE < size; idx += ROUND_SIZE)
    {     //first n blocks
        //printf("Processing idx = %d: ", idx);
        //for (i = 0; i < ROUND_SIZE; i ++) printf("0x%02X ", firmware[idx + i]);
        //printf("\n");
        memcpy(mkey, firmware + idx, ROUND_SIZE);
        ClefiaKeySet128(rk, mkey);
        ClefiaDecrypt(state, state, rk, 18);
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
    ClefiaKeySet128(rk, mkey);
    ClefiaDecrypt(state, state, rk, 18);
}

/**
 * FOR: 128b block, 128b key
 * write codes here: Miyaguchi閿熺春Preneel
 * input:
 * nonce 16 bytes -> key 16 bytes (padding zeros)
 * message 16 bytes -> message 16 bytes
 */
void __attribute__ ((noinline)) HASH_CLEFIA_MP(uint64_t nonce, const u8 firmware[], const uint16_t size, u8 state[16])
{
    u16 idx = 0;
    u16 residual = size;
    u8 nextState[16] = {0};
    u8 mkey[16] = {0};
    u8 rk[8 * 26 + 16]; /* 8 bytes x 26 rounds(max) + whitening keys */

    memcpy(mkey, &nonce, 8); // first 64b
    memset(&mkey[8], 0, 8); // last 64b ->

#undef ROUND_SIZE
#define ROUND_SIZE 16 // message size
    for (; idx + ROUND_SIZE < size; idx += ROUND_SIZE)
    {
        // prepare ctext
        memcpy(nextState, firmware + idx, ROUND_SIZE);
        memcpy(state, nextState, ROUND_SIZE);

        // decipher
        ClefiaKeySet128(rk, mkey);
        ClefiaDecrypt(nextState, nextState, rk, 18);

        // calc next state
        *(uint64_t *) state ^= *(uint64_t *) mkey ^ *(uint64_t *) nextState;
        *((uint64_t *)&state[8]) ^= *((uint64_t *)&mkey[8]) ^ *((uint64_t *)&nextState[8]);

        // update key
        memcpy(mkey, state, 8);
        memset(&mkey[8], 0, 8); // last 32b ->
    }
    residual = size - idx; //how many bytes left not hashed
    //printf("Last idx = %d; residual = %d.\n", idx, residual);

    // last block
    memcpy(nextState, firmware + idx, residual);
    memset(nextState + residual, 0, ROUND_SIZE - residual); // fill the missing bytes with 0
    memcpy(state, nextState, ROUND_SIZE);
    ClefiaKeySet128(rk, mkey);
    ClefiaDecrypt(nextState, nextState, rk, 18);
    *(uint64_t *) state ^= *(uint64_t *) mkey ^ *(uint64_t *) nextState;
    *((uint64_t *)&state[8]) ^= *((uint64_t *)&mkey[8]) ^ *((uint64_t *)&nextState[8]);
}

/**
 * FOR: 128b block, 128b key
 * write codes here: Matyas-Meyer-Osea
 * input:
 * nonce 16 bytes -> key 16 bytes (padding zeros)
 * message 16 bytes -> message 16 bytes
 */
void __attribute__ ((noinline)) HASH_CLEFIA_MMO(uint64_t nonce, const u8 firmware[], const uint16_t size, u8 state[16])
{
    u16 idx = 0;
    u16 residual = size;
    u8 nextState[16] = {0};
    u8 mkey[16] = {0};
    u8 rk[8 * 26 + 16]; /* 8 bytes x 26 rounds(max) + whitening keys */

    memcpy(mkey, &nonce, 8); // first 64b
    memset(&mkey[8], 0, 8); // last 64b ->

#undef ROUND_SIZE
#define ROUND_SIZE 16 // message size
    for (; idx + ROUND_SIZE < size; idx += ROUND_SIZE)
    {
        // prepare ctext
        memcpy(nextState, firmware + idx, ROUND_SIZE);
        memcpy(state, nextState, ROUND_SIZE);

        // decipher
        ClefiaKeySet128(rk, mkey);
        ClefiaDecrypt(nextState, nextState, rk, 18);

        // calc next state
        *(uint64_t *) state ^= *(uint64_t *) nextState;
        *((uint64_t *)&state[8]) ^=  *((uint64_t *)&nextState[8]);

        // update key
        memcpy(mkey, state, 8);
        memset(&mkey[8], 0, 8); // last 32b ->
    }
    residual = size - idx; //how many bytes left not hashed
    //printf("Last idx = %d; residual = %d.\n", idx, residual);

    // last block
    memcpy(nextState, firmware + idx, residual);
    memset(nextState + residual, 0, ROUND_SIZE - residual); // fill the missing bytes with 0
    memcpy(state, nextState, ROUND_SIZE);
    ClefiaKeySet128(rk, mkey);
    ClefiaDecrypt(nextState, nextState, rk, 18);
    *(uint64_t *) state ^= *(uint64_t *) nextState;
    *((uint64_t *)&state[8]) ^=  *((uint64_t *)&nextState[8]);
}

#endif