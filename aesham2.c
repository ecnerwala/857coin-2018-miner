#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <cpuid.h>
#include <wmmintrin.h>
#include <emmintrin.h>

bool __get_cpuid_aes() {
    unsigned int a,b,c,d;
    if (!__get_cpuid(0x1, &a, &b, &c, &d)) {
        return false;
    }
    return (bool) (c & bit_AES);
}

inline int popcount128(__uint128_t v) {
    uint64_t *a = (uint64_t *) &v;
    return __builtin_popcountll(a[0]) + __builtin_popcountll(a[1]);
}

#define IS_ALIGNED(v, a) ((((uintptr_t) v) & ((a)-1)) == 0)

inline __m128i aes128_keyexpand(__m128i key) {
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, _mm_slli_si128(key, 4));
}

#define KEYEXP128_H(K1, K2, I, S) _mm_xor_si128(aes128_keyexpand(K1), \
        _mm_shuffle_epi32(_mm_aeskeygenassist_si128(K2, I), S))

#define KEYEXP256(K1, K2, I)  KEYEXP128_H(K1, K2, I, 0xff)
#define KEYEXP256_2(K1, K2) KEYEXP128_H(K1, K2, 0x00, 0xaa)

inline void aes_keygen(__m128i rk[], const void* cipherKey) {
    assert(IS_ALIGNED(cipherKey, 16));
    const void *cipherKey2 = (const char *) cipherKey + 16;

    /* 256 bit key setup */
    rk[0] = _mm_load_si128((const __m128i*) cipherKey);
    rk[1] = _mm_load_si128((const __m128i*) cipherKey2);
    rk[2] = KEYEXP256(rk[0], rk[1], 0x01);
    rk[3] = KEYEXP256_2(rk[1], rk[2]);
    rk[4] = KEYEXP256(rk[2], rk[3], 0x02);
    rk[5] = KEYEXP256_2(rk[3], rk[4]);
    rk[6] = KEYEXP256(rk[4], rk[5], 0x04);
    rk[7] = KEYEXP256_2(rk[5], rk[6]);
    rk[8] = KEYEXP256(rk[6], rk[7], 0x08);
    rk[9] = KEYEXP256_2(rk[7], rk[8]);
    rk[10] = KEYEXP256(rk[8], rk[9], 0x10);
    rk[11] = KEYEXP256_2(rk[9], rk[10]);
    rk[12] = KEYEXP256(rk[10], rk[11], 0x20);
    rk[13] = KEYEXP256_2(rk[11], rk[12]);
    rk[14] = KEYEXP256(rk[12], rk[13], 0x40);
}

inline void aes_encrypt_num(__m128i ek[], uint64_t in, __uint128_t* out) {
    assert(IS_ALIGNED(out, 16));
    // Confusingly, this uses little-endian, so we have to reverse all our numbers as we insert them
    in = __builtin_bswap64(in);
    __m128i m = _mm_loadl_epi64((const __m128i*) &in);
    m = _mm_shuffle_epi32(m, 0b01001110);
    m = _mm_xor_si128(m, ek[0]);
    m = _mm_aesenc_si128(m, ek[1]);
    m = _mm_aesenc_si128(m, ek[2]);
    m = _mm_aesenc_si128(m, ek[3]);
    m = _mm_aesenc_si128(m, ek[4]);
    m = _mm_aesenc_si128(m, ek[5]);
    m = _mm_aesenc_si128(m, ek[6]);
    m = _mm_aesenc_si128(m, ek[7]);
    m = _mm_aesenc_si128(m, ek[8]);
    m = _mm_aesenc_si128(m, ek[9]);
    m = _mm_aesenc_si128(m, ek[10]);
    m = _mm_aesenc_si128(m, ek[11]);
    m = _mm_aesenc_si128(m, ek[12]);
    m = _mm_aesenc_si128(m, ek[13]);
    m = _mm_aesenclast_si128(m, ek[14]);
    m = _mm_shuffle_epi32(m, 0b01001110);
    _mm_storeu_si128((__m128i*) out, m);
    uint64_t *res = (uint64_t*) out;
    res[0] = __builtin_bswap64(res[0]);
    res[1] = __builtin_bswap64(res[1]);
}

uint8_t A[32] __attribute__((aligned(16)));
uint8_t B[32] __attribute__((aligned(16)));

#define BUCKET_SIZE (1 << 20)
__uint128_t cache[BUCKET_SIZE][2] __attribute__((aligned(64)));
uint64_t nonces[BUCKET_SIZE];

void cache_aes(uint64_t start) {
    fprintf(stderr, "Computed from %" PRIu64 "\n", start);

    uint64_t end = start + BUCKET_SIZE;
    {
        // Perform the encryptions
        __m128i __attribute__((aligned(16))) ek[15];
        aes_keygen(ek, A);
        for (uint64_t i = 0; i < BUCKET_SIZE; i++) {
            aes_encrypt_num(ek, start + i, &cache[i][0]);
        }
        aes_keygen(ek, B);
        for (uint64_t i = 0; i < BUCKET_SIZE; i++) {
            aes_encrypt_num(ek, start + i, &cache[i][1]);
        }
    }

    for (uint64_t i = 0; i < BUCKET_SIZE; i++) {
        nonces[i] = start + i;
    }

    fprintf(stderr, "Computed up to %" PRIu64 "\n", end);
}

int difficulty;

inline void check_points(uint64_t i, uint64_t j) {
    int diff = popcount128((cache[i][0] + cache[j][1]) ^ (cache[j][0] + cache[i][1]));
    if (diff <= 128 - difficulty) {
        uint64_t N1 = nonces[j], N2 = nonces[i];
        printf("%" PRIu64 "\n", N1);
        printf("%" PRIu64 "\n", N2);
        exit(0);
    }
}

inline void find_collision_flat(uint64_t si, uint64_t sj, uint64_t n) {
    if (si < sj) return;
    for (uint64_t i = 0; i < n; i ++) {
        for (uint64_t j = 0; j < ((si == sj) ? i : n); j ++) {
            check_points(si + i, sj + j);
        }
    }
}

void find_collision_recursive(uint64_t si, uint64_t sj, uint64_t n) {
    if (si < sj) return;
    if (n <= (1 << 10)) {
        return find_collision_flat(si, sj, n);
    }

    n /= 2;
    find_collision_recursive(si, sj, n);
    find_collision_recursive(si + n, sj, n);
    find_collision_recursive(si, sj + n, n);
    find_collision_recursive(si + n, sj + n, n);
}

void find_collision() {
    // TODO: parallelize
    find_collision_recursive(0, 0, BUCKET_SIZE);
}


void aesham2() {
    for (uint64_t start = 0; ; start += BUCKET_SIZE) {
        cache_aes(start);
        find_collision();
    }
}


void parse_hex(const char s[], uint8_t v[]) {
    while (*s) {
        sscanf(s, "%2hhx", v);
        s += 2;
        v ++;
    }
}


void print128(__uint128_t val) {
    uint8_t *v = (uint8_t *) &val;
    for (int i = 0; i < 16; i++) { fprintf(stderr, "%02x", v[i]); } fprintf(stderr, "\n");
}


void test() {
    memset(A, 0, sizeof(A));
    A[0] = 1;

    __m128i __attribute__((aligned(16))) ek[15];
    aes_keygen(ek, A);

    __uint128_t res;
    aes_encrypt_num(ek, 1, &res);

    __uint128_t res2;
    aes_encrypt_num(ek, 2, &res2);

    print128(res);
    print128(res2);

    print128(res + res2);
}


int main(int argc, char *argv[]) {
    if (!__get_cpuid_aes()) {
        fprintf(stderr, "AES-NI not supported on this CPU!\n");
        return 1;
    }

    if (argc != 4) {
        printf("Usage: aesham2 SEED SEED2 DIFFICULTY\n");
        return 1;
    }

    char *seed1 = argv[1];
    char *seed2 = argv[2];
    parse_hex(seed1, A);
    parse_hex(seed2, B);
    //for (int i = 0; i < 32; i++) { fprintf(stderr, "%02x", A[i]); } fprintf(stderr, "\n");
    //for (int i = 0; i < 32; i++) { fprintf(stderr, "%02x", B[i]); } fprintf(stderr, "\n");

    difficulty = atoi(argv[3]);

    aesham2();
}
