#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <cpuid.h>
#include <wmmintrin.h>
#include <emmintrin.h>

#include <pthread.h>

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

inline uint64_t low64(const __uint128_t *v) {
    return *(const uint64_t *)(v);
}

inline struct timespec time_diff(struct timespec start, struct timespec end) {
    struct timespec diff;
    if ((end.tv_nsec-start.tv_nsec)<0) {
        diff.tv_sec = end.tv_sec-start.tv_sec-1;
        diff.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
    } else {
        diff.tv_sec = end.tv_sec-start.tv_sec;
        diff.tv_nsec = end.tv_nsec-start.tv_nsec;
    }
    return diff;
}

inline void fprint_time(FILE *stream, struct timespec t) {
    fprintf(stream, "%3ld.%09ld", t.tv_sec, t.tv_nsec);
}

struct timespec program_start_time;

inline void fprint_timestamp(FILE *stream) {
    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);
    struct timespec diff = time_diff(program_start_time, current_time);
    fprint_time(stream, diff);
    fprintf(stream, ": ");
}

// THREADING UTILITIES

#define NUM_THREADS 8

pthread_t threads[NUM_THREADS];

inline void spawn_threads(void *(*start_routine) (void *)) {
    if (NUM_THREADS == 1) {
        start_routine(0);
    } else {
        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_create(&threads[i], NULL, start_routine, (void *) (uintptr_t) i);
        }
        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }
    }
}

// END THREADING UTILITIES

uint8_t A[32] __attribute__((aligned(16)));
uint8_t B[32] __attribute__((aligned(16)));

#define MEM_BITS 24
#define FILTER_BITS 6
#define BUCKET_BITS 14

#define FILTER_MASK (((1 << FILTER_BITS) - 1) << BUCKET_BITS)
#define BUCKET_MASK ((1 << BUCKET_BITS) - 1)
#define NUM_BUCKETS (1 << BUCKET_BITS)
#define MEM_SIZE (1 << MEM_BITS)

#define MEM_PER_THREAD (MEM_SIZE / NUM_THREADS)
static_assert(MEM_PER_THREAD * NUM_THREADS == MEM_SIZE, "Memory is not a multiple of thread size");
#define BUCKETS_PER_THREAD (NUM_BUCKETS / NUM_THREADS)
static_assert(BUCKETS_PER_THREAD * NUM_THREADS == NUM_BUCKETS, "Buckets is not a multiple of thread size");

__uint128_t aes[MEM_SIZE][2] __attribute__((aligned(4096)));
uint64_t nonces[MEM_SIZE];

__uint128_t aes2[MEM_SIZE][2] __attribute__((aligned(4096)));
uint64_t nonces2[MEM_SIZE];
uint64_t buckets[MEM_SIZE];

size_t bucket_locs[NUM_BUCKETS+1];

// BENCHMARKS: Computing 1<<25 AES pairs takes around 1.3 seconds
// 1 << 24 .. 1 << 25 starts to be throughput limited (and hit memory caps)
// Computing 1 << 16 choose 2 pairs takes about 5.2 seconds
// 1 << 15 .. 1 << 16 starts to become actually throughput limited
// That means about 1 << 18 choose 2 pairs in 2 minutes

uint64_t next_nonce;

void *compute_aes_thread(void *arg) {
    uintptr_t tid = (uintptr_t) arg;
    size_t start = MEM_PER_THREAD * tid;

    for (size_t j = 0; j < MEM_PER_THREAD; ) {
        uint64_t nonce = __atomic_fetch_add(&next_nonce, MEM_PER_THREAD, __ATOMIC_RELAXED);
        // Perform the encryptions
        __m128i __attribute__((aligned(16))) ek[15];
        aes_keygen(ek, A);
        for (size_t i = 0; i < MEM_PER_THREAD; i++) {
            aes_encrypt_num(ek, nonce + i, &aes[start + i][0]);
        }
        aes_keygen(ek, B);
        for (size_t i = 0; i < MEM_PER_THREAD; i++) {
            aes_encrypt_num(ek, nonce + i, &aes[start + i][1]);
        }

        for (size_t i = 0; i < MEM_PER_THREAD && j < MEM_PER_THREAD; i++) {
            uint64_t diff = low64(&aes[start + i][0]) - low64(&aes[start + i][1]);
            if ((diff & FILTER_MASK) == 0) {
                aes2[start + j][0] = aes[start + i][0];
                aes2[start + j][1] = aes[start + i][1];
                nonces2[start + j] = nonce + i;
                buckets[start + j] = diff & BUCKET_MASK;
                __atomic_fetch_add(&bucket_locs[buckets[start + j]+1], 1, __ATOMIC_RELAXED);
                j++;
            }
        }
    }

    return NULL;
}

void compute_aes() {
    fprint_timestamp(stderr);
    fprintf(stderr, "START: Computing AES from %" PRIu64 "\n", next_nonce);

    memset(bucket_locs, 0, sizeof(bucket_locs));

    spawn_threads(compute_aes_thread);

    fprint_timestamp(stderr);
    fprintf(stderr, "FINISH: Computed AES up to %" PRIu64 "\n", next_nonce);
}

void *bucket_aes_thread(void *arg) {
    uintptr_t tid = (uintptr_t) arg;
    size_t start = MEM_PER_THREAD * tid;

    for (size_t i = 0; i < MEM_PER_THREAD; i++) {
        size_t j = __atomic_fetch_add(&bucket_locs[buckets[start+i]], 1, __ATOMIC_RELAXED);
        aes[j][0] = aes2[start+i][0];
        aes[j][1] = aes2[start+i][1];
        nonces[j] = nonces2[start+i];
    }

    return NULL;
}

void bucket_aes() {
    fprint_timestamp(stderr);
    fprintf(stderr, "START: Bucketing %u items into %u buckets\n", MEM_SIZE, NUM_BUCKETS);

    for (size_t b = 0; b < NUM_BUCKETS; b ++) {
        bucket_locs[b+1] += bucket_locs[b];
    }
    assert(bucket_locs[NUM_BUCKETS] == MEM_SIZE);

    spawn_threads(bucket_aes_thread);

    // Reset bucket_locs for future use
    for(size_t b = NUM_BUCKETS; b > 0; b--) {
        bucket_locs[b] = bucket_locs[b-1];
    }
    bucket_locs[0] = 0;

    assert(bucket_locs[NUM_BUCKETS] == MEM_SIZE);

    fprint_timestamp(stderr);
    fprintf(stderr, "FINISH: Bucketed items\n");
}

int difficulty;

inline void check_points(uint64_t i, uint64_t j) {
    int diff = popcount128((aes[i][0] + aes[j][1]) ^ (aes[j][0] + aes[i][1]));
    if (diff <= 128 - difficulty) {
        assert(i != j);
        uint64_t N1 = nonces[j], N2 = nonces[i];
        assert(N1 != N2);

        fprint_timestamp(stderr);
        fprintf(stderr, "FINISH: Found a collision!\n");

        printf("%" PRIu64 "\n", N1);
        printf("%" PRIu64 "\n", N2);
        exit(0);
    }
}

void *find_collision_thread(void *arg) {
    uintptr_t tid = (uintptr_t) arg;
    size_t start = BUCKETS_PER_THREAD * tid;

    for (size_t b = 0; b < BUCKETS_PER_THREAD; b++) {
        size_t st = bucket_locs[start+b], en = bucket_locs[start+b+1];
        for (size_t i = st; i < en; i++) {
            for (size_t j = st; j < i; j++) {
                check_points(i, j);
            }
        }
    }

    return NULL;
}

void find_collision() {
    fprint_timestamp(stderr);
    fprintf(stderr, "START: Finding collisions: %u items in %u buckets (%u each) with ~%llu checks\n", MEM_SIZE, NUM_BUCKETS, MEM_SIZE / NUM_BUCKETS, (unsigned long long) (MEM_SIZE / NUM_BUCKETS) * MEM_SIZE / 2);

    spawn_threads(find_collision_thread);

    fprint_timestamp(stderr);
    fprintf(stderr, "FINISH: Found no collisions\n");
}


void aesham2() {
    while (true) {
        compute_aes();
        bucket_aes();
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
    A[0] = 1;
    B[0] = 255;
    difficulty = 102;

    compute_aes();
    bucket_aes();
    struct timespec start, end;
    clock_gettime(CLOCK_REALTIME, &start);
    find_collision();
    clock_gettime(CLOCK_REALTIME, &end);
    fprint_time(stderr, time_diff(start, end));
    exit(0);


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
    clock_gettime(CLOCK_REALTIME, &program_start_time);

    if (!__get_cpuid_aes()) {
        fprintf(stderr, "AES-NI not supported on this CPU!\n");
        return 1;
    }

    if (argc == 2 && argv[1][0] == 't') {
        test();
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

    fprintf(stderr, "Running with %d threads\n", NUM_THREADS);
    aesham2();
}
