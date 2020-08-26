#include "secure-rng.h"

#include <stdio.h>
#include <time.h>

uint8_t fake_entropy1[48] = {0};
uint8_t fake_entropy2[48] = {1};
uint8_t fake_personalization[48] = {0};

uint8_t fake_key[32];
uint8_t fake_seed[64];

void print(const uint8_t *data, int length) {
    for (int i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
}

int main() {
    struct secure_rng_ctx ctx;
    
    unsigned i;
    clock_t tic;
    clock_t toc;
    double elapsed;
    
    const unsigned num_keys = 1000;
    const unsigned num_seeds = 1000;

    if (RNG_SUCCESS != secure_rng_seed(&ctx, fake_entropy1, fake_personalization, sizeof(fake_personalization))) {
        printf("secure_rng_seed() failed\n");
        return -1;
    }
    
    printf("Computing %d random private keys...\n", num_keys);

    // Benchmark start
    tic = clock();

    for(i = 0; i < num_keys; ++i) {
        if (RNG_SUCCESS != secure_rng_bytes(&ctx, fake_key, sizeof(fake_key), 0)) {
            printf("secure_rng_bytes() failed\n");
            return -1;
        }
        printf("key %d: ", i);
        print(fake_key, sizeof(fake_key));
        printf("\n");
    }

    // Benchmark end
    toc = clock();
    elapsed = (double)(toc - tic) / CLOCKS_PER_SEC;

    printf("Elapsed: %f seconds (%f keys/s)\n", elapsed, num_keys / elapsed);

    if (RNG_SUCCESS != secure_rng_reseed(&ctx, fake_entropy2, NULL, 0)) {
        printf("secure_rng_seed() failed\n");
        return -1;
    }

    printf("Computing %d random private seeds...\n", num_seeds);

    // Benchmark start
    tic = clock();

    for(i = 0; i < num_seeds; ++i) {
        if (RNG_SUCCESS != secure_rng_bytes(&ctx, fake_seed, sizeof(fake_seed), 0)) {
            printf("secure_rng_bytes() failed\n");
            return -1;
        }
        printf("seed %d: ", i);
        print(fake_seed, sizeof(fake_seed));
        printf("\n");
    }

    // Benchmark end
    toc = clock();
    elapsed = (double)(toc - tic) / CLOCKS_PER_SEC;

    printf("Elapsed: %f seconds (%f seeds/s)\n", elapsed, num_seeds / elapsed);

}
