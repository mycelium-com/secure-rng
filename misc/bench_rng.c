#include "secure-rng.h"

#include <stdio.h>
#include <time.h>

uint8_t fake_entropy[48] = {0};
uint8_t fake_personalization[48] = {0};

uint8_t fake_key[32];
uint8_t fake_seed[64];

int main() {
    struct secure_rng_ctx ctx;
    
    unsigned i;
    clock_t tic;
    clock_t toc;
    double elapsed;
    
    const unsigned num_keys = 1000000;
    const unsigned num_seeds = 1000000;

    secure_rng_seed(&ctx, fake_entropy, fake_personalization);
    
    printf("Computing %d random private keys...\n", num_keys);

    // Benchmark start
    tic = clock();

    for(i = 0; i < num_keys; ++i) {
        if (RNG_SUCCESS != secure_rng_bytes(&ctx, fake_key, sizeof(fake_key))) {
            printf("secure_rng_bytes() failed\n");
            return -1;
        }
    }

    // Benchmark end
    toc = clock();
    elapsed = (double)(toc - tic) / CLOCKS_PER_SEC;

    printf("Elapsed: %f seconds (%f keys/s)\n", elapsed, num_keys / elapsed);

    printf("Computing %d random private seeds...\n", num_seeds);

    // Benchmark start
    tic = clock();

    for(i = 0; i < num_seeds; ++i) {
        if (RNG_SUCCESS != secure_rng_bytes(&ctx, fake_seed, sizeof(fake_seed))) {
            printf("secure_rng_bytes() failed\n");
            return -1;
        }
    }

    // Benchmark end
    toc = clock();
    elapsed = (double)(toc - tic) / CLOCKS_PER_SEC;

    printf("Elapsed: %f seconds (%f seeds/s)\n", elapsed, num_seeds / elapsed);

}
