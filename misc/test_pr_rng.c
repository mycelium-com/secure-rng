#include "secure-rng.h"

#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

uint8_t fake_entropy1[48] = {0};
uint8_t fake_entropy2[48] = {1};
uint8_t fake_personalization[48] = {0};

uint8_t fake_key[32];
uint8_t fake_seed[64];

// Lazy and simplest imitation for prediction resistance callback
static void pr_seeder (uint8_t entropy[48]) {
    static int fd = -1;
    if (fd == -1) fd = open ("/dev/urandom", O_RDONLY);
    read (fd, entropy, 48);
}

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
    
    // Enable prediction resistance
    //  Set reseed interval to 0 (reseed on every call)
    secure_rng_set_seeder(&ctx, &pr_seeder, 0);
    
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
