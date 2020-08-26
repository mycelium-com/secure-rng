#ifndef SECURERNG_H
#define SECURERNG_H

#include <stdio.h>
#include <stdint.h>

#define RNG_SUCCESS       0
#define RNG_BAD_MAXLEN   -1
#define RNG_NEED_RESEED  -2

#define MAX_GENERATE_LENGTH 65535

struct secure_rng_ctx {
    uint8_t   Key[32];
    uint8_t   V[16];
    uint64_t  reseed_counter;
    uint64_t  reseed_interval;
    void (*resistance_seeder)(uint8_t seed_out[48]);
} __attribute__ ((aligned (16)));

#ifdef __cplusplus
extern "C" {
#endif

void secure_rng_set_seeder(struct secure_rng_ctx *ctx, void (*resistance_seeder_function)(uint8_t seed_out[48]), uint64_t reseed_interval);
int secure_rng_seed(struct secure_rng_ctx *ctx, const uint8_t entropy_input[48], const uint8_t *personalization_string, size_t personalization_len);
int secure_rng_reseed(struct secure_rng_ctx *ctx, const uint8_t entropy_input[48], const uint8_t *additional_data, size_t additional_data_len);
int secure_rng_bytes(struct secure_rng_ctx *ctx, uint8_t *x, size_t xlen, int resistance);

#ifdef __cplusplus
}
#endif

#endif
