//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#ifndef SECURERNG_H
#define SECURERNG_H

#include <stdio.h>
#include <stdint.h>

#define RNG_SUCCESS       0
#define RNG_BAD_MAXLEN   -1
#define RNG_NEED_RESEED  -2

#define MAX_GENERATE_LENGTH 65535

struct secure_rng_ctx {
    unsigned char   Key[32];
    unsigned char   V[16];
    uint64_t    reseed_counter;
} __attribute__ ((aligned (16)));

#ifdef __cplusplus
extern "C" {
#endif

void secure_rng_seed(struct secure_rng_ctx *ctx, const uint8_t *entropy_input, const uint8_t *personalization_string);
void secure_rng_reseed(struct secure_rng_ctx *ctx, const uint8_t *entropy_input);
int secure_rng_bytes(struct secure_rng_ctx *ctx, uint8_t *x, size_t xlen);

#ifdef __cplusplus
}
#endif

#endif
