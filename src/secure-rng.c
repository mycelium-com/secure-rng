//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#include <string.h>
#include <stddef.h>
#include "aes.h"
#include "secure-rng.h"

static const uint64_t kMaxReseedCount = UINT64_C(1) << 48;

// Increment V
inline static void drbg_increment_v(struct secure_rng_ctx *ctx) {
    // Treat AES counter as a big-endian integer
    for (int j=15; j>=0; --j) {
        if (ctx->V[j] == 0xff) {
            ctx->V[j] = 0x00;
        } else {
            ctx->V[j]++;
            break;
        }
    }
}

inline static void drbg_run_one_round(uint8_t buffer[16], struct secure_rng_ctx *ctx) {
    drbg_increment_v(ctx);
    aesctr256 (buffer, ctx->Key, ctx->V, 16);
}

inline static void drbg_run_three_rounds(uint8_t buffer[48], struct secure_rng_ctx *ctx) {
    drbg_run_one_round(buffer, ctx);
    drbg_run_one_round(buffer + 16, ctx);
    drbg_run_one_round(buffer + 32, ctx);
}

inline static void drbg_mix(uint8_t buffer[48], const uint8_t provided_data[48]) {
    if (provided_data != NULL) {
        for (int i=0; i<48; ++i) {
            buffer[i] ^= provided_data[i];
        }
    }
}

inline static void drbg_apply(const uint8_t buffer[48], struct secure_rng_ctx *ctx) {
    memcpy(ctx->Key, buffer, 32);
    memcpy(ctx->V, buffer+32, 16);
}

void secure_rng_set_seeder(struct secure_rng_ctx *ctx, void (*resistance_seeder_function)(uint8_t seed_out[48]), uint64_t reseed_interval) {
    if (resistance_seeder_function == NULL) {
        ctx->resistance_seeder = NULL;
        ctx->reseed_interval = kMaxReseedCount;
    }
    else {
        ctx->resistance_seeder = resistance_seeder_function;
        ctx->reseed_interval = reseed_interval;
    }
}

int secure_rng_seed(struct secure_rng_ctx *ctx, const uint8_t entropy_input[48], const uint8_t *personalization_string, size_t personalization_len) {
    uint8_t round_bytes[48] = {0};
    uint8_t seed_material[48] = {0};

    // Check additional entropy buffer length
    if (personalization_len > 0) {
        // Must not be nonger than 48 bytes
        if (personalization_len > 48) {
            return RNG_BAD_MAXLEN;
        }

        // Must not be NULL
        if (personalization_string == NULL) {
            return RNG_BAD_MAXLEN;
        }
    }

    // Original entropy buffer is a constant
    memcpy(seed_material, entropy_input, 48);

    // XOR the entropy data with personalization
    //  bytes, if there are any
    for (int i=0; i < personalization_len; ++i) {
        seed_material[i] ^= personalization_string[i];
    }

    // kInitMask is the result of encrypting blocks with
    //  big-endian value 1, 2 and 3 with the all-zero AES-256 key
    static const uint8_t kInitMask[48] = {
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1,
        0xc4, 0xcb, 0x73, 0x8b, 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18, 0x72, 0x60, 0x03, 0xca,
        0x37, 0xa6, 0x2a, 0x74, 0xd1, 0xa2, 0xf5, 0x8e, 0x75, 0x06, 0x35, 0x8e,
    };

    // XOR seed material with the init mask bytes
    for (int i = 0; i < 48; ++i) {
        seed_material[i] ^= kInitMask[i];
    }
    
    // Key and counter are
    //  initialized by zeros
    drbg_apply(round_bytes, ctx);

    // Run first three rounds to calculate
    //  AES key and init counter
    drbg_run_three_rounds(round_bytes, ctx);
    drbg_mix(round_bytes, seed_material);
    drbg_apply(round_bytes, ctx);
    ctx->reseed_counter = 1;

    // Prediction resistance is
    //   disabled by default
    ctx->resistance_seeder = NULL;
    ctx->reseed_interval = kMaxReseedCount;

    return RNG_SUCCESS;
}

int secure_rng_reseed(struct secure_rng_ctx *ctx, const uint8_t entropy[48], const uint8_t *additional_data, size_t additional_data_len) {
    uint8_t entropy_copy[48] = {0};
    uint8_t round_bytes[48] = {0};
    memcpy(entropy_copy, entropy, 48);

    // Handle additional entropy
    if (additional_data_len > 0) {
        // Must not be longer than 48 bytes
        if (additional_data_len > 48) {
            return RNG_BAD_MAXLEN;
        }

        // Must not be NULL
        if (additional_data == NULL) {
            return RNG_BAD_MAXLEN;
        }

        // XOR entropy with additional data
        for (size_t i = 0; i < additional_data_len; ++i) {
            entropy_copy[i] ^= additional_data[i];
        }
    }

    // Reset the RNG internal state
    drbg_run_three_rounds(round_bytes, ctx);
    drbg_mix(round_bytes, entropy_copy);
    drbg_apply(round_bytes, ctx);
    ctx->reseed_counter = 1;

    return RNG_SUCCESS;
}

int secure_rng_bytes(struct secure_rng_ctx *ctx, uint8_t *x, size_t xlen) {
    // Buffer for generated block
    uint8_t block[16] = {0};
    uint8_t state_bytes[48] = {0};
    const uint8_t *xend = x + xlen;
    
    // Remaining length
    ptrdiff_t xrem = 0;

    // Must provide non-NULL pointer and must not
    //  query more than MAX_GENERATE_LENGTH bytes
    if (xlen > MAX_GENERATE_LENGTH || x == NULL) {
        return RNG_BAD_MAXLEN;
    }

    // If the prediction resistance is enabled then
    //   query new entropy and use it to seed a generator
    if (ctx->resistance_seeder != NULL && ctx->reseed_counter > ctx->reseed_interval) {
        ctx->resistance_seeder(state_bytes);
        secure_rng_reseed(ctx, state_bytes, NULL, 0);
    }

    // If the entropy pool is exhausted then request reseeding
    if (ctx->reseed_counter > kMaxReseedCount) {
        return RNG_NEED_RESEED;
    }

    // Repeat while amount of remaining
    //  bytes is greater than zero
    while ( (xrem = xend - x) ) {
        
        if (xrem > 15) {
            // Generate new block of pseudo random
            // bytes directly into the result buffer
            drbg_run_one_round(x, ctx);
            // Increment x by block size
            x += 16;
        }
        else {
            // Generate new block of pseudo random
            // bytes and copy the requested amount
            drbg_run_one_round(block, ctx);
            memcpy(x, block, xrem);
            // Increment x by xrem
            x += xrem;
        }
    }

    // Complete by running three generation rounds
    drbg_run_three_rounds(state_bytes, ctx);
    drbg_apply(state_bytes, ctx);
    
    // Increment reseed counter
    ctx->reseed_counter++;

    return RNG_SUCCESS;
}
