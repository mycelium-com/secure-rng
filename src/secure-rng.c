//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#include <string.h>
#include "aes.h"
#include "secure-rng.h"

static const uint64_t kMaxReseedCount = UINT64_C(1) << 48;

// Increment V
inline static void drbg_increment_v(struct secure_rng_ctx *ctx) {
    for (int j=15; j>=0; --j) {
        if (ctx->V[j] == 0xff) {
            ctx->V[j] = 0x00;
        } else {
            ctx->V[j]++;
            break;
        }
    }
}

inline static void drbg_round(struct secure_rng_ctx *ctx) {
    uint8_t temp[48];

    for (int i=0; i<3; ++i) {
        drbg_increment_v(ctx);
        aesctr256 (temp+16*i, ctx->Key, ctx->V, 16);
    }

    memcpy(ctx->Key, temp, 32);
    memcpy(ctx->V, temp+32, 16);
}

inline static void drbg_update(uint8_t provided_data[48], struct secure_rng_ctx *ctx) {
    uint8_t temp[48];

    for (int i=0; i<3; ++i) {
        drbg_increment_v(ctx);
        aesctr256 (temp+16*i, ctx->Key, ctx->V, 16);
    }

    if (provided_data != NULL) {
        for (int i=0; i<48; ++i) {
            temp[i] ^= provided_data[i];
        }
    }

    memcpy(ctx->Key, temp, 32);
    memcpy(ctx->V, temp+32, 16);
}

int secure_rng_seed(struct secure_rng_ctx *ctx, const uint8_t entropy_input[48], const uint8_t *personalization_string, size_t personalization_len) {
    uint8_t seed_material[48];

    if (personalization_len > 48) {
        return RNG_BAD_MAXLEN;
    }

    memcpy(seed_material, entropy_input, 48);

    for (int i=0; i < personalization_len; ++i) {
        seed_material[i] ^= personalization_string[i];
    }

    static const uint8_t kInitMask[48] = {
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1,
        0xc4, 0xcb, 0x73, 0x8b, 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18, 0x72, 0x60, 0x03, 0xca,
        0x37, 0xa6, 0x2a, 0x74, 0xd1, 0xa2, 0xf5, 0x8e, 0x75, 0x06, 0x35, 0x8e,
    };

    for (int i = 0; i < 48; ++i) {
        seed_material[i] ^= kInitMask[i];
    }

    memset(ctx->Key, 0x00, 32);
    memset(ctx->V, 0x00, 16);

    drbg_update(seed_material, ctx);
    ctx->reseed_counter = 1;

    return RNG_SUCCESS;
}

int secure_rng_reseed(struct secure_rng_ctx *ctx, const uint8_t entropy[48], const uint8_t *additional_data, size_t additional_data_len) {
    uint8_t entropy_copy[48];
    memcpy(entropy_copy, entropy, 48);

    if (additional_data_len > 0) {
        if (additional_data_len > 48) {
            return RNG_BAD_MAXLEN;
        }

        for (size_t i = 0; i < additional_data_len; ++i) {
            entropy_copy[i] ^= additional_data[i];
        }
    }

    drbg_update(entropy_copy, ctx);
    ctx->reseed_counter = 1;

    return RNG_SUCCESS;
}

int secure_rng_bytes(struct secure_rng_ctx *ctx, uint8_t *x, size_t xlen) {
    uint8_t block[16];
    int i = 0;

    if (xlen > MAX_GENERATE_LENGTH) {
        return RNG_BAD_MAXLEN;
    }

    if (ctx->reseed_counter > kMaxReseedCount) {
        return RNG_NEED_RESEED;
    }

    while ( xlen > 0 ) {
        drbg_increment_v(ctx);
        aesctr256 (block, ctx->Key, ctx->V, 16);
        if (xlen > 15) {
            memcpy(x+i, block, 16);
            i += 16;
            xlen -= 16;
        }
        else {
            memcpy(x+i, block, xlen);
            xlen = 0;
        }
    }

    drbg_round(ctx);
    ctx->reseed_counter++;

    return RNG_SUCCESS;
}
