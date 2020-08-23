//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#include <string.h>
#include "aes.h"
#include "secure-rng.h"

static const uint64_t kMaxReseedCount = UINT64_C(1) << 48;

static void AES256_CTR_DRBG_Update(uint8_t *provided_data, uint8_t *Key, uint8_t *V)
{
    uint8_t temp[48];

    for (int i=0; i<3; i++) {
        //increment V
        for (int j=15; j>=0; j--) {
            if ( V[j] == 0xff )
                V[j] = 0x00;
            else {
                V[j]++;
                break;
            }
        }

        aesctr256 (temp+16*i, Key, V, 16);
    }
    if ( provided_data != NULL )
        for (int i=0; i<48; i++)
            temp[i] ^= provided_data[i];
    memcpy(Key, temp, 32);
    memcpy(V, temp+32, 16);
}

void secure_rng_seed(struct secure_rng_ctx *ctx, const uint8_t *entropy_input, const uint8_t *personalization_string)
{
    uint8_t seed_material[48];

    memcpy(seed_material, entropy_input, 48);
    if (personalization_string)
        for (int i=0; i<48; i++)
            seed_material[i] ^= personalization_string[i];

    static const uint8_t kInitMask[48] = {
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1,
        0xc4, 0xcb, 0x73, 0x8b, 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18, 0x72, 0x60, 0x03, 0xca,
        0x37, 0xa6, 0x2a, 0x74, 0xd1, 0xa2, 0xf5, 0x8e, 0x75, 0x06, 0x35, 0x8e,
    };

    for (int i = 0; i < 48; i++)
        seed_material[i] ^= kInitMask[i];

    memset(ctx->Key, 0x00, 32);
    memset(ctx->V, 0x00, 16);

    AES256_CTR_DRBG_Update(seed_material, ctx->Key, ctx->V);
    ctx->reseed_counter = 1;
}

void secure_rng_reseed(struct secure_rng_ctx *ctx, const uint8_t *entropy_input)
{
    uint8_t seed_material[48];
    memcpy(seed_material, entropy_input, 48);
    AES256_CTR_DRBG_Update(seed_material, ctx->Key, ctx->V);
    ctx->reseed_counter++;
}

int secure_rng_bytes(struct secure_rng_ctx *ctx, uint8_t *x, size_t xlen)
{
    uint8_t block[16];
    int i = 0;

    if (ctx->reseed_counter > MAX_GENERATE_LENGTH) {
        return RNG_BAD_MAXLEN;
    }

    if (ctx->reseed_counter > kMaxReseedCount) {
        return RNG_NEED_RESEED;
    }

    while ( xlen > 0 ) {
        //increment V
        for (int j=15; j>=0; j--) {
            if ( ctx->V[j] == 0xff )
                ctx->V[j] = 0x00;
            else {
                ctx->V[j]++;
                break;
            }
        }
        aesctr256 (block, ctx->Key, ctx->V, 16);
        if ( xlen > 15 ) {
            memcpy(x+i, block, 16);
            i += 16;
            xlen -= 16;
        }
        else {
            memcpy(x+i, block, xlen);
            xlen = 0;
        }
    }
    AES256_CTR_DRBG_Update(NULL, ctx->Key, ctx->V);
    ctx->reseed_counter++;

    return RNG_SUCCESS;
}

