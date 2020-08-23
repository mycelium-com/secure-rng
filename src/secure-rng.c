//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#include <string.h>
#include "aes.h"
#include "secure-rng.h"

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
    memset(ctx->Key, 0x00, 32);
    memset(ctx->V, 0x00, 16);
    AES256_CTR_DRBG_Update(seed_material, ctx->Key, ctx->V);
    ctx->reseed_counter = 1;
}

int secure_rng_bytes(struct secure_rng_ctx *ctx, uint8_t *x, size_t xlen)
{
    uint8_t block[16];
    int i = 0;

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

