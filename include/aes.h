/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void aesctr256 (uint8_t *out, const uint8_t *sk, const void *counter, int bytes);

void aesctr256_zeroiv (uint8_t *out, const uint8_t *sk, int bytes);

#ifdef __cplusplus
}
#endif

#endif
