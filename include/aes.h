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

#ifdef SOFTWARE_FALLBACK
void aesctr256_software (uint8_t *out, const uint8_t *sk, const void *counter, int bytes);
void aesctr256_zeroiv_software (uint8_t *out, const uint8_t *sk, int bytes);
#endif

#ifdef HARDWARE_SUPPORT
void aesctr256_hardware (uint8_t *out, const uint8_t *sk, const void *counter, int bytes);
void aesctr256_zeroiv_hardware (uint8_t *out, const uint8_t *sk, int bytes);
int aes_hardware_supported();
#endif

#ifdef __cplusplus
}
#endif

#endif
