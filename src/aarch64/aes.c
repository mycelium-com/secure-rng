/*
 *  Alexey Demidov
 *  Radius Group, LLC
 *  balthazar@yandex.ru
 *
 *  Microsoft Reference Source License (Ms-RSL)
 */

#include <arm_neon.h>
#include "aes.h"

static const uint8x16_t zero8x16 = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};

static uint8x16_t assist256_1 (uint8x16_t a, uint8x16_t b) {
    uint8x16_t c;
    b = vreinterpretq_u8_s32(vdupq_laneq_s32(vreinterpretq_s32_u8(b), 3)); // shuffle ( , 0xff or 3,3,3,3)
    c = vextq_u8(vdupq_n_u8(0), a, 12); // slli (12 = 16 - 4)
    a = veorq_u8(a, c);
    c = vextq_u8(vdupq_n_u8(0), c, 12);
    a = veorq_u8(a, c);
    c = vextq_u8(vdupq_n_u8(0), c, 12);
    a = veorq_u8(a, c);
    return veorq_u8(a, b); // return a = veorq_s32(a, b);
}

static uint8x16_t assist256_2 (uint8x16_t a, uint8x16_t c) {
    uint8x16_t b, d;

    d = vaeseq_u8(a, zero8x16);
    uint8x16_t dest = {
        d[0x4], d[0x1], d[0xE], d[0xB],
        d[0x1], d[0xE], d[0xB], d[0x4],
        d[0xC], d[0x9], d[0x6], d[0x3],
        d[0x9], d[0x6], d[0x3], d[0xC]
    };
    d = dest; //d = dest ^ (int32x4_t)((uint32x4_t){0, rcon, 0, rcon}); drop xor - rcon == 0
    b = vreinterpretq_u8_s32(vdupq_laneq_s32(vreinterpretq_s32_u8(d), 2)); // shuffle ( , 0xaa or 2,2,2,2)
    d = vextq_u8(vdupq_n_u8(0), c, 12);
    c = veorq_u8(c, d);
    d = vextq_u8(vdupq_n_u8(0), d, 12);
    c = veorq_u8(c, d);
    d = vextq_u8(vdupq_n_u8(0), d, 12);
    c = veorq_u8(c, d);
    return veorq_u8(c, b); // return c = veorq_s32(c, b);
}

static uint8x16_t aeskeygenassist(uint8x16_t a, unsigned rcon) {

    a = vaeseq_u8(a, zero8x16);
    uint8x16_t dest = {
        a[0x4], a[0x1], a[0xE], a[0xB],
        a[0x1], a[0xE], a[0xB], a[0x4],
        a[0xC], a[0x9], a[0x6], a[0x3],
        a[0x9], a[0x6], a[0x3], a[0xC]
    };
    return (uint8x16_t)(vreinterpretq_u32_u8(dest) ^ (uint32x4_t){0, rcon, 0, rcon});
}

void expand256(uint8x16_t* keyExp, const uint8x16_t* userkey)
{
    uint8x16_t temp1, temp2, temp3;

    temp1 = keyExp[0] = vld1q_u8((uint8_t *)userkey);
    temp3 = keyExp[1] = vld1q_u8((uint8_t *)(userkey+1));

    temp2 = aeskeygenassist(temp3, 0x01);
    temp1 = keyExp[2] = assist256_1(temp1, temp2);
    temp3 = keyExp[3] = assist256_2(temp1, temp3);

    temp2 = aeskeygenassist(temp3, 0x02);
    temp1 = keyExp[4] = assist256_1(temp1, temp2);
    temp3 = keyExp[5] = assist256_2(temp1, temp3);

    temp2 = aeskeygenassist(temp3, 0x04);
    temp1 = keyExp[6] = assist256_1(temp1, temp2);
    temp3 = keyExp[7] = assist256_2(temp1, temp3);

    temp2 = aeskeygenassist(temp3, 0x08);
    temp1 = keyExp[8] = assist256_1(temp1, temp2);
    temp3 = keyExp[9] = assist256_2(temp1, temp3);

    temp2 = aeskeygenassist(temp3, 0x10);
    temp1 = keyExp[10] = assist256_1(temp1, temp2);
    temp3 = keyExp[11] = assist256_2(temp1, temp3);

    temp2 = aeskeygenassist(temp3, 0x20);
    temp1 = keyExp[12] = assist256_1(temp1, temp2);
    temp3 = keyExp[13] = assist256_2(temp1, temp3);

    keyExp[14] = assist256_1(temp1, aeskeygenassist(temp3, 0x40));
}

static int32x4_t increment_be_neon(int32x4_t x) {
    int32x4_t one = {0, 0, 0, 0x01};
    x = vreinterpretq_s32_u8(vrev32q_u8(vreinterpretq_u8_s32(x)));
    x = vaddq_s32(x, one);
    return vreinterpretq_s32_u8(vrev32q_u8(vreinterpretq_u8_s32(x)));
}

void aesctr256_direct_x4 (uint8_t *out, const uint8x16_t *rkeys, const void *counter, size_t bytes) {
    uint8x16_t s1, s2, s3, s4;
    int32x4_t ctr, *bo;
    /* bytes will always be a multiple of 16 */
    int blocks = bytes / 16;
    int blocks_parallel = 4 * (blocks / 4);
    int blocks_left = blocks - blocks_parallel;
    int i;

    ctr = vld1q_s32((int32_t *)counter);
    bo = (int32x4_t *)out;

    for (i = 0; i < blocks_parallel; i += 4) {
        s1 = vaesmcq_u8(vaeseq_u8((uint8x16_t)ctr, rkeys[0]));
        ctr = increment_be_neon(ctr);
        s2 = vaesmcq_u8(vaeseq_u8((uint8x16_t)ctr, rkeys[0]));
        ctr = increment_be_neon(ctr);
        s3 = vaesmcq_u8(vaeseq_u8((uint8x16_t)ctr, rkeys[0]));
        ctr = increment_be_neon(ctr);
        s4 = vaesmcq_u8(vaeseq_u8((uint8x16_t)ctr, rkeys[0]));
        ctr = increment_be_neon(ctr);

        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[1]));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rkeys[1]));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rkeys[1]));
        s4 = vaesmcq_u8(vaeseq_u8(s4, rkeys[1]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[2]));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rkeys[2]));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rkeys[2]));
        s4 = vaesmcq_u8(vaeseq_u8(s4, rkeys[2]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[3]));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rkeys[3]));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rkeys[3]));
        s4 = vaesmcq_u8(vaeseq_u8(s4, rkeys[3]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[4]));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rkeys[4]));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rkeys[4]));
        s4 = vaesmcq_u8(vaeseq_u8(s4, rkeys[4]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[5]));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rkeys[5]));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rkeys[5]));
        s4 = vaesmcq_u8(vaeseq_u8(s4, rkeys[5]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[6]));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rkeys[6]));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rkeys[6]));
        s4 = vaesmcq_u8(vaeseq_u8(s4, rkeys[6]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[7]));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rkeys[7]));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rkeys[7]));
        s4 = vaesmcq_u8(vaeseq_u8(s4, rkeys[7]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[8]));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rkeys[8]));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rkeys[8]));
        s4 = vaesmcq_u8(vaeseq_u8(s4, rkeys[8]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[9]));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rkeys[9]));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rkeys[9]));
        s4 = vaesmcq_u8(vaeseq_u8(s4, rkeys[9]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[10]));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rkeys[10]));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rkeys[10]));
        s4 = vaesmcq_u8(vaeseq_u8(s4, rkeys[10]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[11]));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rkeys[11]));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rkeys[11]));
        s4 = vaesmcq_u8(vaeseq_u8(s4, rkeys[11]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[12]));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rkeys[12]));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rkeys[12]));
        s4 = vaesmcq_u8(vaeseq_u8(s4, rkeys[12]));
        s1 = vaeseq_u8(s1, rkeys[13]);
        s2 = vaeseq_u8(s2, rkeys[13]);
        s3 = vaeseq_u8(s3, rkeys[13]);
        s4 = vaeseq_u8(s4, rkeys[13]);

        s1 = s1 ^ rkeys[14];
        s2 = s2 ^ rkeys[14];
        s3 = s3 ^ rkeys[14];
        s4 = s4 ^ rkeys[14];

        vst1q_s32((int32_t*)(bo + i), vreinterpretq_s32_u8(s1));
        vst1q_s32((int32_t*)(bo + i + 1), vreinterpretq_s32_u8(s2));
        vst1q_s32((int32_t*)(bo + i + 2), vreinterpretq_s32_u8(s3));
        vst1q_s32((int32_t*)(bo + i + 3), vreinterpretq_s32_u8(s4));

    }

    for (i = 0; i < blocks_left; i++) {
        s1 = vaesmcq_u8(vaeseq_u8((uint8x16_t)ctr, rkeys[0]));
        ctr = increment_be_neon(ctr);
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[1]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[2]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[3]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[4]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[5]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[6]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[7]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[8]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[9]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[10]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[11]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rkeys[12]));
        s1 = vaeseq_u8(s1, rkeys[13]);

        s1 = s1 ^ rkeys[14];

        vst1q_s32((int32_t*)(bo + blocks_parallel + i), vreinterpretq_s32_u8(s1));

    }
}

void aesctr256_zeroiv (uint8_t *out, const uint8_t *sk, int bytes) {
    uint8_t counter[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    aesctr256(out, sk, counter, bytes);
}

void aesctr256 (uint8_t *out, const uint8_t *k, const void *counter, int bytes) {
    uint8x16_t rkeys[15];
    expand256 (rkeys, (uint8x16_t *)k);
    aesctr256_direct_x4 (out, rkeys, counter, bytes);
}

#ifdef TRY_COMPILE
int main() {
    return 0;
}
#endif
