#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

using namespace std;

#define rounds 4

void sbox(uint16_t sBoxes[16], uint16_t state[4])
{
    state[0] =
          (sBoxes[(state[0] >> 0)  & (uint16_t)0x000f] << 0)
        ^ (sBoxes[(state[0] >> 4)  & (uint16_t)0x000f] << 4)
        ^ (sBoxes[(state[0] >> 8)  & (uint16_t)0x000f] << 8)
        ^ (sBoxes[(state[0] >> 12) & (uint16_t)0x000f] << 12);

    state[1] =
          (sBoxes[(state[1] >> 0)  & (uint16_t)0x000f] << 0)
        ^ (sBoxes[(state[1] >> 4)  & (uint16_t)0x000f] << 4)
        ^ (sBoxes[(state[1] >> 8)  & (uint16_t)0x000f] << 8)
        ^ (sBoxes[(state[1] >> 12) & (uint16_t)0x000f] << 12);

    state[2] =
          (sBoxes[(state[2] >> 0)  & (uint16_t)0xf] << 0)
        ^ (sBoxes[(state[2] >> 4)  & (uint16_t)0xf] << 4)
        ^ (sBoxes[(state[2] >> 8)  & (uint16_t)0xf] << 8)
        ^ (sBoxes[(state[2] >> 12) & (uint16_t)0xf] << 12);

    state[3] =
          (sBoxes[(state[3] >> 0)  & (uint16_t)0xf] << 0)
        ^ (sBoxes[(state[3] >> 4)  & (uint16_t)0xf] << 4)
        ^ (sBoxes[(state[3] >> 8)  & (uint16_t)0xf] << 8)
        ^ (sBoxes[(state[3] >> 12) & (uint16_t)0xf] << 12);
}

void permute(uint16_t state[4])
{
    uint16_t out[4] = { 0 };

    out[0] ^= state[0] & 0x1111;
    out[1] ^= state[0] & 0x2222;
    out[2] ^= state[0] & 0x4444;
    out[3] ^= state[0] & 0x8888;

    out[1] ^= state[1] & 0x1111;
    out[2] ^= state[1] & 0x2222;
    out[3] ^= state[1] & 0x4444;
    out[0] ^= state[1] & 0x8888;

    out[2] ^= state[2] & 0x1111;
    out[3] ^= state[2] & 0x2222;
    out[0] ^= state[2] & 0x4444;
    out[1] ^= state[2] & 0x8888;

    out[3] ^= state[3] & 0x1111;
    out[0] ^= state[3] & 0x2222;
    out[1] ^= state[3] & 0x4444;
    out[2] ^= state[3] & 0x8888;

    state[0] = out[0]; state[1] = out[1]; state[2] = out[2]; state[3] = out[3];
}

void permuteInverse(uint16_t out[4])
{
    // inverse
    uint16_t originalValue[4] = { 0 };

    originalValue[0] ^= out[0] & 0x1111;
    originalValue[0] ^= out[1] & 0x2222;
    originalValue[0] ^= out[2] & 0x4444;
    originalValue[0] ^= out[3] & 0x8888;

    originalValue[1] ^= out[1] & 0x1111;
    originalValue[1] ^= out[2] & 0x2222;
    originalValue[1] ^= out[3] & 0x4444;
    originalValue[1] ^= out[0] & 0x8888;

    originalValue[2] ^= out[2] & 0x1111;
    originalValue[2] ^= out[3] & 0x2222;
    originalValue[2] ^= out[0] & 0x4444;
    originalValue[2] ^= out[1] & 0x8888;

    originalValue[3] ^= out[3] & 0x1111;
    originalValue[3] ^= out[0] & 0x2222;
    originalValue[3] ^= out[1] & 0x4444;
    originalValue[3] ^= out[2] & 0x8888;

    out[0] = originalValue[0]; out[1] = originalValue[1]; out[2] = originalValue[2]; out[3] = originalValue[3];
}

int encrypt(uint8_t data[], uint8_t key[], uint16_t sBox[16])
{
    uint16_t state[4], rk[4];

    memcpy(state, data, sizeof(state));
    memcpy(rk,    key,  sizeof(rk));

    for (int round = 0; round < rounds; round++)
    {
        // key addition
        for (int i = 0; i < 4; i++)
            state[i] ^= rk[i];
        
        sbox(sBox, state);
        permute(state);
    }

    memcpy(data, state, sizeof(state));
    return 1;
}

int decrypt(uint8_t data[8], uint8_t key[8], uint16_t sBoxInverse[16])
{
    uint16_t state[4], rk[4];

    memcpy(state, data, sizeof(state));
    memcpy(rk, key, sizeof(rk));

    for (int round = 0; round < rounds; round++)
    {
        permuteInverse(state);
        sbox(sBoxInverse, state);

        // key addition
        for (int i = 0; i < 4; i++)
            state[i] ^= rk[i];
    }

    memcpy(data, state, sizeof(state));

    return 1;
}

int test_encryption_internal(uint8_t key[], uint16_t sBox[]) {
    bool saveResults = false;

    int block_size = 16;
    int64_t sequences = static_cast<int64_t>(1) << 32;

    clock_t begin = clock();
    for (uint64_t i = 0; i < sequences; i++) {
        for (uint64_t j = 0; j < sequences; j++) {
            double time_spent = (double)(clock() - begin) / CLOCKS_PER_SEC;
            if (time_spent > 3)
                return int(i) * sequences + int(j);
            uint8_t data[16];
            for (int x = 0; x < 8; x++) data[x] = (uint8_t)(i >> (8 * (8 - x - 1)));
            for (int x = 0; x < 8; x++) data[x + 8] = (uint8_t)(j >> (8 * (8 - x - 1)));
            encrypt(data, key, sBox);
        }
    }
    return 0;
}

void test_encryption(uint8_t key[], uint16_t sBox[]) {
    int n = test_encryption_internal(key, sBox);

    FILE* fp = fopen("speed_test_encryption_result_16_size_block_optimized_4_rounds.txt", "w");
    if (fp == NULL) {
        perror("Unable to open file!");
        exit(1);
    }

    fprintf(fp, "Doing own SPN encryption on 16 size blocks: %d in 3s.\n", n);
    fprintf(fp, "Doing AES-128-ECB for 3s on 16 size blocks: 152315266 AES-128-ECB's in 3.00s\n");
    fclose(fp);
}

int test_bruteforce_decryption_internal(uint16_t sBoxInverse[]) {
    // 128 bitovy zasifrovany text
    uint8_t ciphertext[] = { 0x8d, 0x15, 0x28, 0x30, 0xa8, 0x79, 0x8c, 0xd6, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35 };

    int64_t sequences = static_cast<int64_t>(1) << 32;

    clock_t begin = clock();
    for (uint64_t i = 0; i < sequences; i++) {
        for (uint64_t j = 0; j < sequences; j++) {
            double time_spent = (double)(clock() - begin) / CLOCKS_PER_SEC;
            if (time_spent > 3)
                return int(i) * sequences + int(j);
            uint8_t key[16];
            for (int x = 0; x < 8; x++) key[x] = (uint8_t)(i >> (8 * (8 - x - 1)));
            for (int x = 0; x < 8; x++) key[x + 8] = (uint8_t)(j >> (8 * (8 - x - 1)));
            decrypt(ciphertext, key, sBoxInverse);
        }
    }
}

void test_bruteforce_decryption(uint16_t sBoxInverse[]) {
    int n = test_bruteforce_decryption_internal(sBoxInverse);

    FILE* fp = fopen("speed_test_decryption_result_16_size_block_optimized.txt", "w");
    if (fp == NULL) {
        perror("Unable to open file!");
        exit(1);
    }

    fprintf(fp, "Doing own SPN decryption on 16 size blocks: %d in 3s.\n", n);
    fprintf(fp, "Doing AES-128-ECB for 3s on 16 size blocks: 152315266 AES-128-ECB's in 3.00s\n");
    fclose(fp);
}

int main() {
    //                             0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   A,   B,   C,   D,   E,   F
    uint16_t sBox[16]        = { 0x5, 0xA, 0x0, 0x9, 0x3, 0x6, 0x1, 0xB, 0x8, 0xC, 0xD, 0x2, 0x4, 0xF, 0x7, 0xE };
    uint16_t sBoxInverse[16] = { 0x2, 0x6, 0xB, 0x4, 0xC, 0x0, 0x5, 0xE, 0x8, 0x3, 0x1, 0x7, 0x9, 0xA, 0xF, 0xD };
    uint8_t key[] = { 's', 'l', 'o', 'v' };

    test_encryption(key, sBox);
    
    /*
    uint8_t data[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5' };
    encrypt(data, key, sBox);
    for (int i = 0; i < sizeof(data); i++) printf("%02x", data[i]);
    */

    //test_bruteforce_decryption(sBoxInverse);

    return 0;
}