// Copyright (c) 2014-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sha1.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define SHA1_BLOCK_SIZE 20  // SHA-1摘要的长度为20字节

// 初始SHA-1上下文
void Sha1_Init(uint32_t state[5]) {
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    state[4] = 0xC3D2E1F0;
}

// SHA-1循环函数
uint32_t Sha1_RotateLeft(uint32_t value, uint32_t shift) {
    return (value << shift) | (value >> (32 - shift));
}

// SHA-1压缩函数
void Sha1_Compress(uint32_t state[5], const uint8_t block[64]) {
    uint32_t a, b, c, d, e, f, k, temp;
    uint32_t w[80];
    int t;

    // 将block划分为16个32位字
    for (t = 0; t < 16; t++) {
        w[t] = block[t * 4 + 0] << 24 |
               block[t * 4 + 1] << 16 |
               block[t * 4 + 2] << 8 |
               block[t * 4 + 3];
    }

    // 将block扩展为80个32位字
    for (t = 16; t < 80; t++) {
        w[t] = Sha1_RotateLeft(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
    }

    // 初始化中间变量
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    // 进行80轮迭代
    for (t = 0; t < 80; t++) {
        if (t >= 0 && t <= 19) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (t >= 20 && t <= 39) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (t >= 40 && t <= 59) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        temp = Sha1_RotateLeft(a, 5) + f + e + k + w[t];
        e = d;
        d = c;
        c = Sha1_RotateLeft(b, 30);
        b = a;
        a = temp;
    }

    // 更新SHA-1上下文
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

// 更新SHA-1上下文
void Sha1_Update(uint32_t state[5], const uint8_t* data, uint32_t length) {
    uint32_t i, j;

    // 对数据块进行处理
    for (i = 0; i < length / 64; i++) {
        uint8_t block[64];
        for (j = 0; j < 64; j++) {
            block[j] = data[i * 64 + j];
        }
        Sha1_Compress(state, block);
    }

    // 处理最后一块数据
    uint8_t block[64] = {0};
    for (j = 0; j < length % 64; j++) {
        block[j] = data[i * 64 + j];
    }
    block[length % 64] = 0x80;

    // 如果数据长度不足448位，则需要填充0
    if (length % 64 < 56) {
        uint64_t bit_length = length * 8;
        for (j = 0; j < 8; j++) {
            block[56 + j] = (bit_length >> (56 - j * 8)) & 0xFF;
        }
        Sha1_Compress(state, block);
    }
        // 否则，需要增加一块处理
    else {
        Sha1_Compress(state, block);
        memset(block, 0, sizeof(block));
        uint64_t bit_length = length * 8;
        for (j = 0; j < 8; j++) {
            block[j] = (bit_length >> (56 - j * 8)) & 0xFF;
        }
        Sha1_Compress(state, block);
    }
}

// 完成SHA-1算法并输出摘要结果
void Sha1_Final(uint32_t state[5], uint8_t digest[SHA1_BLOCK_SIZE]) {
    int i;
    for (i = 0; i < SHA1_BLOCK_SIZE/4; i++) {
        digest[i*4 + 0] = (state[i] >> 24) & 0xFF;
        digest[i*4 + 1] = (state[i] >> 16) & 0xFF;
        digest[i*4 + 2] = (state[i] >> 8) & 0xFF;
        digest[i*4 + 3] = state[i] & 0xFF;
    }
}

void testsha1() {
    // 测试示例
    uint8_t message[] = "123456";
    uint8_t digest[SHA1_BLOCK_SIZE];
    uint32_t state[5];

    Sha1_Init(state);
//    Sha1_Update(state, message, sizeof(message)-1); // 不算结尾的'\0'
    Sha1_Update(state, message, strlen(reinterpret_cast<const char *>(message))); // 不算结尾的'\0'
    Sha1_Final(state, digest);

    printf("123456 SHA-1 Digest: ");
    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

}
