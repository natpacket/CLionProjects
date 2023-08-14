// Copyright (c) 2014-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sha1.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// SHA1算法常量
#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20
#define SHA1_ROUNDS 80

// SHA1算法上下文结构体
typedef struct {
    uint32_t state[5]; // hash状态
    uint64_t count;    // 输入的数据位数
    uint8_t buffer[SHA1_BLOCK_SIZE]; // 输入数据缓冲区
} SHA1_CTX;

// 声明内部函数
static void sha1_transform(SHA1_CTX *ctx, const uint8_t data[]);
static void sha1_update(SHA1_CTX *ctx, const uint8_t data[], uint32_t len);
static void sha1_init(SHA1_CTX *ctx);

// 循环左移操作
static inline uint32_t SHA1_ROTL(uint32_t value, uint32_t shift) {
    return (value << shift) | (value >> (32 - shift));
}

// SHA1算法初始化
void sha1_init(SHA1_CTX *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

// SHA1算法更新
void sha1_update(SHA1_CTX *ctx, const uint8_t data[], uint32_t len) {
    uint32_t i;

    for (i = 0; i < len; i++) {
        ctx->buffer[(ctx->count >> 3) & 63] = data[i]; // 将数据存入缓冲区
        ctx->count += 8; // 记录输入的位数

        if ((ctx->count & 0x3F) == 0) { // 如果缓冲区满了
            sha1_transform(ctx, ctx->buffer); // 对缓冲区数据进行处理
        }
    }
}

// SHA1算法最后的处理
void sha1_final(SHA1_CTX *ctx, uint8_t digest[]) {
    uint32_t i;
    uint8_t finalcount[8];

    for (i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((ctx->count >> ((7 - i) * 8)) & 255); // 计算输入数据的位数
    }

    sha1_update(ctx, (uint8_t *)"\200", 1); // 补位，将第一个bit设为1，后面补0

    while ((ctx->count & 0x3F) != 56) { // 直到缓冲区满足补位要求
        sha1_update(ctx, (uint8_t *)"\0", 1); // 补0
    }

    sha1_update(ctx, finalcount, 8); // 将输入位数追加到缓冲区

    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        digest[i] = (uint8_t)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255); // 从状态中生成最终散列值
    }
}

// SHA1算法核心转换函数
void sha1_transform(SHA1_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, i, j, t, m[SHA1_ROUNDS];

    // 将输入分组存储到数组m中
    for (i = 0, j = 0; i < 16; i++, j += 4) {
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    }

    for (; i < SHA1_ROUNDS; i++) {
        m[i] = SHA1_ROTL(m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16], 1); // 生成轮密钥
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (i = 0; i < SHA1_ROUNDS; i++) {
        if (i < 20) {
            t = SHA1_ROTL(a, 5) + ((b & c) | (~b & d)) + e + m[i] + 0x5A827999;
        } else if (i < 40) {
            t = SHA1_ROTL(a, 5) + (b ^ c ^ d) + e + m[i] + 0x6ED9EBA1;
        } else if (i < 60) {
            t = SHA1_ROTL(a, 5) + ((b & c) | (b & d) | (c & d)) + e + m[i] + 0x8F1BBCDC;
        } else {
            t = SHA1_ROTL(a, 5) + (b ^ c ^ d) + e + m[i] + 0xCA62C1D6;
        }

        e = d;
        d = c;
        c = SHA1_ROTL(b, 30);
        b = a;
        a = t;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}
void testsha1() {
    uint8_t input[] = "123456";
    uint8_t digest[SHA1_DIGEST_SIZE];

    SHA1_CTX ctx;
    sha1_init(&ctx); // 初始化SHA1上下文
    sha1_update(&ctx, input, strlen(reinterpret_cast<const char *>(input))); // 更新输入数据
    sha1_final(&ctx, digest); // 计算SHA1散列值

    printf("SHA1 Digest: ");
    for (int i = 0; i < SHA1_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]); // 将散列值输出
    }
    printf("\n");

}
