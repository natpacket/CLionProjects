// Copyright (c) 2014-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sha1.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define SHA1_BLOCK_SIZE 20
#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE 64

typedef unsigned char uint8; // 8位无符号整数类型

// 定义SHA-1上下文结构体
typedef struct {
    uint32_t state[5];           // 存储中间结果
    uint32_t count[2];           // 存储输入比特数
    unsigned char buffer[SHA1_BLOCK_SIZE];    // 输入缓冲区
} SHA1_CTX;
/* 常量表 */
static const uint8 PADDING[SHA1_BLOCK_SIZE] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
// 初始化SHA-1上下文
void Sha1_Init(SHA1_CTX *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;

    ctx->count[0] = ctx->count[1] = 0;
}

// 执行SHA-1转换
void Sha1_Transform(SHA1_CTX *ctx, const unsigned char *data) {
    uint32_t a, b, c, d, e, temp;
    uint32_t w[80];
    // 将block划分为16个32位字
    for (int i = 0; i < 16; i++) {
        w[i] = data[i * 4 + 0] << 24 |
                data[i * 4 + 1] << 16 |
                data[i * 4 + 2] << 8 |
                data[i * 4 + 3];
    }
    // 扩展消息块
    for (int i = 16; i < 80; i++) {
        w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]);
        w[i] = (w[i] << 1) | (w[i] >> 31);
    }

    // 初始化哈希值
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    // 主循环
    for (int i = 0; i < 80; i++) {
        if (i < 20) {
            temp = ((b & c) | ((~b) & d)) + 0x5A827999;
        } else if (i < 40) {
            temp = (b ^ c ^ d) + 0x6ED9EBA1;
        } else if (i < 60) {
            temp = ((b & c) | (b & d) | (c & d)) + 0x8F1BBCDC;
        } else {
            temp = (b ^ c ^ d) + 0xCA62C1D6;
        }

        temp += ((a << 5) | (a >> 27)) + e + w[i];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;
    }

    // 计算下一个消息块
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

// 更新SHA-1上下文
void Sha1_Update(SHA1_CTX *ctx, const unsigned char *data, uint32_t len) {
    uint32_t i, index, partlen;

    index = (ctx->count[0] >> 3) & 0x3F;
    ctx->count[0] += len << 3;

    if (ctx->count[0] < (len << 3)) {
        ctx->count[1]++;
    }

    ctx->count[1] += (len >> 29);
    // 计算处理后的数据长度
    partlen = SHA1_BLOCK_SIZE - index;
    if (len >= partlen) {
        memcpy(&(ctx->buffer[index]), data, partlen);
        Sha1_Transform(ctx, ctx->buffer);

        for (i = partlen; i+SHA1_BLOCK_SIZE <= len; i += SHA1_BLOCK_SIZE) {
            Sha1_Transform(ctx, &(data[i]));
        }

        index = 0;
    } else {
        i = 0;
    }

    memcpy(&(ctx->buffer[index]), &(data[i]), len - i);
}

// 结束SHA-1计算，返回摘要结果
void Sha1_Final(unsigned char digest[SHA1_DIGEST_SIZE], SHA1_CTX *ctx) {
    uint32_t i,index, padlen;
    uint8_t  bits[8];

//    memcpy(bits, ctx->count, 8);
    // 数据长度填充方式和md5有区别，为大端方式填充
    for (i = 0; i < 8; i++)
    {
        bits[i] = (unsigned char)((ctx->count[(i >= 4 ? 0 : 1)]
                >> ((3 - (i & 3)) * 8)) & 255); /*   Endian   independent   */
    }
    index = (ctx->count[0] >> 3) & 0x3F;
    //计算需要填充的长度
    padlen = (index < 56) ? (56 - index) : (120 - index);
    // 数据填充
    Sha1_Update(ctx, PADDING, padlen);
    // 填充长度
    Sha1_Update(ctx, bits, 8);
    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        digest[i] = (unsigned char)((ctx->state[i>>2] >> ((3-(i & 3)) * 8)) & 0xFF);
    }

    // 清空敏感信息
    memset(ctx, 0, sizeof(*ctx));
}
void testsha1() {
    unsigned char digest[SHA1_DIGEST_SIZE];
    SHA1_CTX ctx;

    // 测试用例1
    const char *str1 = "123456";
    Sha1_Init(&ctx);
//    Sha1_Update1(&ctx, (const unsigned char *)str1, strlen(str1));
//    Sha1_Final1(&ctx ,digest);
    Sha1_Update(&ctx, (const unsigned char *)str1, strlen(str1));
    Sha1_Final(digest,&ctx);
    printf("SHA-1 hash for '%s': ", str1);

    for (int i = 0; i < SHA1_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}
