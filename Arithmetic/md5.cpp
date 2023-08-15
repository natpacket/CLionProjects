//
// Created by natpacket on 2023/8/11.
//

#include "md5.h"
/*
 * MD5是一种常见的哈希算法，用于计算消息的摘要值。
 * 它将输入消息通过一系列的步骤转化为一个128位（16字节）的哈希值。
 * 以下代码实现了MD5的初始化、更新和最终化的函数。
 */

#include <stdio.h>
#include <string.h>

// 算法来源 https://www.cs.cmu.edu/afs/club/usr/jhutz/project/sss/util/md5c.c


/* 常量表 */
static const uint8 PADDING[MD5_BLOCK_SIZE] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint32 T[MD5_BLOCK_SIZE] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/* 左移位数 */
#define SHIFT(a, b) ((a << b) | (a >> (32 - b)))

/* FF, GG, HH, II函数 */
#define FF(a, b, c, d, x, s, ac) { \
    (a) += F((b), (c), (d)) + (x) + (uint32)(ac); \
    (a) = SHIFT((a), (s)); \
    (a) += (b); \
}

#define GG(a, b, c, d, x, s, ac) { \
    (a) += G((b), (c), (d)) + (x) + (uint32)(ac); \
    (a) = SHIFT((a), (s)); \
    (a) += (b); \
}

#define HH(a, b, c, d, x, s, ac) { \
    (a) += H((b), (c), (d)) + (x) + (uint32)(ac); \
    (a) = SHIFT((a), (s)); \
    (a) += (b); \
}

#define II(a, b, c, d, x, s, ac) { \
    (a) += I((b), (c), (d)) + (x) + (uint32)(ac); \
    (a) = SHIFT((a), (s)); \
    (a) += (b); \
}

/* F, G, H, I函数 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))
/* 编码函数  高地址往低地址复制数据*/
void Encode(uint8 *output, const uint32 *input, uint32 len) {
    uint32 i, j;
    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (uint8)(input[i] & 0xff);
        output[j + 1] = (uint8)((input[i] >> 8) & 0xff);
        output[j + 2] = (uint8)((input[i] >> 16) & 0xff);
        output[j + 3] = (uint8)((input[i] >> 24) & 0xff);
    }
}

/* 解码函数  高地址往低地址复制数据*/
void Decode(uint32 *output, const uint8 *input, uint32 len) {
    uint32 i, j;
    for (i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((uint32)input[j]) | (((uint32)input[j + 1]) << 8) |
                    (((uint32)input[j + 2]) << 16) | (((uint32)input[j + 3]) << 24);
}

/* 初始化MD5算法上下文 */
void MD5_Init(MD5_CTX *context) {
    context->count[0] = context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}
/* 转换函数 */
void MD5_Transform(uint32 state[4], const uint8 block[MD5_BLOCK_SIZE]) {
    uint32 a = state[0];
    uint32 b = state[1];
    uint32 c = state[2];
    uint32 d = state[3];
    uint32 x[16];
//    Decode(x, block, MD5_BLOCK_SIZE);
    memcpy(x, block, MD5_BLOCK_SIZE);
    FF(a, b, c, d, x[0], 7, T[0]);
    FF(d, a, b, c, x[1], 12, T[1]);
    FF(c, d, a, b, x[2], 17, T[2]);
    FF(b, c, d, a, x[3], 22, T[3]);
    FF(a, b, c, d, x[4], 7, T[4]);
    FF(d, a, b, c, x[5], 12, T[5]);
    FF(c, d, a, b, x[6], 17, T[6]);
    FF(b, c, d, a, x[7], 22, T[7]);
    FF(a, b, c, d, x[8], 7, T[8]);
    FF(d, a, b, c, x[9], 12, T[9]);
    FF(c, d, a, b, x[10], 17, T[10]);
    FF(b, c, d, a, x[11], 22, T[11]);
    FF(a, b, c, d, x[12], 7, T[12]);
    FF(d, a, b, c, x[13], 12, T[13]);
    FF(c, d, a, b, x[14], 17, T[14]);
    FF(b, c, d, a, x[15], 22, T[15]);

    GG(a, b, c, d, x[1], 5, T[16]);
    GG(d, a, b, c, x[6], 9, T[17]);
    GG(c, d, a, b, x[11], 14, T[18]);
    GG(b, c, d, a, x[0], 20, T[19]);
    GG(a, b, c, d, x[5], 5, T[20]);
    GG(d, a, b, c, x[10], 9, T[21]);
    GG(c, d, a, b, x[15], 14, T[22]);
    GG(b, c, d, a, x[4], 20, T[23]);
    GG(a, b, c, d, x[9], 5, T[24]);
    GG(d, a, b, c, x[14], 9, T[25]);
    GG(c, d, a, b, x[3], 14, T[26]);
    GG(b, c, d, a, x[8], 20, T[27]);
    GG(a, b, c, d, x[13], 5, T[28]);
    GG(d, a, b, c, x[2], 9, T[29]);
    GG(c, d, a, b, x[7], 14, T[30]);
    GG(b, c, d, a, x[12], 20, T[31]);

    HH(a, b, c, d, x[5], 4, T[32]);
    HH(d, a, b, c, x[8], 11, T[33]);
    HH(c, d, a, b, x[11], 16, T[34]);
    HH(b, c, d, a, x[14], 23, T[35]);
    HH(a, b, c, d, x[1], 4, T[36]);
    HH(d, a, b, c, x[4], 11, T[37]);
    HH(c, d, a, b, x[7], 16, T[38]);
    HH(b, c, d, a, x[10], 23, T[39]);
    HH(a, b, c, d, x[13], 4, T[40]);
    HH(d, a, b, c, x[0], 11, T[41]);
    HH(c, d, a, b, x[3], 16, T[42]);
    HH(b, c, d, a, x[6], 23, T[43]);
    HH(a, b, c, d, x[9], 4, T[44]);
    HH(d, a, b, c, x[12], 11, T[45]);
    HH(c, d, a, b, x[15], 16, T[46]);
    HH(b, c, d, a, x[2], 23, T[47]);

    II(a, b, c, d, x[0], 6, T[48]);
    II(d, a, b, c, x[7], 10, T[49]);
    II(c, d, a, b, x[14], 15, T[50]);
    II(b, c, d, a, x[5], 21, T[51]);
    II(a, b, c, d, x[12], 6, T[52]);
    II(d, a, b, c, x[3], 10, T[53]);
    II(c, d, a, b, x[10], 15, T[54]);
    II(b, c, d, a, x[1], 21, T[55]);
    II(a, b, c, d, x[8], 6, T[56]);
    II(d, a, b, c, x[15], 10, T[57]);
    II(c, d, a, b, x[6], 15, T[58]);
    II(b, c, d, a, x[13], 21, T[59]);
    II(a, b, c, d, x[4], 6, T[60]);
    II(d, a, b, c, x[11], 10, T[61]);
    II(c, d, a, b, x[2], 15, T[62]);
    II(b, c, d, a, x[9], 21, T[63]);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

/* 更新MD5算法上下文 */
void MD5_Update(MD5_CTX *context, const uint8 *input, uint32 inputlen) {
    uint32 i, index, partlen;
    // 计算缓冲区中剩余空间
    // context->count[0] >> 3 (bit位数 变 byte字节数)
    // 0x3f == 63
    // count & 63 == count % 63 (求余)
    // 当前记录的位数进行求余 表示缓冲区待处理的数据长度
    index = (context->count[0] >> 3) & 0x3F;
    // 更新位计数器
    // 如果位计数器溢出，则更新高位计数器
    // 比如 下面的情况
    //    unsigned  int a= 0xffffffff;
    //    printf("%x \n",a+3);  打印为: 2
    if ((context->count[0] += (inputlen << 3)) < (inputlen << 3))
        context->count[1]++;
    context->count[1] += (inputlen >> 29);
    // 计算处理后的数据长度
    partlen = MD5_BLOCK_SIZE - index;

    // 处理第一部分数据
    if (inputlen >= partlen) {
        memcpy(&context->buffer[index], input, partlen);
        MD5_Transform(context->state, context->buffer);
        // 处理剩余的数据块
        for (i = partlen; i + MD5_BLOCK_SIZE <= inputlen; i += MD5_BLOCK_SIZE)
            MD5_Transform(context->state, &input[i]);
        index = 0;
    } else {
        i = 0;
    }
    // 缓冲区中留下的数据
    memcpy(&context->buffer[index], &input[i], inputlen - i);
}

/* 结束MD5算法，生成摘要结果 */
void MD5_Final(MD5_CTX *context, uint8 digest[16]) {
    uint8 bits[8];
    uint32 index, padlen;
//    Encode(bits, context->count, 8);

    memcpy(bits, context->count, 8);
    index = (context->count[0] >> 3) & 0x3F;
    //计算需要填充的长度
    padlen = (index < 56) ? (56 - index) : (120 - index);
    // 数据填充
    MD5_Update(context, PADDING, padlen);
    // 填充长度
    MD5_Update(context, bits, 8);
//    Encode(digest, context->state, MD5_DIGEST_SIZE);
    memcpy(digest, context->state, MD5_DIGEST_SIZE);
    memset(context, 0, sizeof(*context));
}



/* 计算字符串的MD5摘要 */
void MD5(const uint8 *input, uint32 inputlen, uint8 output[MD5_DIGEST_SIZE]) {
    MD5_CTX context;
    MD5_Init(&context);
    MD5_Update(&context, input, inputlen);
    MD5_Final(&context, output);
}

/* 测试代码 */
void testmd5() {
    uint8 input[] = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
    uint8 output[MD5_DIGEST_SIZE];
    MD5(input, strlen((char *)input), output);
    printf("%s MD5: ",input);
    for (uint32 i = 0; i < MD5_DIGEST_SIZE; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");
//    unsigned  int a= 0xffffffff;
//    printf("%x \n",a+3);
//    int b=3;
//    if( (a += 3) < b)
//        printf(" < \n");

//    int a =0x67452301;
//    int c = 0;
//    uint8  b[4] ={0};
//    memcpy(b, &a, 4);
//    for (uint32 i = 0; i < 4; i++) {
//        printf("%02x", b[i]);
//    }
//    printf("\n");
//    Encode(b, reinterpret_cast<const uint32 *>(&a), 4);
//    for (uint32 i = 0; i < 4; i++) {
//        printf("%02x", b[i]);
//    }
//    printf("\n");
//    Decode(reinterpret_cast<uint32 *>(&c), b, 4);
//    printf("%x",c);
//    printf("\n");
//    memcpy(&c, b, 4);
//    printf("%x",c);
//    printf("\n");
}


