//
// Created by natpacket on 2023/8/11.
//

#ifndef ARITHMETIC_MD5_H
#define ARITHMETIC_MD5_H

#define MD5_BLOCK_SIZE 64
#define MD5_DIGEST_SIZE 16

typedef unsigned char uint8; // 8位无符号整数类型
typedef unsigned int uint32; // 32位无符号整数类型

/* MD5算法上下文结构 */
typedef struct {
    uint32 state[4];   // 维护MD5算法的运算状态
    uint32 count[2];   // 记录消息的位数
    uint8 buffer[MD5_BLOCK_SIZE];  // 缓存消息块
} MD5_CTX;

void MD5_Init(MD5_CTX *context);
void MD5_Update(MD5_CTX *context, const uint8 *input, uint32 inputlen);
void MD5_Final(MD5_CTX *context, uint8 digest[16]);
void MD5(const uint8 *input, uint32 inputlen, uint8 output[MD5_DIGEST_SIZE]);
void testmd5();
#endif //ARITHMETIC_MD5_H
