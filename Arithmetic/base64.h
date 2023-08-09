//
// Created by 王世林 on 2023/8/9.
//

#ifndef TEST_BASE64_H
#define TEST_BASE64_H

#endif //TEST_BASE64_H


char* base64Encode(const unsigned char* data, int dataSize);
unsigned char* base64Decode(const char* encodedData, int* dataSize);
void testBase64();