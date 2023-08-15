//
// Created by 王世林 on 2023/8/9.
//
#include "base64.h"

#include <stdio.h>
#include <stdlib.h>
#include <cstring>

// Base64字符表
const char base64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// 将数据按照Base64规则编码
char* base64Encode(const unsigned char* data, int dataSize) {
    int i, j;
    int encSize = dataSize * 4 / 3 + 3;
    char* encodedData = (char*)malloc(encSize);

    for (i = 0, j = 0; i < dataSize; i += 3, j += 4) {
        unsigned char byte1 = data[i];
        unsigned char byte2 = (i + 1 < dataSize) ? data[i + 1] : 0;
        unsigned char byte3 = (i + 2 < dataSize) ? data[i + 2] : 0;

        encodedData[j] = base64Table[byte1 >> 2];
        encodedData[j + 1] = base64Table[((byte1 & 0x03) << 4) | (byte2 >> 4)];
        encodedData[j + 2] = (i + 1 < dataSize) ? base64Table[((byte2 & 0x0F) << 2) | (byte3 >> 6)] : '=';
        encodedData[j + 3] = (i + 2 < dataSize) ? base64Table[byte3 & 0x3F] : '=';
    }

    encodedData[j] = '\0';

    return encodedData;
}

// 将Base64编码的数据解码
unsigned char* base64Decode(const char* encodedData, int* dataSize) {
    int i, j;
    int encSize = strlen(encodedData);
    int paddingCount = (encodedData[encSize - 1] == '=') + (encodedData[encSize - 2] == '=');
    int decSize = encSize * 3 / 4 - paddingCount;
    unsigned char* decodedData = (unsigned char*)malloc(decSize);

    for (i = 0, j = 0; i < encSize; i += 4, j += 3) {
        unsigned char byte1 = strchr(base64Table, encodedData[i]) - base64Table;
        unsigned char byte2 = strchr(base64Table, encodedData[i + 1]) - base64Table;
        unsigned char byte3 = (encodedData[i + 2] == '=') ? 0 : strchr(base64Table, encodedData[i + 2]) - base64Table;
        unsigned char byte4 = (encodedData[i + 3] == '=') ? 0 : strchr(base64Table, encodedData[i + 3]) - base64Table;

        decodedData[j] = (byte1 << 2) | (byte2 >> 4);
        decodedData[j + 1] = (byte2 << 4) | (byte3 >> 2);
        decodedData[j + 2] = (byte3 << 6) | (byte4);
    }

    *dataSize = decSize;

    return decodedData;
}

void testBase64() {
    const char *input = "Hello, Base64!";
    const unsigned char plainData[] = "Hello World!";
    int plainDataSize = strlen(input);

    // 加密
    char* encryptedData = base64Encode(reinterpret_cast<const unsigned char *>(input), plainDataSize);
    printf("Base64 Encrypted: %s\n", encryptedData);

    // 解密
    int decryptedDataSize;
    unsigned char* decryptedData = base64Decode(encryptedData, &decryptedDataSize);
    printf("Base64 Decrypted: ");
    for (int i = 0; i < decryptedDataSize; i++) {
        printf("%c", decryptedData[i]);
    }
    printf("\n");

    free(encryptedData);
    free(decryptedData);
}