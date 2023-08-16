//
// Created by natpacket on 2023/8/16.
//

#include "crc32.h"
#include <stdio.h>
#include <stdint.h>
#include <cstring>

#define CRC32_POLYNOMIAL    0xEDB88320

// 生成CRC32校验表
void generate_crc32_table(uint32_t* crc32_table) {
    for (int i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ ((crc & 1) ? CRC32_POLYNOMIAL : 0);
        }
        crc32_table[i] = crc;
    }
}

// 计算给定数据的CRC32校验值
uint32_t calculate_crc32(const uint8_t* data, size_t size, const uint32_t* crc32_table) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < size; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

void testcrc32() {
    // 生成CRC32校验表
    uint32_t crc32_table[256];
    generate_crc32_table(crc32_table);

    // 测试数据
    uint8_t data[] = "123456";
    size_t size = strlen(reinterpret_cast<const char *>(data));

    // 计算CRC32校验值
    uint32_t crc32 = calculate_crc32(data, size, crc32_table);

    printf("%s CRC32: %08X\n",data, crc32);
}
