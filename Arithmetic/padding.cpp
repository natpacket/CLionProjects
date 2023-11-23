//
// Created by natpacket on 2023/11/23.
//

#include "padding.h"

#include <string>
#include <vector>

// AES 128-bit block size
const int BLOCK_SIZE = 16;

// PKCS7 padding function
std::vector<unsigned char> PKCS7Padding(const std::vector<unsigned char>& input) {
    int paddingSize = BLOCK_SIZE - (input.size() % BLOCK_SIZE);
    std::vector<unsigned char> paddedInput(input);
    for (int i = 0; i < paddingSize; i++) {
        paddedInput.push_back(paddingSize);
    }
    return paddedInput;
}

// PKCS7 unpadding function
std::vector<unsigned char> PKCS7Unpadding(const std::vector<unsigned char>& input) {
    int paddingSize = input.back();
    std::vector<unsigned char> unpaddedInput(input.begin(), input.end() - paddingSize);
    return unpaddedInput;
}