//
// Created by natpacket on 2023/11/23.
//

#ifndef ARITHMETIC_PADDING_H
#define ARITHMETIC_PADDING_H
#include <iostream>

std::vector<unsigned char> PKCS7Padding(const std::vector<unsigned char>& input);
std::vector<unsigned char> PKCS7Unpadding(const std::vector<unsigned char>& input);
#endif //ARITHMETIC_PADDING_H
