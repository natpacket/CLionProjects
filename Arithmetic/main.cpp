#include <iostream>
#include "base64.h"
#include "md5.h"

int main() {
    testBase64();
    testmd5();
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
