#include <iostream>
#include "base64.h"
#include "md5.h"
#include "sha1.h"

int main() {
    testBase64();
    testmd5();
    testsha1();
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
