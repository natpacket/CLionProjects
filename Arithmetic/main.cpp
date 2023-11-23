#include <iostream>
#include "base64.h"
#include "md5.h"
#include "sha1.h"
#include "hmac_md5.h"
#include "crc32.h"
#include "aes.h"

int main() {
    testBase64();
    testmd5();
    testsha1();
    testcrc32();
    test_hmac_md5();
    testAes();
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
