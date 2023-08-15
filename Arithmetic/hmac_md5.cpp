//
// Created by natpacket on 2023/8/15.
//

#include "hmac_md5.h"
#include <stdint.h>
#include <cstring>
#include <cstdio>
#include "md5.h"

#define IPAD 0x36
#define OPAD 0x5C

void hmac_md5(uint8 dest[16], const uint8 *key, uint16_t keylength, const uint8 *msg, uint32_t msglength){
    MD5_CTX s;
    uint8_t i;
    uint8_t buffer[MD5_BLOCK_SIZE];

    memset(buffer, 0, MD5_BLOCK_SIZE);

    /* if key is larger than a block we have to hash it*/
    if (keylength > MD5_BLOCK_SIZE){
        MD5(key, keylength,buffer);
    } else {
        memcpy(buffer, key, keylength);
    }

    for (i=0; i<MD5_BLOCK_SIZE; ++i){
        buffer[i] ^= IPAD;
    }
    MD5_Init(&s);
    MD5_Update(&s, buffer,MD5_BLOCK_SIZE);
    while (msglength >= MD5_BLOCK_SIZE){
        MD5_Update(&s, msg,MD5_BLOCK_SIZE);
        msg = (uint8_t*)msg + MD5_BLOCK_SIZE;
        msglength -=  MD5_BLOCK_SIZE;
    }
    MD5_Update(&s, msg, msglength);
    /* since buffer still contains key xor ipad we can do ... */
    for (i=0; i<MD5_BLOCK_SIZE; ++i){
        buffer[i] ^= IPAD ^ OPAD;
    }
    MD5_Final(&s,dest); /* save inner hash temporary to dest */
    MD5_Init(&s);
    MD5_Update(&s, buffer,MD5_BLOCK_SIZE);
    MD5_Update(&s, dest, MD5_DIGEST_SIZE);
    MD5_Final(&s,dest);
}

void test_hmac_md5(){
    uint8 dest[16];
    const uint8 key[] ="qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
    uint16_t keylength_b = strlen(reinterpret_cast<const char *>(key));
    const uint8 msg[] ="1234567";
    uint32_t msglength_b = strlen(reinterpret_cast<const char *>(msg));
    hmac_md5(dest,key,keylength_b,msg,msglength_b);
    printf("%s key: %s HMAC-MD5: ",msg,key);
    for (uint32 i = 0; i < MD5_DIGEST_SIZE; i++) {
        printf("%02x", dest[i]);
    }
    printf("\n");
}