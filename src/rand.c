/*
 *  Copyright 2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/win_support.h>

#define RAND_MAX_BUF_SIZE 4096

#ifndef _MSC_VER
int rand_bytes(uint8_t* buf, size_t len)
{
    FILE* fp;
    if (!buf) {
        error_print();
        return -1;
    }
    if (len > RAND_MAX_BUF_SIZE) {
        error_print();
        return -1;
    }
    if (!len) {
        return 0;
    }

    if (!(fp = fopen("/dev/urandom", "rb"))) {
        error_print();
        return -1;
    }
    if (fread(buf, 1, len, fp) != len) {
        error_print();
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 1;
}
#else
int rand_bytes(uint8_t* buf, size_t len)
{
    HCRYPTPROV   hCryptProv;
    int result = -1;
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0))
    {
        if (CryptGenRandom(hCryptProv, len, buf))
        {
            result = CryptReleaseContext(hCryptProv, 0);
        }
    }
    return result;
}
#endif
