/*
 * AESKey.cpp
 *
 *  Created on: 2013-4-22
 *      Author: administrator
 */

#include "AESKey.h"

AESKey::AESKey()
{
    AESKey::GenerateKey();
}

AESKey::AESKey(byte k[], byte v[], int sz)
{
    key = *byte_to_str(k, AES::DEFAULT_KEYLENGTH);
    iv = *byte_to_str(v, AES::BLOCKSIZE);
    size = sz;
}

void AESKey::GenerateKey()
{
    AutoSeededRandomPool rnd;
    byte key1[AES::DEFAULT_KEYLENGTH];
    rnd.GenerateBlock(key1, AES::DEFAULT_KEYLENGTH);

    // Generate a random IV
    byte iv1[AES::BLOCKSIZE];
    rnd.GenerateBlock(iv1, AES::BLOCKSIZE);

    key = *byte_to_str(key1, AES::DEFAULT_KEYLENGTH);
    iv = *byte_to_str(iv1, AES::BLOCKSIZE);
    size = 16;
}
