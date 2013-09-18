/*
 * MyAES.h
 *
 *  Created on: 2013-3-6
 *      Author: hust
 */

#ifndef MYAES_H_
#define MYAES_H_

#include <cryptopp/aes.h>
#include <cryptopp/default.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>

#include <stdlib.h>
#include <string>
#include <iostream>

using namespace CryptoPP;
using namespace std;

class MyAES
{
public:
    byte * key;
    byte * iv;
    int key_length;

    MyAES();
    MyAES(byte * key, byte *iv, int length);
    ~MyAES();

    //use the key to encrypt the plainText and return the cipher
    string Encrypt(const string &plainText);
    //use the same key to decrypt the cipher and return the recover
    string Decrypt(const string &cipher);
    //use the key to encrypt the file
    bool EncryptFile(const string & inFilename, const string & outFilename);
    //use the key to decyrpt the file
    bool DecryptFile(const string & DecFilename,
                     const string & recoverFilename);
    void GenerateKey();
    void SetKey(byte * key, byte * iv, int length);
};

#endif /* MYAES_H_ */

