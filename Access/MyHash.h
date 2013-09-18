/*
 * MyHash.h
 *
 *  Created on: 2013-3-7
 *      Author: hust
 */

#ifndef MYHASH_H_
#define MYHASH_H_

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <string>
#include <iostream>

using namespace std;
using namespace CryptoPP;

class MyHash
{
public:
    MyHash();
    ~MyHash();
    //calculate the md5 of the message
    static string MD5String(const char * message);
    //calculate the md5 of the file
    static string MD5File(const char * filename);
};

#endif /* MYHASH_H_ */
