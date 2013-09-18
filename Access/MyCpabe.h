/*
 * cpabe.h
 *
 *  Created on: 2013-3-8
 *      Author: hust
 */

#ifndef CPABE_H_
#define CPABE_H_

#include <stdlib.h>
#include <string>
#include <iostream>
using namespace std;

class MyCpabe
{
public:
    MyCpabe();

    bool setUp();

    bool Encrypt(const string & pubKeyFilename, const string & plainText,
                 const string & policy);

    bool KeyGen(const string & pubKeyFilename, const string & masterKeyFilename,
                const string & userAtrtributeSet, const string & outFile =
                    "priv_key");

    bool Decrypt(const string & pubKeyFilename, const string & secretKey,
                 const string & cipherText);
};

#endif /* CPABE_H_ */
