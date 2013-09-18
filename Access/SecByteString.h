/*
 * SecByteString.h
 *
 *  Created on: Apr 19, 2013
 *      Author: liuyueyi
 *  Description:
 *  	实现SecbyteBlock与string类型之间的相互转换
 */

#ifndef SECBYTESTRING_H_
#define SECBYTESTRING_H_
#include <cryptopp/rsa.h>
#include <iostream>
#include <string>

using namespace std;
using namespace CryptoPP;

// implements  SecByteBlock to byte[]
void sec_to_byte(SecByteBlock & sec, byte temp[], int size);
// implements byte[] to SecByteBlock
SecByteBlock byte_to_sec(byte bt[], int size);
// implements string to byte[]
void str_to_byte(string str_arr, byte byte_arr[], int length);
// implements byte[] to string
string* byte_to_str(byte byte_arr[], int arr_len);

// implements SecByteBlock to string, you can just call this function to simplify your code
string sec_to_str(SecByteBlock & sec);
// directly implements the conversion from string to SecByteBlock
SecByteBlock str_to_sec(string str);

#endif /* SECBYTESTRING_H_ */
