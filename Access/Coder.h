/*
 * Coder.h
 *
 *  Created on: Apr 19, 2013
 *      Author: liuyueyi
 */

#ifndef CODER_H_
#define CODER_H_

#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <iostream>
#include <string>

using namespace std;
using namespace CryptoPP;
// 编码string
string MyBase64EncoderString(const char * in);
// 解码string
string MyBase64DecoderString(const char * in);
// 解码string in, 并将恢复的数据存储在out文件中
void MyBase64DecoderString(const char * in , const char * out);
// 编码file in， 并返回编码得到的string
string MyBase64EncoderFile(const char * in);
// in作为待编码的文件，out为编码后输出的文件
void MyBase64EncoderFile(const char * in, const char * out);
// in作为待解码的文件，out为解码后输出的文件
void MyBase64DecoderFile(const char * in, const char * out);

#endif /* CODER_H_ */
