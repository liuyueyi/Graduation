/*
 * Coder.cpp
 *
 *  Created on: Apr 19, 2013
 *      Author: liuyueyi
 */

#include "Coder.h"

/*
 * Description: 对string类型数据进行Base64编码
 * Input:
 * 	in: 待编码的字符串
 * Output:
 * 	返回编码后的字符串
 */
string MyBase64EncoderString(const char * in)
{
    string out;
    StringSource(in, true, new Base64Encoder(new StringSink(out)));
    return out;
}

/*
 * Description: 对Base64编码的string数据解码
 * Input：
 * 	in: 待解码的Base64格式字符串
 * Output:
 *  返回解码后的字符串
 */
string MyBase64DecoderString(const char * in)
{
    string out;
    StringSource(in, true, new Base64Decoder(new StringSink(out)));
    return out;
}
/*
 * Description: 对文件进行Base64编码
 * Input:
 * 	in: 待编码的文件
 * 	out: 编码后生成的文件
 */
void MyBase64EncoderFile(const char *in, const char *out)
{
    FileSource(in, true, new Base64Encoder(new FileSink(out)));
}

/*
 * Description: 对Base64文件进行解码
 * Input：
 *  in: 待解码的文件
 *  out: 解码后生成的文件
 */
void MyBase64DecoderFile(const char *in, const char *out)
{
    FileSource(in, true, new Base64Decoder(new FileSink(out)));
}

/*
 * Description: 对file进行Base64编码
 * Input:
 * 	in: 待编码的file
 * Output:
 * 	返回编码后的字符串
 */
string MyBase64EncoderFile(const char * in)
{
    string out;
    FileSource(in, true, new Base64Encoder(new StringSink(out)));
    return out;
}

/*
 * Description: 对string进行Base64编码
 * Input:
 * 	in: 待编码的string
 * 	out: 编码后生成的文件
 */
void MyBase64DecoderString(const char * in , const char * out)
{
    StringSource(in, true, new Base64Decoder(new FileSink(out)));
}
