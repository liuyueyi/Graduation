/*
 * SecByteString.cpp
 *
 *  Created on: Apr 19, 2013
 *      Author: liuyueyi
 */

#include "SecByteString.h"

/*
 * SecByteBlock to byte
 * Input:
 * 	sec: 待转化的SecByteBlock
 * 	temp: 转换后的内容存在temp中，即，temp[]就是所需的byte[]
 * 	size: byte[]的大小
 */
void sec_to_byte(SecByteBlock & sec, byte temp[], int size)
{
    for (int i = 0; i < size; i++)
    {
        temp[i] = sec[i];
    }
}

/**
 * byte to SecByteBlock
 * Input:
 *  bt[]: 待转换的byte数组
 *  size： byte数组的长度
 * Output：
 * 	返回生成的SecByteBlock
 */
SecByteBlock byte_to_sec(byte bt[], int size)
{
    SecByteBlock sec(CryptoPP::SecByteBlock(bt, size));
    return sec;
}

/**
 * Description: 将字符串类型转换为BYTE数组
 * Input:
 *  str_arr: 待转换的字符串
 *  byte_arr[]: 转换后的目标byte数组
 *  length:	byte数组的长度
 */
void str_to_byte(string str_arr, byte byte_arr[], int length)
{
    unsigned char ch1;
    unsigned char ch2;
    int k = 0;
    for (unsigned int i = 0; i < str_arr.length(); i = i + 2)
    {
        ch1 = str_arr.at(i);
        ch2 = str_arr.at(i + 1);
        if (ch1 >= 48 && ch1 <= 57)
        {
            ch1 &= 0x0F;
        }
        if (ch1 >= 'A' && ch1 <= 'F')
        {
            ch1 &= 0x0F;
            ch1 += 0x09;
        }
        if (ch2 >= 48 && ch2 <= 57)
        {
            ch2 &= 0x0F;
        }
        if (ch2 >= 'A' && ch2 <= 'F')
        {
            ch2 &= 0x0F;
            ch2 += 0x09;
        }
        ch1 <<= 4;
        byte_arr[k] = (byte) (ch1 + ch2); //int类型转byte类型，有问题
        k++;
    }
}

/**
 * Description:将BYTE数组转换为字符串类型
 * Input:
 * 	byte_arr[]: 待转换的byte数组
 * 	arr_len： byte数组的长度
 * Output:
 *  返回转化后生成的string
 */
string* byte_to_str(byte byte_arr[], int arr_len)
{
    string* hexstr = new string;
    for (int i = 0; i < arr_len; i++)
    {
        char hex1;
        char hex2;
        int value = byte_arr[i];
        int v1 = value / 16;
        int v2 = value % 16;
        //将商转换为字母
        if (v1 >= 0 && v1 <= 9)
        {
            hex1 = (char) (48 + v1);
        }
        else
        {
            hex1 = (char) (55 + v1);
        }
        //将余数转成字母
        if (v2 >= 0 && v2 <= 9)
        {
            hex2 = (char) (48 + v2);
        }
        else
        {
            hex2 = (char) (55 + v2);
        }
        //将字母连成一串
        *hexstr = *hexstr + hex1 + hex2;
    }
    return hexstr;
}

/*
 * 直接将SecByteBlock转化为string,流程：首先将SecByteBlock转换为Byte，再将Byte转换为String
 * Input:
 * 	sec:待转换的secByteBlock
 * OutPut:
 * 	返回转换后生成的string
 */
string sec_to_str(SecByteBlock & sec)
{
    int size = sec.size();
    byte temp[size];
    sec_to_byte(sec, temp, size);

    return *byte_to_str(temp, size);
}

/*
 * 将string转换为SecByteBlock，流程：首先将string转换为byte, 然后将byte转换为SecByteBlock
 * Input：
 * 	str: 待转换的string
 * Outpu：
 * 	返回生成的SecByteBlock
 */
SecByteBlock str_to_sec(string str)
{
    int size = str.length() / 2;
    byte temp[size];

    str_to_byte(str, temp, size);

    return byte_to_sec(temp, size);
}

/*
 * 用来测试的一个实例，需要引入头文件 #include "MyRSA.h"

 void test()
 {
 string plain = "My name is wuzebang!";
 string priv_key = "key/priv_key";
 string pub_key = "key/pub_key";
 MyRSA rsa;
 rsa.GenerateRSAKey(1024, priv_key.c_str(), pub_key.c_str());

 SecByteBlock signature = rsa.SignString(priv_key.c_str(), plain.c_str());

 string enc = sec_to_str(signature);
 cout << "The enc signature is : " << enc << endl;
 cout << "The signature size is : " << signature.size() << endl;
 cout << "The ecn signature is : " << enc.length() << endl;
 cout << endl;

 SecByteBlock recover = str_to_sec(enc);

 if( recover == signature )
 cout << "The two secbyteblocks are the same" << endl << endl;
 else cout << "The two secbyteblocks are not the same" << endl << endl;

 }
 */
