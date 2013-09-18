/*
 * test.h
 *
 *  Created on: 2013-4-18
 *      Author: administrator
 */

#ifndef TEST_H_
#define TEST_H_

#include <sys/time.h>
#include "MyAES.h"
#include "MyRSA.h"
#include "MyCpabe.h"
#include "MyHash.h"

#include "AttributeTree.h"
#include "AESKey.h"
#include "Coder.h"
#include "Credential.h"
#include "Metadata.h"

struct timeval start, finish;
float duration;
ofstream record;

string get_filename(const string & filename);

// 将aes key 序列化保存到outfile文件中
void save_aes_key(MyAES aes, const string & outfile);
// 判断两个文件是否相同，计算两个文件的MD5来比对
bool test_compare(const string & file1, const string & file2);
// 利用签名密钥signKey来签名文件testfile
string test_sign(const string & signKey, const string & testfile);
// 验证签名，以判断文件的完整性； 首先从meta中得到Kverify Signature，
// 调用AES验证算法，验证testfile是否完整
bool test_verify(const Metadata & meta, const string & testfile);
// 创建metadata对象，并序列化保存到文件中
// Metadata对象有：访问策略Policy, 黑名单blacklist, 验证公钥pub_key, 签名signature
// 序列化后保存的文件名metadatafile
void create_metadata(const string & policy, const string & blacklist,
                     const string & pub_key, const string & signature,
                     const string & metadatafile);

// 利用AES key加密testfile, 密文保存在outfile中
bool test_encrypt(MyAES & aes, const string & testFile, const string & outFile);
// 利用AES Key解密testfile, 明文保存在outfile中
bool test_decrypt(MyAES & aes, const string & testFile, const string & outfile);
// 返回用户用于解密内容密钥的属性私钥
string send_user_key(const Credential credential, const string & filename);
// 上传内容密钥加密后的密文，元数据，加密后内容密钥，加密后签名密钥，属性公钥，属性主密钥
bool upload(string & enc, string & meta, string & enc_aes, string & enc_sign,
            string & pk, string & mk);
// 下载文件
bool download(const Credential credential, const string & file);

// 测试用户put请求操作, 上传filename(明文形式的文件)，访问策略policy，黑名单blacklist
bool test_put(const string & filename, const string & policy,
              const string & blacklist);

// 测试用户获得请求操作, 发送用户credential，访问的文件名
bool test_get(const Credential credential, const string & filename);

// 批量上传文件
bool put();

// 测试访问控制识别的正确率
bool test_get_rate();
// 测试用户开销，主要是同一用户对于不同访问策略文件访问的开销
// 分别访问2-6层访问控制树
void test_judge_cost1();
// 测试不同用户访问同一访问策略文件的开销
// 主要是针对不同用户属性集的情况
void tset_judge_cost2();

#endif /* TEST_H_ */
