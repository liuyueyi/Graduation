/*
 * test.cpp
 *
 *  Created on: 2013-4-18
 *      Author: administrator
 *  Compile command: g++ -lcryptopp -lpthread -lboost_serialization test.cpp MyAES.cpp MyRSA.cpp MyCpabe.cpp Coder.cpp SecByteString.cpp AESKey.cpp MyHash.cpp AttributeTree.cpp -o test
 */
#include "test.h"

map<string , list<int> > my_map;

string get_filename(const string & filename)
{
    // 输出密文的名称与原始数据名称一样，仅路径不同而已
    // 如原文件 datamodel/1KB 获得1KB返回
    int index = filename.find_last_of('/');
    if (index == string::npos) // 查找失败
    {
        index = 0;
    }
    return filename.substr(index + 1);

}

// 将aes key序列化保存到outfile文件中
void save_aes_key(MyAES aes, const string & outfile)
{
    // 获得aes_key对象，接着将aes key序列化到文件中
    AESKey myAesKey(aes.key, aes.iv, aes.key_length);
    // 保存aes key的文件
    ofstream ofs(outfile.c_str());
    boost::archive::text_oarchive oa(ofs);
    oa << myAesKey;
    ofs.close();
}

/*
 * Description:判断两个文件的内容是否相同
 * Input:
 *  file1, file2: 待判定的两个文件
 * Output:
 *  如果两个文件的内容相同，则返回true; 否则返回false
 */
bool test_compare(const string & file1, const string & file2)
{
    string md51 = MyHash::MD5File(file1.c_str());
    string md52 = MyHash::MD5File(file2.c_str());
    if (md51 == md52)
        return true;
    else
        return false;
}

/*
 * Description: 签名testfile的MD5, 并将生成的SecByteBlock格式的sig转换为string返回
 * Input:
 *  rsa: rsa对象
 *  signKey: rsa private key
 *  testfile: 待签名的文件名
 * Output:
 *  返回testfile的MD5值的签名（转化为string类型的签名）
 */
string test_sign(const string & signKey, const string & testfile)
{
    MyRSA rsa;
// 计算对称加密后生成的秘文的MD5,然后对MD5进行签名
    string md5 = rsa.MD5File(testfile.c_str());
    SecByteBlock sig = rsa.SignString(signKey.c_str(), md5.c_str());
// 获得构成Metadata的签名signature
    string signature = sec_to_str(sig);
    return signature;
}

/*
 * Description: 验证签名，以判断文件的完整性
 * Input:
 * 	meta: Metadata对象，从该对象中获取存储其中的签名signature
 * 	testfile: 待验证的文件
 * 	verifyKey: 验证密钥，同样封装在meta对象中
 */
bool test_verify(const Metadata & meta, const string & testfile)
{
// 获得验证密钥
    string verifyKey = meta.verifyKey;
    string verify_key = "temp/" + get_filename(testfile) + ".verify";
    ofstream write(verify_key.c_str());
    write << verifyKey;
    write.close();

// get the signature
    string sig = meta.signature;
    SecByteBlock signature = str_to_sec(sig);

    MyRSA rsa;
// 验证数据的完整性，若不满足则返回false
    gettimeofday(&start, NULL);
    string md5 = MyHash::MD5File(testfile.c_str());
    bool result = rsa.VerifyString(verify_key.c_str(), md5.c_str(), signature);
    gettimeofday(&finish, NULL);
    duration = 1000000 * (finish.tv_sec - start.tv_sec)
               + (finish.tv_usec - start.tv_usec);
    duration /= 1000.0;
    record << "Verify cost is: " << duration << "ms" << endl;

    return result;
}

/*
 * Description:利用属性加密算法加密密钥
 * Input:
 * 	pubkey: cpbae算法启动时，生成的公共密钥
 * 	testfile: 待加密的密钥（文件形式）
 *	outfile:  将加密后的密钥编码后保存的文件名
 * 	policy： 定义的访问策略
 * Output
 */
void test_encrypt_key(const string & pubkey, const string & testfile,
                      const string & outfile, const string & policy)
{
    MyCpabe cpabe;
    if (cpabe.Encrypt(pubkey, testfile, policy))
    {
        string ans = testfile + ".cpabe";
        // 将加密后的秘文base64位编码，返回
        MyBase64EncoderFile(ans.c_str(), outfile.c_str());
    }
}

string test_decrypt_key(const string & pub_key, const string & user_key,
                        const string & file)
{
    MyCpabe cpabe;

    // 获得aesKey,并解码得到利用cpabe加密的aes_key
    string aesKey = "temp/" + file + ".aes";
    string enc_aes_key = "temp/" + file + "_aes.cpabe";
    MyBase64DecoderFile(aesKey.c_str(), enc_aes_key.c_str());

    // 解密对称密钥
    gettimeofday(&start, NULL);
    cpabe.Decrypt(pub_key, user_key, enc_aes_key);
    gettimeofday(&finish, NULL);
    duration = 1000000 * (finish.tv_sec - start.tv_sec)
               + (finish.tv_usec - start.tv_usec);
    duration /= 1000.0;
    record << "Decrypt the aes key cost is : " << duration << "ms" << endl;

    // 得到序列化后的对称密钥文件
    return ("temp/" + file + "_aes");
}

/*
 * Description:生成Metadata对象，并将其中内容序列化后存储在metadata指定的文件中
 * Input:
 * 	policy: 定义加密对称密钥和签名密钥的访问策略，即定义有权访问数据的访问策略
 * 			形如："((A or BC)and(E or FG))and((H and IJ)or(K or MN))"
 * 	blacklist: 黑名单
 * 	pub_key: cpbae的公共密钥文件名
 * 	signKey: 签名密钥经过如下处理：1.属性加密 2.base64编码加密后的文件； 得到string对象
 * 	signature: 签名，利用用户签名密钥签名后得到的SecByteBlock类型转化而得的string对象
 * 	aesKey:	内容密钥（对称密钥）如下处理：1.封装到AESKey类中 2.序列化AESKey对象，
 * 			得到保存aes key相关参数的文件 3.属性加密 4.base64编码加密后的文件；得到string对象
 * 	metadata: 元数据文件名；即由上面五个参数首先构建Metadata对象，然后序列化该对象，存储相关信息的文件
 */
void create_metadata(const string & policy, const string & blacklist,
                     const string & pub_key, const string & signature,
                     const string & metadata)
{
    ifstream pub(pub_key.c_str());
    char temp[2048];
    pub.getline(temp, 2048);
// 获得构成Metadata的验证密钥verifyKey
    string verifyKey = temp;
    pub.close();

// 生成Metadata对象
    Metadata meta(policy, blacklist, verifyKey, signature);
// 将metadata序列化后，开始执行上传过程
    ofstream ofs2(metadata.c_str());
    boost::archive::text_oarchive oa2(ofs2);
    oa2 << meta;
    ofs2.close();
}

/*
 * Description: 测试加密文件所消耗的时间函数
 * Input:
 * 		aes: 封装了aes加密算法的对象
 * 	 	testFile: 待加密的文件
 * 	 	outFile: 输出秘文的文件名
 * Output:
 * 	if encrypt the file succeed, return true; else return false
 */
bool test_encrypt(MyAES & aes, const string & testFile, const string & outFile)
{
// 判断文件是否存在已经包含在EncryptFile函数内，因此这里可以省去
    return aes.EncryptFile(testFile, outFile);
}

/*
 * Description: 测试加密文件所消耗的时间函数
 * Input:
 * 		aes: 封装了aes加密算法的对象
 * 	 	testFile: 待解密的文件
 * 	 	outFile: 输出明文的文件名
 * Output:
 * 	if decrypt the file succeed, return true; else return false
 */
bool test_decrypt(MyAES & aes, const string & testFile, const string & outFile)
{
    return aes.DecryptFile(testFile, outFile);
}

// 返回用户用于解密对称密钥的属性私钥
string send_user_key(const Credential credential, const string & filename)
{
    ostringstream oss;
    oss << credential.UID;
    string user_key = "key/" + oss.str() + "_sk";

    MyCpabe cpabe;
    string pubKeyFilename = "key/pub_key", masterKeyFilename =
                                "key/master_key";
    cpabe.KeyGen(pubKeyFilename, masterKeyFilename, credential.attributes,
                 user_key);
    return user_key;
}

bool upload(string & enc, string & meta, string & enc_aes, string & enc_sign,
            string & pk, string & mk)
{
    string cmd = "mv " + enc + " cloud/output/";
    system(cmd.c_str());

    cmd = "mv " + enc_aes + " " + enc_sign + " cloud/key/";
    system(cmd.c_str());

    string file = get_filename(enc);
    cmd = "mv " + meta + " " + " cloud/metadata/";
    system(cmd.c_str());

    cmd = "cp " + pk + " " + mk + " key/";
    system(cmd.c_str());

    system(
        "rm temp/aesKey.cpabe temp/rsaPrivKey.cpabe temp/rsaPubKey");
    return true;
}

bool download(const Credential credential, const string & file)
{
    // 读取元数据中的访问策略
    string metadata = "cloud/metadata/" + file + ".metadata";
    ifstream ifs(metadata.c_str(), std::ios::binary);
    boost::archive::text_iarchive ia2(ifs);
    Metadata meta;
    ia2 >> meta;
    ifs.close();

    // 判断用户的属性集是否满足访问策略，满足返回true；否则返回false；
    // 这里省略了将文件+metadata返回的操作
    gettimeofday(&start, NULL);

    bool ans = judge(file, meta.policy, meta.blacklist, credential, my_map);

    gettimeofday(&finish, NULL);
    duration = 1000000 * (finish.tv_sec - start.tv_sec)
               + (finish.tv_usec - start.tv_usec);
    duration /= 1000.0;
    record << "------------GET------------------" << endl;
    record << "Access control judge cost is : " << duration << "ms" << endl;

    if (ans)
    {
        // 返回加密后的文件
        string temp = " ";
        string cmd = "cp" + temp + " cloud/output/" + file + " temp/";
        system(cmd.c_str());

        // 返回metadata文件
        cmd = "cp " + metadata + " temp/";
        system(cmd.c_str());

        // 返回加密后的内容密钥
        cmd = "cp" + temp + "cloud/key/" + file + ".aes" + temp + "temp/";
        system(cmd.c_str());

        // 返回用户私钥和属性公钥
        // ...
        return true;
    }
    else
    {
        record << "Access control denyed!" << endl << endl;
        return false;
    }

}

// 流程：1. 利用对称密钥加密原数据 2. 利用属性加密机制加密对称密钥 3. 签名 4. 打包上传
bool test_put(const string & filename, const string & policy,
              const string & blacklist)
{
    AutoSeededRandomPool rnd;
    byte key[AES::DEFAULT_KEYLENGTH];
    rnd.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);

// Generate a random IV
    byte iv[AES::BLOCKSIZE];
    rnd.GenerateBlock(iv, AES::BLOCKSIZE);

    int keysize = 16;

// 定义MyAES对象
    MyAES aes(key, iv, keysize);

// 输出密文的名称与原始数据名称一样，仅路径不同而已
// 如原文件 datamodel/1KB 则密文 temp/1KB， 后期上传则直接操作temp下的文件
    string file = get_filename(filename);
    string outfile = "temp/" + file;

// 加密测试文件
    gettimeofday(&start, NULL);
    test_encrypt(aes, filename, outfile);
    gettimeofday(&finish, NULL);
    duration = 1000000 * (finish.tv_sec - start.tv_sec)
               + (finish.tv_usec - start.tv_usec);
    duration /= 1000.0;
    record << "------------PUT " << file << "---------------" << endl;
    record << "Encrypt cost is : " << duration << "ms" << endl;

// 序列化保存对称密钥到aes_key指定的文件中
    string aes_key = "temp/aesKey";
    save_aes_key(aes, aes_key);

    MyRSA rsa;
// 生成签名密钥，和验证密钥；其中签名密钥加密后上传
    string rsa_priv_key = "temp/rsaPrivKey";
    string rsa_pub_key = "temp/rsaPubKey";
    unsigned int length = 1024;
    rsa.GenerateRSAKey(length, rsa_priv_key.c_str(), rsa_pub_key.c_str());

// 签名对称密钥加密后得到的秘文
    gettimeofday(&start, NULL);
    string signature = test_sign(rsa_priv_key, outfile);
    gettimeofday(&finish, NULL);
    duration = 1000000 * (finish.tv_sec - start.tv_sec)
               + (finish.tv_usec - start.tv_usec);
    duration /= 1000.0;
    record << "Sign cost is : " << duration << "ms" << endl;

// cpabe启动时生成的公共密钥和主密钥
    string pubKey = "pub_key", masterKey = "master_key";
// 利用属性加密算法加密对称密钥和签名密钥,并且将它们保存在指定的文件中
    string enc_aes_key = "temp/" + file + ".aes";
    string enc_sign_key = "temp/" + file + ".sign";
    gettimeofday(&start, NULL);
    test_encrypt_key(pubKey, aes_key, enc_aes_key, policy);
    test_encrypt_key(pubKey, rsa_priv_key, enc_sign_key, policy);
    gettimeofday(&finish, NULL);
    duration = 1000000 * (finish.tv_sec - start.tv_sec)
               + (finish.tv_usec - start.tv_usec);
    duration /= 1000.0;
    record << "Encrypt and serialize the aes key and sign key cost is : "
    << duration << "ms" << endl << endl;

    string metadata = "temp/" + file + ".metadata";
// 创建Metadata对象，并将Metadata对象中成员序列化到metadata指定的元数据文件中
    create_metadata(policy, blacklist, rsa_pub_key, signature, metadata);

// 上传操作，将对称加密后的秘文，元数据文件，主密钥上传到云端
    if (upload(outfile, metadata, enc_aes_key, enc_sign_key, pubKey, masterKey))
        return true;
    else
        return false;
}
// 实现整个get请求的流程
bool test_get(const Credential credential, const string & filename)
{
    string file = get_filename(filename);
// 首先发出请求，然后判断是否拥有访问权限
    if (!download(credential, file))
    {
        record << ">>> This person can not access the file: " << filename
        << endl << endl;
        return false;
    }
// 获得metadata，并开始解析metadata
    string metadata = "temp/" + file + ".metadata";
    ifstream ifs(metadata.c_str(), std::ios::binary);
    boost::archive::text_iarchive ia(ifs);
    Metadata meta;
    ia >> meta;
    ifs.close();

// 判断数据的完整性，若完整则执行之后的操作，否则返回false
    if (!test_verify(meta, "temp/" + file))
    {
        record << ">>> Verify failed!" << endl << endl;
        return false;
    }
    else
        record << ">>> Verify succeed!" << endl << endl;

    // 获得用于私钥，用来解密内容密钥
    string user_key = send_user_key(credential, filename);
    // 解密属性加密后的对称密钥，并返回序列化后存储的文件名
    string ser_aes_key = test_decrypt_key("key/pub_key", user_key, file);

    // 反序列化，得到AESKey对象aes_key
    ifstream ifs2(ser_aes_key.c_str(), std::ios::binary);
    boost::archive::text_iarchive ia2(ifs2);
    AESKey aes_key;
    ia2 >> aes_key;
    ifs2.close();

    byte key[AES::DEFAULT_KEYLENGTH];
    str_to_byte(aes_key.key, key, AES::DEFAULT_KEYLENGTH);

    byte iv[AES::BLOCKSIZE];
    str_to_byte(aes_key.iv, iv, AES::BLOCKSIZE);

    int size = aes_key.size;

    MyAES aes(key, iv, size);

    // 利用对称密钥解密秘文
    string recoverFile = "recover/" + file;

    gettimeofday(&start, NULL);
    test_decrypt(aes, "temp/" + file, recoverFile);
    gettimeofday(&finish, NULL);
    duration = 1000000 * (finish.tv_sec - start.tv_sec)
               + (finish.tv_usec - start.tv_usec);
    duration /= 1000.0;
    record << "Decrypt the cipher cost is :" << duration << "ms" << endl;

    if (test_compare(recoverFile, filename))
    {
        record << "The original file and the recover file are the same!" << endl
        << endl;
        return true;
    }
    else
    {
        record << "The original file and the recover file are not the same!"
        << endl << endl;
        return false;
    }
}

/*
 * 上传文件到云端
 */
bool put()
{
    string policy, file, blacklist;

    // 两层
    policy = "A and E";             //2
    blacklist = "1 2";
    file = "datamodel/4KB";
    test_put(file, policy, blacklist);

    file = "datamodel/4MB";
    test_put(file, policy, blacklist);

    // 三层
    policy = "(A and E)or(B or C)";         // 4
    blacklist = "1 2";
    file = "datamodel/8KB";
    test_put(file, policy, blacklist);

    // 四层
    policy = "((A and E)and(C or D))and(M or TT)";      // 6
    blacklist = "1 2";
    file = "datamodel/16KB";
    test_put(file, policy, blacklist);

    policy = "((A or BC)and(E or FG))and((H and IJ)or(K or MN))";   // 8
    blacklist = "91 92 93 94 95 96 97 98 99 100 1 2 3 4 5 6 7 8 9 10";
    file = "datamodel/32KB";
    test_put(file, policy, blacklist);

    // 五层
    policy = "(((A or BC)and(E or FG))or(D or MN))and(((K or TT)and(PP and CM))or(C or M))";    // 12
    blacklist = "1 2 3 4";
    file = "datamodel/64KB";
    test_put(file, policy, blacklist);

    policy = "(((A or BC)and(E or FG))or((D or MN)or(FC and FB)))and(((K or TT)and(PP and CM))or((C or M1)and(M or FF2)))"; // 16
    blacklist = "1 2 3 4";
    file = "datamodel/128KB";
    test_put(file, policy, blacklist);

    // 六层
    policy = "((((A or BC)and(E or FG))or(FC and FB))or(((K or TT)and(PP and CM))or(C1 or M21)))and((((A2 or BC3)and(E2 or FG3))or(C or FB1))and((PP4 and CM1)or((C4 or M)and(M or ew1))))";    // 24
    blacklist = "1 2 3 4";
    file = "datamodel/256KB";
    test_put(file, policy, blacklist);

    policy =
        "((((A or BC)and(E or FG))or((D or MN)and(BB and PP)))and(((P and F)or(K or TT))and((WX or M)or(TT and CC))))or((((A1 or BC1)and(E1 or FG1))or((D1 or MN1)and(BB1 and PP1)))and(((P1 and F1)or(K1 or TT1))and((WX1 or M1)or(TT1 and CC1))))"; // 32
    blacklist = "1 2 3 4";
    file = "datamodel/512KB";
    test_put(file, policy, blacklist);

//    // 六层
//    policy =
//        "((((A or BC)and(E or FG))or((D or MN)or(FC and FB)))and(((K or TT)and(PP and CM))or((C1 or M21)and(M1 or FF22))))or((((A2 or BC3)and(E2 or FG3))or((D1 or MN3)or(FC4 and FB1)))and(((K5 or TT3)and(PP4 and CM1))or((C4 or 2M1)and(M33 or ew1))))";   // 32
//    blacklist = "1 2 3 4";
//    file = "datamodel/1024KB";
//    test_put(file, policy, blacklist);
    return true;
}

/*
 * 测试访问控制的正确率，
 * 访问对象 32KB， 访问策略："((A or BC)and(E or FG))and((H and IJ)or(K or MN))"
 * 其中UID为为偶数，表示不满足ACT的用户
 * UID为基数的用户，表示满足ACT的用户
 * 1-10， 99-100号用户为黑名单用户；即，即使其属性集满足ACT，仍不能访问
 */
bool test_get_rate(int num)
{
    ofstream rate_result("result/rate_result");
    string temp[12][3] =
    {
        { "A", "E", "H IJ" },
        { "A", "E", "K" },
        { "A", "E", "MN" },
        { "A", "FG", "H IJ" },
        { "A", "FG", "K" },
        { "A", "FG", "MN" },
        { "BC", "E", "H IJ" },
        { "BC", "E", "K" },
        { "BC", "E", "MN" },
        { "BC", "FG", "H IJ" },
        { "BC", "FG", "K" },
        { "BC", "FG", "MN" }
    };
    string temp1[] =
    {
        "AD", "CH", "EFF", "HI", "J", "MND", "EF", "PO", "UI", "WS", "PPO", "YZ",
        "MB"
    }; //13
    string temp2[] =
    { "A", "BC", "E", "FG", "H", "IJ", "K", "MN" }; //8

    Credential credential;
    int test_num = num;
    for (int i = 1; i <= test_num; i++)
    {
        string attrs = "";
        if (i % 2 == 0) //UID为偶数的用户为无权限用户
        {
            int j1 = i % 13, j2, j3;
            if (j1 == 12)
                j2 = 0;
            else
                j2 = j1 + 1;
            if (j2 == 12)
                j3 = 0;
            else
                j3 = j2 + 1;

            int m1 = i % 8, m2;
            if (m1 == 7)
                m2 = 0;
            else
                m2 = m1 + 1;

            attrs = temp1[j1] + " " + temp2[m1] + " " + temp1[j2] + " "
                    + temp1[j3] + " " + temp2[m2];
        }
        else // UID为奇数的用户有权限用户
        {
            string temp4[3] = temp[i % 12];
            int m1 = i % 13, m2;
            if (m1 == 12)
                m2 = 0;
            else
                m2 = m1 + 1;

            attrs = temp4[0] + " " + temp1[m1] + " " + temp4[1] + " "
                    + temp1[m2] + " " + temp4[2];
        }

        credential.UID = i;
        credential.attributes = attrs;
        if (download(credential, "32KB"))
        {
            rate_result << i << ": " << "can access the file" << endl;
            cout << "V" << " ";
        }
        else
        {
            rate_result << i << ": " << "can not access the file" << endl;
            cout << "X" << " ";
        }
        if (i % 20 == 0)
            cout << endl;
    }

    cout << endl;

    rate_result.close();
    return true;
}

/*
 * 测试判断用户是否拥有权限的开销
 * 1： 相同用户对于不同深度ACT，开销的不同
 * 2： 不同用户对于相同深度ACT，开销的不同
 */
void test_judge_cost1()
{
    ofstream judge_cost("result/judge_cost1", ios::app);
    Credential credential(15, "A E K WX");

    string file[] =
    { "4KB", "8KB", "16KB", "32KB", "64KB", "128KB", "256KB", "512KB"};

    for (int i = 0; i < 8; i++)
    {
        //download(credential, file[i]);

        float sum = 0.0f;
        // 读取元数据中的访问策略
        string metadata = "cloud/metadata/" + file[i] + ".metadata";
        ifstream ifs(metadata.c_str(), std::ios::binary);
        boost::archive::text_iarchive ia2(ifs);
        Metadata meta;
        ia2 >> meta;
        ifs.close();
        judge_cost << "------------GET " + file[i] + "----------------" << endl;
        cout << "------------GET " + file[i] + "----------------" << endl;
        for (int j = 0; j < 11; j++)
        {
            // 判断用户的属性集是否满足访问策略，满足返回true；否则返回false；
            // 这里省略了将文件+metadata返回的操作
            gettimeofday(&start, NULL);
            bool ans = judge(file[i], meta.policy, meta.blacklist, credential, my_map);
            gettimeofday(&finish, NULL);
            duration = 1000000 * (finish.tv_sec - start.tv_sec)
                       + (finish.tv_usec - start.tv_usec);
            if(j>0) sum += duration;
            judge_cost << "  judge cost is : " << duration << "us" << endl;
        }
        sum /= 10;
        judge_cost << endl << "Average cost is : " << sum << "mus" << endl
        << endl;
        cout << endl << "Average cost is : " << sum << "us" << endl << endl;
    }
    judge_cost << "=========The Next record!============" << endl << endl;
    judge_cost.close();
}

/*
 * 测试不同用户访问相同文件的时间开销
 */
void test_judge_cost2()
{
    string file = "32KB";
    ofstream judge_cost("result/judge_cost2", ios::app);
    Credential credential;

    string attrs[] =
    {
        "A E K M", " A BC EK E K LM W E",
        "BE E K IJ KK BW N W QQ PP SID A",
        "AB E A L M N KM EN K JJ II Q D G E W",
        "Q W E R T Y U I O P AS D F G H J K LA A QQ",
        "QT WW E R T Y U I O P AS D F G H J K LA A Z DD W2 R4 D4",
        "QT WW E R T Y U I BC EJM WL O P AS D F G H J K LA A Z DD W2 R4 D4 J2",
        "Q W E R T Y U I O P AS D F G H J K LA A Z X C V B N M ER HJ SD QQ ES EW",
        "Q W WW QI YY HH E R T Y U I O P AS D F G H J K LA A Z X C V B N M ER HJ SD QQ ES EW",
        "Q W WW QI YY HH E R RE L1L1 23 T Y U I O P AS D F G H J K LA A Z X C V B N M ER HJ SD QQ ES EW RR"
    };

    for (int i = 0; i < 10; i++)
    {
        credential.UID = 11 + i;
        credential.attributes = attrs[i];
        float sum = 0.0f;
        // 读取元数据中的访问策略
        string metadata = "cloud/metadata/" + file + ".metadata";
        ifstream ifs(metadata.c_str(), std::ios::binary);
        boost::archive::text_iarchive ia2(ifs);
        Metadata meta;
        ia2 >> meta;
        ifs.close();
        judge_cost << "--------------" << credential.UID
        << " : GET " + file + "----------------" << endl;
        for (int j = 0; j < 11; j++)
        {
            // 判断用户的属性集是否满足访问策略，满足返回true；否则返回false；
            // 这里省略了将文件+metadata返回的操作
            gettimeofday(&start, NULL);
            bool ans = judge(file, meta.policy, meta.blacklist, credential, my_map);
            gettimeofday(&finish, NULL);
            duration = 1000000 * (finish.tv_sec - start.tv_sec)
                       + (finish.tv_usec - start.tv_usec);
            if(j>0) sum += duration;
            judge_cost << "  judge cost is : " << duration << "us" << endl;
        }
        sum /= 10;
        judge_cost << endl << "Average cost is : " << sum << "us" << endl
        << endl;
        cout << endl << "Average cost is : " << sum << "us" << endl
             << endl;
    }

    judge_cost << "=========The Next record!============" << endl << endl;
    judge_cost.close();
}

void cal()
{
    int i = -1;
    while(i != 0 )
    {
        cout << "\t\t 0:end" << endl << "\t\t 1:different ACT" << endl << "\t\t 2:different user" << endl << "\t\t ";
        cin >> i;
        switch(i)
        {
        case 0:
            break;
        case 1:
            test_judge_cost1();
            break;
        case 2:
            test_judge_cost2();
            break;
        default:
            break;
        }
    }
}

/*
int main()
{
//        MyCpabe cpabe;
//    	cpabe.setUp();
    	 //以追加写模式打开保存结果的文件
    	record.open("result/result1", ios::app);
    	put();
//    	unsigned int i = 0;
//    	cout << "Input the user num: " ;
//    	cin >> i;
//    	test_get_rate(i);

    	record << "===================================" << endl;
    	 //关闭记录文件
    	record.close();

//	test_judge_cost1();
//    test_judge_cost2();
    cout << "over" << endl;
    return 0;
}*/
