//============================================================================
// Name        : MyAES.cpp
// Author      : hust
// Version     :
// Copyright   : 1.0
// Description : 本类将AES的加密，解密函数封装，直接调用即可对string进行加密or解密
//				 另外，构造MyAES类的时候，传入参数key, iv, key_length
//				 待解决：编写一个生成密钥的函数，即需要 KeyGenerate(Random random);
// reference   : http://www.codeproject.com/Articles/21877/Applied-Crypto-Block-Ciphers
//============================================================================

#include "MyAES.h"
#include <time.h>
MyAES::MyAES()
{

}

MyAES::MyAES(byte * key1, byte * iv1, int key_length1)
{
    SetKey(key1, iv1, key_length1);
}

MyAES::~MyAES()
{

}

void MyAES::GenerateKey()
{
    AutoSeededRandomPool rnd;
    byte key1[AES::DEFAULT_KEYLENGTH];
    rnd.GenerateBlock(key1, AES::DEFAULT_KEYLENGTH);

    // Generate a random IV
    byte iv1[AES::BLOCKSIZE];
    rnd.GenerateBlock(iv1, AES::BLOCKSIZE);

    SetKey(key1, iv1, 16);
}

void MyAES::SetKey(byte * key1, byte * iv1, int length1)
{
    this->key = key1;
    this->iv = iv1;
    this->key_length = length1;
}

/*
 * Description: use key to encrypt 'plainText', return the cipher
 * Input:
 * 	plainText: the string need to be encrypted
 * OutPUt:
 * 	return the cipher
 */
string MyAES::Encrypt(const string &plainText)
{
    string cipher;
    CBC_Mode<AES>::Encryption aesEncryptor(key, key_length, iv);
//	AESEncryption aesEncryptor; //加密器
//	aesEncryptor.SetKey( key, key_length );  //设定加密密钥
    StringSource(plainText, true,
                 new StreamTransformationFilter(aesEncryptor,
                         new StringSink(cipher)));
    return cipher;
}

/*
 * Description: use the same key to decrypt "cipher" and return the plainText
 * Input:
 * 	cipher: the string to be decrypted
 * Output:
 * 	return the recover
 */
string MyAES::Decrypt(const string & cipher)
{
    string recover;
    CBC_Mode<AES>::Decryption aesDecryptor(key, key_length, iv);
    //AESDecryption aesDecryptor; //解密器
    //aesDecryptor.SetKey( key, key_length );  //设定加密密钥
    StringSource(cipher, true,
                 new StreamTransformationFilter(aesDecryptor,
                         new StringSink(recover)));
    return recover;
}

/*
 * Description: use the key to encrypt the 'inFilename' and store the cipher in 'outFilname'
 * Input:
 *  inFilename: the file need to be encrypted!
 *  outFilename: the encrypted file
 * OutPut:
 *  if encrypt success, return true, or return false
 * Others: the function should delete the file : 'inFilename', however I note it
 */
bool MyAES::EncryptFile(const string & inFilename, const string & outFilename)
{
    // check if the file 'inFilename' exists.
    if (access(inFilename.c_str(), 0) == -1)
    {
        cout << "The file " << inFilename << " is not exist! " << endl;
        return false;
    }
    // file exists, the encrypt the file
    CBC_Mode<AES>::Encryption aesEncryptor(key, key_length, iv);

    FileSource(inFilename.c_str(), true,
               new StreamTransformationFilter(aesEncryptor,
                       new FileSink(outFilename.c_str())));
    // remove the file 'inFilename'
    // if(remove(inFilename) == 0) cout << "remove file succeed! " << endl;
    // 		else cout << "fail to remove the file " << inFilname << endl;
    // use function remove(), you have to add #include <cstdio> in the .h file
    return true;
}

/*
 * Description: use the same key to decrypt the 'decFilename' and create recoverFile
 * Input:
 * 	decFilename: the encrypted file name
 * 	recoverFilename: the decrypted file name
 * OutPut:
 * 	if decrypted the file successful, return true, else return false
 * Others: we should also delete the file 'decFilename'
 */
bool MyAES::DecryptFile(const string & decFilename,
                        const string & recoverFilename)
{
    // check if the file 'decFilename' exists!
    if (access(decFilename.c_str(), 0) == -1)
    {
        cout << "The file " << decFilename << " is not exist! " << endl;
        return false;
    }
    // exist , then decrypt the file
    CBC_Mode<AES>::Decryption aesDecryptor(key, key_length, iv);
    FileSource(decFilename.c_str(), true,
               new StreamTransformationFilter(aesDecryptor,
                       new FileSink(recoverFilename.c_str())));
    return true;
}

/*

 int main() {

 //	byte key[]	= {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,	0x01,0x02, 0x03,0x04,0x05,0x06,0x07,0x08};
 //	//AES::DEFAULT_KEYLENGTH
 //	byte iv[]	= {0x01,0x02,0x03,0x03,0x03,0x03,0x03,0x03,	0x03,0x03, 0x01,0x02,0x03,0x03,0x03,0x03};
 //	int keysize = 16;


 // generate the key
 AutoSeededRandomPool rnd;
 byte key[AES::DEFAULT_KEYLENGTH];
 rnd.GenerateBlock( key, AES::DEFAULT_KEYLENGTH);

 // Generate a random IV
 byte iv[AES::BLOCKSIZE];
 rnd.GenerateBlock(iv, AES::BLOCKSIZE);

 int keysize = 16;

 string plainText = "Hello World!";

 clock_t start , finish;
 double duration;
 start = clock();

 MyAES aes(key, iv, keysize);

 cout << "AES parameters: " << endl;
 cout << "The algorithm name is : " << AES::StaticAlgorithmName() << endl;
 cout << "The iv is : " << aes.iv << endl;
 cout << "The key is : " << aes.key << endl;
 cout << "The key length is : " << aes.key_length << endl;

 string cipher = aes.Encrypt(plainText);
 cout << "The cipher is : " << cipher << endl;

 string recover = aes.Decrypt(cipher);
 cout << "The recover is : " << recover << endl;

 cout << "=====================" << endl;

 // encrypt the file and decrypt it
 string inFilename = "aesTest";
 string outFilename = "aesEncrypt";
 string recoverFilename = "aesRecover";

 if(aes.EncryptFile(inFilename, outFilename)){
 cout << "*__*" << endl << "Encrypt succeed!" << endl;
 if(aes.DecryptFile(outFilename, recoverFilename)){
 cout << "*__*" << endl << "Recover succeed!" << endl;
 } else
 cout << ")__(" << endl << "Recover failed!" << endl;
 } else
 cout << ")__(" << endl << "Encrypt failed!" << endl;



 finish = clock();
 duration = (double)(finish - start) / CLOCKS_PER_SEC;
 cout << "the cost is : " << duration << endl;

 return 0;
 }

 */
