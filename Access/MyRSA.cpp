/*
 * MyRSA.cpp
 *
 *  Created on: 2013-3-7
 *      Author: hust
 */
#include "MyRSA.h"
#include <time.h>
MyRSA::MyRSA()
{

}

MyRSA::~MyRSA()
{

}
/*
 * Description: this function is used to calcuate the string 'message' 's hash value
 * Input:
 * 	message: the init string to be hashed
 * Output:
 * 	return the hash of the parameter
 */
string MyRSA::MD5(const char * message)
{
    string digest;
    Weak::MD5 md5;
    StringSource(message, true,
                 new HashFilter(md5, new HexEncoder(new StringSink(digest))));
    return digest;
}
/*
 * Description: to calculate the hash of the file and return the hash value(string)
 * Input:
 * 	filename: the file to be calculated the hash value
 * Output:
 *  return the hash value of the file and its type is string
 */
string MyRSA::MD5File(const char * filename)
{
    string digest;
    Weak::MD5 md5;
    FileSource(filename, true,
               new HashFilter(md5, new HexEncoder(new StringSink(digest))));
    return digest;

}

/*
 * Description: generate the RSA public key and private key in separate file
 * Input:
 *  KeyLength: the length of the key, such as 1024...
 *  privFilename: private key file name you want to store the private key
 *  pubFilename: public key file name you want to store the public key
 * Output:
 * 	nothing
 */
void MyRSA::GenerateRSAKey(unsigned int keyLength, const char *privFilename,
                           const char *pubFilename)
{
    RSAES_OAEP_SHA_Decryptor priv(_rng, keyLength);
    HexEncoder privFile(new FileSink(privFilename));
    priv.DEREncode(privFile);
    privFile.MessageEnd();

    RSAES_OAEP_SHA_Encryptor pub(priv);
    HexEncoder pubFile(new FileSink(pubFilename));
    pub.DEREncode(pubFile);
    pubFile.MessageEnd();
}

/*
 * Description: this function is used to encrypt the string 'plainText' with the
 * 				private key, and return the cipher
 * Input:
 * 	pubFilename: the public key
 * 	message: the string to be encrypted
 * OutPut:
 *  return the cipher
 */
string MyRSA::Encrypt(const char * pubFilename, const char * message)
{
    FileSource pubFile(pubFilename, true, new HexDecoder);

    RSAES_OAEP_SHA_Encryptor pub(pubFile);
    string result;
    StringSource(message, true,
                 new PK_EncryptorFilter(_rng, pub,
                                        new HexEncoder(new StringSink(result))));
    return result;
}
/*
 * Description: decrypt the cipher with the private key
 * Input:
 * 	privFilename: the private key file
 * 	ciphertext: the string to be decrypted
 * Output:
 * 	return the decrypted string
 */
string MyRSA::Decrypt(const char * privFilename, const char * ciphertext)
{
    FileSource privFile(privFilename, true, new HexDecoder);

    RSAES_OAEP_SHA_Decryptor priv(privFile);
    string result;
    StringSource(ciphertext, true,
                 new HexDecoder(
                     new PK_DecryptorFilter(_rng, priv,
                                            new StringSink(result))));
    return result;
}

/*
 * Description: sign the file with the private key, and generate the signature file
 * Input:
 *  privFilename: the private key file
 *  messageFilename: the file to be signed
 *  signatureFilename: the signature file to be generated
 * Output:
 * 	nothing
 */
void MyRSA::SignFile(const char * privFilename, const char *messageFilename,
                     const char * signatureFilename)
{
    FileSource priFile(privFilename, true, new HexDecoder);
    RSASS<PKCS1v15, SHA>::Signer priv(priFile);
    FileSource f(messageFilename, true,
                 new SignerFilter(_rng, priv,
                                  new HexEncoder(new FileSink(signatureFilename))));
}

/*
 * Description: verify the file with the public key, and return the answer
 * Input:
 *  pubFilename: the publicFilename
 *  messageFilename: the init message file, and it should be not changed
 *  signatureFilename: the SignFile function generate, and it's used to verify if the message
 *  					file is the original one
 * Output:
 * 	if the message file match the signature file, return true; else return false
 */
bool MyRSA::VerifyFile(const char * pubFilename, const char * messageFilename,
                       const char * signatureFilename)
{
    FileSource pubFile(pubFilename, true, new HexDecoder);
    RSASS<PKCS1v15, SHA>::Verifier pub(pubFile);

    FileSource signatureFile(signatureFilename, true, new HexDecoder);
    if (signatureFile.MaxRetrievable() != pub.SignatureLength())
        return false;
    SecByteBlock signature(pub.SignatureLength());
    signatureFile.Get(signature, signature.size());

    VerifierFilter *verifierFilter = new VerifierFilter(pub);
    verifierFilter->Put(signature, pub.SignatureLength());
    FileSource f(messageFilename, true, verifierFilter);

    return verifierFilter->GetLastResult();
}

/*
 * Description: sign the string with the private key, and generate the signature
 * Input:
 *  privFilename: the private key file
 *  message: the string to be signed
 * Output:
 * 	return the SecByteBlock signature
 */
SecByteBlock MyRSA::SignString(const char * privFilename, const char * message)
{
    // calculate the md5(HASH) of the message
    string digest = MD5(message);
    FileSource priFile(privFilename, true, new HexDecoder);
    RSASSA_PKCS1v15_SHA_Signer priv(priFile);

    // Create signature space
    size_t length = priv.MaxSignatureLength();
    SecByteBlock signature(length);

    // sign message
    priv.SignMessage(_rng, (const byte*) digest.c_str(), digest.length(),
                     signature);

    return signature;
}
/*
 * Description: verify the file with the public key, and return the answer
 * Input:
 *  pubFilename: the publicFilename
 *  message: the original message, and it should be not changed
 *  signature: the SignString function returned, and it's used to verify if the message
 *  		   is the original one
 * Output:
 * 	if the message match the signature , return true; else return false
 */
bool MyRSA::VerifyString(const char * pubFilename, const char * message,
                         const SecByteBlock & signature)
{
    // calculate the md5 of the message first
    string digest = MD5(message);
    FileSource pubFile(pubFilename, true, new HexDecoder);
    RSASSA_PKCS1v15_SHA_Verifier verifier(pubFile);

    bool result = verifier.VerifyMessage((const byte*) digest.c_str(),
                                         digest.length(), signature, signature.size());
    return result;
}

/*
 int main() {
 char privFilename[128] = "prvKey", pubFilename[128] = "pubKey";
 unsigned int keyLength = 1024;
 clock_t start, finish;
 double duration;


 //	cout << "Key length in bits: ";
 //	cin >> keyLength;

 //	cout << "\nSave private key to file: ";
 //	cin >> privFilename;

 //	cout << "\nSave public key to file: ";
 //	cin >> pubFilename;


 MyRSA rsa;


 start = clock();
 cout << "============encrypt and decrypt================" << endl;
 rsa.GenerateRSAKey(keyLength, privFilename, pubFilename);
 string message = "hello world, i am a student from huazhong university of science and technology!";
 string ciphertext = rsa.Encrypt(pubFilename, message.c_str());
 cout << "The cipher is : " << ciphertext << endl;

 string decrypted = rsa.Decrypt(privFilename, ciphertext.c_str());
 cout << "The recover is : " << decrypted << endl;

 finish = clock();
 duration = (double) (finish - start) / CLOCKS_PER_SEC;
 cout << "The cost is : " << duration << " seconds" << endl;


 cout << "==============sign file================" << endl;
 start = clock();
 string messageFilename = "signTest";
 string signatureFilename = "signature";
 rsa.SignFile(privFilename, messageFilename.c_str(),
 signatureFilename.c_str());

 if (rsa.VerifyFile(pubFilename, messageFilename.c_str(),
 signatureFilename.c_str())) {
 cout << "verify correct!" << endl;
 } else
 cout << "verify error!" << endl;

 finish = clock();
 duration = (double) (finish - start) / CLOCKS_PER_SEC;
 cout << "The sign file cost is : " << duration << " seconds" << endl;


 cout << "============sign string=================" << endl;
 start = clock();
 string plainText = "Sign me, i am a student from huazhong university of science and technology!";

 SecByteBlock signature = rsa.SignString(privFilename, plainText.c_str());
 cout << "The Signature size is : " << signature.size() << endl;

 //cout << endl << "The signature is : " << signature << endl << endl;

 // save the signature to the file
 //ofstream signatureFile("signatureFile");
 //if(signatureFile.is_open() )
 //{
 //	for(int i = 0; i < signature.get
 //}

 if (rsa.VerifyString(pubFilename, plainText.c_str(), signature)) {
 cout << "Verify correct!" << endl;
 } else {
 cout << "Verify wrong!" << endl;
 }

 finish = clock();
 duration = (double) (finish - start) / CLOCKS_PER_SEC;
 cout << "The sign string cost is : " << duration << " seconds" << endl;
 return 0;
 }
 */
