/*
 * MyMD5.cpp
 *
 *  Created on: 2013-3-7
 *      Author: hust
 */
#include "MyHash.h"
#include <time.h>
MyHash::MyHash()
{

}

MyHash::~MyHash()
{

}
/*
 * Description: to calculate the hash of the message, and return it(string).
 * Input:
 * 	message: need to calculate its hash value
 * Output:
 * 	return the hash value(string) of the message.
 */
string MyHash::MD5String(const char * message)
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
string MyHash::MD5File(const char * filename)
{
    string digest;
    Weak::MD5 md5;
    FileSource(filename, true,
               new HashFilter(md5, new HexEncoder(new StringSink(digest))));
    return digest;

}
/*

int main()
{
	clock_t start, finish;
	double duration;

	start = clock();
	string message = "The string to calculate the hash value!";
	string filename = "md5file";

	//calculate string's hash value
	string digest = MyHash::MD5String(message.c_str());
	cout << "The string : " + message << "\'s hash value is:\n" << digest
			<< endl;

	string digest2 = MyHash::MD5File(filename.c_str());
	cout << "The file: " + filename << "\'s hash value is:\n" << digest2
			<< endl;

	finish = clock();
	duration = (double) (finish - start) / CLOCKS_PER_SEC;
	cout << "The cost is : " << duration << endl;
	return 0;
}
*/
