/*
 * AESKey.h
 *
 *  Created on: 2013-4-22
 *      Author: administrator
 */

#ifndef AESKEY_H_
#define AESKEY_H_

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include "MyAES.h"
#include "SecByteString.h"

class AESKey
{
private:
    friend class boost::serialization::access;
    // When the class Archive corresponds to an output archive, the
    // & operator is defined similar to <<.  Likewise, when the class Archive
    // is a type of input archive the & operator is defined similar to >>.
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & key;
        ar & iv;
        ar & size;
    }

public:
    std::string key;
    std::string iv;
    int size;

    AESKey();
    AESKey(byte k[], byte v[], int sz);
    void GenerateKey();
};

#endif /* AESKEY_H_ */
