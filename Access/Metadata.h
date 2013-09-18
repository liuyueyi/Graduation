/*
 * metadata.h
 *
 *  Created on: 2013-4-18
 *      Author: administrator
 */

#ifndef METADATA_H_
#define METADATA_H_
// 元数据头文件
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <string>
#include <sstream>

using namespace std;

class Metadata
{
private:
    friend class boost::serialization::access;
    // When the class Archive corresponds to an output archive, the
    // & operator is defined similar to <<.  Likewise, when the class Archive
    // is a type of input archive the & operator is defined similar to >>.
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & policy;
        ar & verifyKey;
        ar & signature;
        ar & blacklist;
    }

public:
    string policy;
    string verifyKey;
    string signature;
    string blacklist;

    Metadata()
    {
    }
    Metadata(const string & pol, const string & vk, const string & sig) :
        policy(pol), verifyKey(vk), signature(sig), blacklist("")
    {
    }
    Metadata(const string & pol, const string & bl, const string & vk,
             const string & sig) :
        policy(pol), verifyKey(vk), signature(sig), blacklist(bl)
    {
    }
    ~Metadata()
    {
    }
};

#endif /* METADATA_H_ */
