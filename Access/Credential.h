/*
 * crediential.h
 *
 *  Created on: 2013-4-18
 *      Author: administrator
 */

#ifndef CREDIENTIAL_H_
#define CREDIENTIAL_H_

// 用户证书类的声明
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <string>

using std::string;

class Credential
{
private:
    friend class boost::serialization::access;
    // When the class Archive corresponds to an output archive, the
    // & operator is defined similar to <<.  Likewise, when the class Archive
    // is a type of input archive the & operator is defined similar to >>.
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & UID;
        ar & attributes;
    }

public:
    // 用户的唯一标识
    int UID;
    // 用户属性集
    string attributes;

    Credential()
    {
        UID = -1;
    }
    Credential(int id, string attrs) :
        UID(id), attributes(attrs)
    {
    }

    ~Credential()
    {
    }
};

#endif /* CREDIENTIAL_H_ */
