//  g++ -lcryptopp -lpthread -lboost_serialization MyAES.cpp  MyCpabe.cpp MyRSA.cpp AESKey.cpp MyHash.cpp SecByteString.cpp AttributeTree.cpp test2.cpp -o test2
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

struct timeval start1, finish1;
float duration1;

void test_judge_cost()
{
    map<string , list<int> > my_map;
    ofstream judge_cost("result/test2", ios::app);
    Credential credential(15, "A E K WX");

    string file[] =
    { "4MB", "4KB", "8KB", "16KB", "32KB", "64KB", "128KB", "256KB", "512KB"};

    for (int i = 0; i < 9; i++)
    {
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
        for (int j = 0; j < 6; j++)
        {
            // 判断用户的属性集是否满足访问策略，满足返回true；否则返回false；
            // 这里省略了将文件+metadata返回的操作
            gettimeofday(&start1, NULL);
            bool ans = judge(file[i], meta.policy, meta.blacklist, credential, my_map);
            gettimeofday(&finish1, NULL);
            duration1 = 1000000 * (finish1.tv_sec - start1.tv_sec)
                        + (finish1.tv_usec - start1.tv_usec);

            if(j>0) sum += duration1;
            judge_cost << "  judge cost is : " << duration1 << "us" << endl;
            cout << "  judge cost is : " << duration1 << "us" << endl;
        }
        sum /= 5;
        judge_cost << endl << "Average cost is : " << sum << "us" << endl << endl;
        cout << endl << "Average cost is : " << sum << "us" << endl << endl;
    }
    judge_cost << "=========The Next record!============" << endl << endl;
    judge_cost.close();
    clear_tree(my_map);
}

void test_attr_cost()
{
    map<string , list<int> > my_map;
    struct timeval start, finish;
    double duration;
    string file = "32KB";
    ofstream judge_cost("result/test3", ios::app);
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
        "Q W WW QI YY HH E R RE L1L1 23 T Y U I O P AS D F G H J K LA A Z X C V B N M ER HJ SD QQ ES EW RR",
        "Q W WW QI YY HH E R RE L1L1 23 T Y U I O P AS D F G H J K LA A Z X C V B N M ER HJ SD QQ ES EW RR 11a 11b 11c 11d 11e 11f 11g 11h 11i 11j",
        "Q W WW QI YY HH E R RE L1L1 23 T Y U I O P AS D F G H J K LA A Z X C V B N M ER HJ SD QQ ES EW RR 11a 11b 11c 11d 11e 11f 11g 11h 11i 11j 11k 11l 11m 11n 11o 11p 11q 11r 11s 11t",
        "Q W WW QI YY HH E R RE L1L1 23 T Y U I O P AS D F G H J K LA A Z X C V B N M ER HJ SD QQ ES EW RR 11a 11b 11c 11d 11e 11f 11g 11h 11i 11j 11k 11l 11m 11n 11o 11p 11q 11r 11s 11t 11u 11v 11w 11x 11y 11z 12a 12b 12c 12d",
        "Q W WW QI YY HH E R RE L1L1 23 T Y U I O P AS D F G H J K LA A Z X C V B N M ER HJ SD QQ ES EW RR 11a 11b 11c 11d 11e 11f 11g 11h 11i 11j 11k 11l 11m 11n 11o 11p 11q 11r 11s 11t 11u 11v 11w 11x 11y 11z 12a 12b 12c 12d 12e 12f 12g 12h 12i 12j 12k 12l 12m 12n",
        "Q W WW QI YY HH E R RE L1L1 23 T Y U I O P AS D F G H J K LA A Z X C V B N M ER HJ SD QQ ES EW RR 11a 11b 11c 11d 11e 11f 11g 11h 11i 11j 11k 11l 11m 11n 11o 11p 11q 11r 11s 11t 11u 11v 11w 11x 11y 11z 12a 12b 12c 12d 12e 12f 12g 12h 12i 12j 12k 12l 12m 12n 12o 12p 12q 12r 12s 12t 12u 12v 12w 12x",
        "Q W WW QI YY HH E R RE L1L1 23 T Y U I O P AS D F G H J K LA A Z X C V B N M ER HJ SD QQ ES EW RR 11a 11b 11c 11d 11e 11f 11g 11h 11i 11j 11k 11l 11m 11n 11o 11p 11q 11r 11s 11t 11u 11v 11w 11x 11y 11z 12a 12b 12c 12d 12e 12f 12g 12h 12i 12j 12k 12l 12m 12n 12o 12p 12q 12r 12s 12t 12u 12v 12w 12x 12y 12z 13a 13b 13c 13d 13e 13f 13g 13h",
    };

    for (int i = 0; i < 16; i++)
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
        for (int j = 0; j < 6; j++)
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
        sum /= 5;
        judge_cost << endl << "Average cost is : " << sum << "us" << endl
        << endl;
        cout << endl << "Average cost is : " << sum << "us" << endl
             << endl;
    }

    judge_cost << "=========The Next record!============" << endl << endl;
    judge_cost.close();
    clear_tree(my_map);
}

int main()
{
    test_judge_cost();
//    test_attr_cost();
    return 0;
}

