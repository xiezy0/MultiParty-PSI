
#include <iostream>
#include "Network/BtChannel.h"
#include "Network/BtEndpoint.h"

using namespace std;
#include "Common/Defines.h"
using namespace osuCrypto;

#include "OtBinMain.h"
#include "bitPosition.h"

#include <numeric>
#include <string>
#include "Common/Log.h"

#include <boost/algorithm/string/classification.hpp> // Include boost::for is_any_of
#include <boost/algorithm/string/split.hpp> // Include for boost::split
//int miraclTestMain();


void usage(const char* argv0)
{
	std::cout << "Error! Please use:" << std::endl;
	std::cout << "\t 1. For unit test: " << argv0 << " -u" << std::endl;
	std::cout << "\t 2. For simulation (5 parties <=> 5 terminals): " << std::endl;;
	std::cout << "\t\t each terminal: " << argv0 << " -n 5 -t 2 -m 12 -p [pIdx]" << std::endl;

}
int main(int argc, char** argv)
{

	//myCuckooTest_stash();
	//Table_Based_Random_Test();
	//OPPRF2_EmptrySet_Test_Main();
	//OPPRFn_EmptrySet_Test_Main();
	//Transpose_Test();
	//OPPRF3_EmptrySet_Test_Main();
	//OPPRFnt_EmptrySet_Test_Main();
	//OPPRFnt_EmptrySet_Test_Main();
	//OPPRFn_Aug_EmptrySet_Test_Impl();
	//OPPRFnt_EmptrySet_Test_Main();
	//OPPRF2_EmptrySet_Test_Main();
	//return 0;

	u64 trials = 1;
	u64 pSetSize = 5, psiSecParam = 40, bitSize = 128;

	u64 nParties, tParties, opt_basedOPPRF, setSize, isAug;

	u64 roundOPPRF;

	std::string inputFilename, outputFilename;

	std::string hostIpStr;
	std::vector<std::string> hostIpArr;

	switch (argc) {
	case 2: //unit test
		if (argv[1][0] == '-' && argv[1][1] == 'u') {
            OPPRFnt_EmptrySet_Test_Main();
        }
		break;

	case 7: //2PSI
		if (argv[1][0] == '-' && argv[1][1] == 'n') {
            nParties = atoi(argv[2]);
        } else {
			usage(argv[0]);
			return 0;
		}

		if (argv[3][0] == '-' && argv[3][1] == 'm') {
            setSize = 1 << atoi(argv[4]);
        } else {
			usage(argv[0]);
			return 0;
		}

		if (argv[5][0] == '-' && argv[5][1] == 'p') {
			u64 pIdx = atoi(argv[6]);
			if (nParties == 2) {
                party2(pIdx, setSize);
            } else {
				usage(argv[0]);
				return 0;
			}
		} else {
			usage(argv[0]);
			return 0;
		}
		break;
	// case 9: //nPSI or optimized 3PSI
	case 13: //nPSI or optimized 3PSI
		cout << "nPSI or optimized 3PSI: argc=15\n";
		// comment by 20211231
		// -n：number of parties
		if (argv[1][0] == '-' && argv[1][1] == 'n') {
            // comment by 20211231
            // int atoi(const char *str) 把参数 str 所指向的字符串转换为一个整数（类型为 int 型）
            // nParties：参与方数量
            nParties = atoi(argv[2]);
        } else {
			usage(argv[0]);
			return 0;
		}

		// comment by 20220104
		// -m：set size
		if (argv[3][0] == '-' && argv[3][1] == 'm') {
            setSize = 1 << atoi(argv[4]); // 1左移x位，即为2^x
        } else {
			usage(argv[0]);
			return 0;
		}

		if (argv[7][0] == '-' && argv[7][1] == 'i') {
			inputFilename = argv[8];
			cout << "argv[10] filename:"<< inputFilename <<"\n";
		} else {
			usage(argv[0]);
			return 0;
		}

        if (argv[9][0] == '-' && argv[9][1] == 'o') {
            outputFilename = argv[10];
            cout << "argv[10] filename:"<< outputFilename <<"\n";
        } else {
            usage(argv[0]);
            return 0;
        }

		if (argv[11][0] == '-' && argv[11][1] == 'i' && argv[11][2] == 'p') {
			hostIpStr = argv[12];
			boost::split(hostIpArr, hostIpStr, boost::is_any_of(","), boost::token_compress_on);
			for(auto &&hostIp : hostIpArr) {
				std::cout << hostIp << "\n";
			}
		} else {
			usage(argv[0]);
			return 0;
		}

		// comment by 20220104
		// -p：party ID
		if (argv[5][0] == '-' && argv[5][1] == 'p') {
			u64 pIdx = atoi(argv[6]);
			if (roundOPPRF == 1 && nParties == 3) {
				//cout << nParties  << " " << roundOPPRF << " " << setSize << " " << pIdx << "\n";
				//party3(pIdx, setSize, trials);
			} else if (strcmp(argv[2], "3") == 0) {
				cout << " log log: =======================exec tparty=======================\n";
				cout << "pIdx:" << pIdx << " nParties:" << nParties << " tParties:" << tParties << " setSize:" << setSize << " trials:" << trials << " filename:" << inputFilename << " hostIpArr.size():" << hostIpArr.size() << "\n";
				//tparty(pIdx, nParties, tParties, setSize, trials, hostIpArr, inputFilename, outputFilename);
                party3(pIdx, setSize, trials, hostIpArr, inputFilename, outputFilename);
			}
		} else {
			usage(argv[0]);
			return 0;
		}
		break;
	}

	return 0;
}
