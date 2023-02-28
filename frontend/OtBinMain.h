#pragma once

#include "Crypto/PRNG.h"
#include <string>

//void OPPRFRecv();
//void OPPRFSend();
//void BarkOPRFRecv();
//void BarkOPRSend();
void Channel_test();
void OPPRF3_EmptrySet_Test_Main();
void OPPRFn_EmptrySet_Test_Main();
void OPPRF2_EmptrySet_Test_Main();
void Bit_Position_Random_Test();
void OPPRFnt_EmptrySet_Test_Main();
void party3(u64 myIdx, u64 setSize, u64 nTrials);
void party2(u64 myIdx, u64 setSize);
void party(u64 myIdx, u64 nParties, u64 setSize, std::vector<block>& mSet);
void tparty(u64 myIdx, u64 nParties, u64 tParties, u64 setSize, u64 nTrials, std::vector<std::string> hostIpArr, std::string inputFilename, std::string outputFilename);
void aug_party(u64 myIdx, u64 nParties, u64 setSize,u64 opt, u64 nTrials);
void OPPRFn_Aug_EmptrySet_Test_Impl();
void OPPRFnt_EmptrySet_Test_Impl();
void BinSize(u64 setSize, std::vector<block> set, u64 psiSecParam);
void read_elements(u64** elements, u64* nelements, std::string filename);
void write_elements(std::vector<std::basic_string<char>> itemVector, std::vector<u64> elements, std::string filename);
std::vector<std::string> vec_to_string(const std::vector<u64>& vec);
void read_txt_file(std::vector<u64>& elements, const std::string& filename);
void read_csv_column(std::vector<u64>& elements, const std::string& filename);
bool file_exists(const std::string& file_name);
void GetPrimaryIp(char (&buffer)[80]);
std::string get_local_ip_address();
//void OPPRFn_EmptrySet_Test();