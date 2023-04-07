//
// Created by xiumaker on 23-3-1.
//
#include "Network/BtEndpoint.h"

#include "OPPRF/OPPRFReceiver.h"
#include "OPPRF/OPPRFSender.h"

#include <fstream>
using namespace osuCrypto;
#include "util.h"
#include "Common/Defines.h"
#include "NChooseOne/KkrtNcoOtReceiver.h"
#include "NChooseOne/KkrtNcoOtSender.h"

#include "Common/Log1.h"
#include "Common/Timer.h"
#include "Crypto/PRNG.h"
#include <iostream>
#include <string>
#include <functional>
#include <time.h>
#include <cstring>      ///< memset
#include "OtBinMain.h"

#define  numTrial 2

void party3(u64 myIdx, u64 setSize, u64 nTrials, std::vector<std::string> hostIpArr, std::string inputFilename, std::string outputFilename)
{
    u64 nParties(3);
    u64 opt = 0;
    std::fstream runtime;
    bool isNTLThreadSafe = false;

    std::vector<u64> elements; //add: 待求交集的数据
    std::vector<std::string> elementsLine; // read every line

    std::cout << "++++++++++start read_elements++++++++++" << "\n";
    // read_txt_file(elements, inputFilename);
    read_csv_column(elements, elementsLine, inputFilename);
    std::vector<std::string> itemStrVector(elements.size()); //add by 20220121: 明文元素集合
    itemStrVector = vec_to_string(elements);

    u64 offlineAvgTime(0), hashingAvgTime(0), getOPRFAvgTime(0),
            secretSharingAvgTime(0), intersectionAvgTime(0), onlineAvgTime(0);

    u64  psiSecParam = 40, bitSize = 128, numThreads = 1;
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    std::string name("psi");
    BtIOService ios(0);
    std::vector<BtEndpoint> ep(nParties);
    Timer timer;

    for(u64 i = 0, j = 0; i < myIdx && j < hostIpArr.size() && i < nParties; ++j, ++i) {
        std::cout<< "tparty() if (i < myIdx)" << std::endl;
        u32 port = 1200 + i * 100 + myIdx;//get the same port; i=1 & pIdx=2 =>port=102
        // u32 port = 1301; 200+1
        std::string remoteIp(hostIpArr[j]);
        std::cout<< "hostIp:port "<< remoteIp << ":" << port <<std::endl;
        ep[i].start(ios, remoteIp, port, false, name); //channel bwt i and pIdx, where i is sender
    }
    std::string localIp = get_local_ip_address();
    for (u64 i = 0; i < nParties; ++i)
    {
        if (i > myIdx)
        {
            std::cout<< "tparty() else if (i > myIdx)" << std::endl;
            u32 port = 1200 + myIdx * 100 + i;//get the same port; i=2 & pIdx=1 =>port=102
            // u32 port = 1200; 1201
            std::cout<< "hostIp:port "<< localIp << ":" << port <<std::endl;
            ep[i].start(ios, localIp, port, true, name); //channel bwt i and pIdx, where i is receiver
        }
    }


    std::vector<std::vector<Channel*>> chls(nParties);

    for (u64 i = 0; i < nParties; ++i)
    {
        if (i != myIdx) {
            chls[i].resize(numThreads);
            for (u64 j = 0; j < numThreads; ++j)
            {
                //chls[i][j] = &ep[i].addChannel("chl" + std::to_string(j), "chl" + std::to_string(j));
                chls[i][j] = &ep[i].addChannel(name, name);
            }
        }
    }

    PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
    PRNG prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));
    u64 expected_intersection;
    u64 num_intersection;
    double dataSent = 0, Mbps = 0, dateRecv = 0, MbpsRecv = 0;

    for (u64 idxTrial = 0; idxTrial < nTrials; idxTrial++)
    {
        std::vector<block> set(setSize);

        block blk_rand = prngSame.get<block>();
        expected_intersection = (*(u64*)&blk_rand) % setSize;

        std::cout << "==========start build set==========" << "\n";
        for(u32 i = 0; i < elements.size(); i++){
            std::cout << itemStrVector[i] << std::endl;

            std::hash<std::string> str_hash;
            time_t salt = std::time(NULL);
            std::string strHash = std::to_string(str_hash(itemStrVector[i]));

            int len = strHash.length();
            int b[4] = {};
            for ( std::string::size_type k = 0, m = 0; k < 4 && m < strHash.size(); m++ )
            {
                b[k] = b[k] << len | (unsigned char)strHash[m];
                if ( m % sizeof( *b ) == sizeof( *b ) - 1 ) k++;
            }

            block seed1 = _mm_set_epi32(b[0],b[1],b[2],b[3]);
            PRNG myPrng(seed1);
            set[i] = myPrng.get<block>();
            std::cout << set[i] << "\n";
        }
        for(u32 i = elements.size(); i < setSize; i++){
            PRNG diffPrng(_mm_set_epi32(434653, 23, myIdx * setSize + i, myIdx * setSize + i));
            set[i] = diffPrng.get<block>();
        }
        std::cout << "==========end build set==========" << "\n";

        std::vector<block> sendPayLoads(setSize);
        std::vector<block> recvPayLoads(setSize);

        //only P0 genaretes secret sharing
        if (myIdx == 0) {
            for (u64 i = 0; i < setSize; ++i)
                sendPayLoads[i] = prng.get<block>();
        }

        std::vector<KkrtNcoOtReceiver> otRecv(nParties);
        std::vector<KkrtNcoOtSender> otSend(nParties);

        OPPRFSender send;
        OPPRFReceiver recv;
        binSet bins;

        std::vector<std::thread>  pThrds(nParties);

        //##########################
        //### Offline Phasing
        //##########################

        auto start = timer.setTimePoint("start");

        bins.init(myIdx, nParties, setSize, psiSecParam, opt);
        u64 otCountSend = bins.mSimpleBins.mBins.size();
        u64 otCountRecv = bins.mCuckooBins.mBins.size();

        u64 nextNeibough = (myIdx + 1) % nParties;
        u64 prevNeibough = (myIdx - 1 + nParties) % nParties;

        for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
        {
            pThrds[pIdx] = std::thread([&, pIdx]() {
                if (pIdx == nextNeibough) {
                    //I am a sender to my next neigbour
                    send.init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountSend, otSend[pIdx], otRecv[pIdx], prng.get<block>(), false);

                }
                else if (pIdx == prevNeibough) {
                    //I am a recv to my previous neigbour
                    recv.init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountRecv, otRecv[pIdx], otSend[pIdx], ZeroBlock, false);
                }
            });
        }

        for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
            pThrds[pIdx].join();

#ifdef PRINT
        std::cout << IoStream::lock;
		if (myIdx == 0)
		{
			Log::out << "------0------" << Log::endl;
			Log::out << otSend[1].mGens[0].get<block>() << Log::endl;
			Log::out << otRecv[2].mGens[0][0].get<block>() << Log::endl;
			Log::out << otRecv[2].mGens[0][1].get<block>() << Log::endl;
		}
		if (myIdx == 1)
		{
			Log::out << "------1------" << Log::endl;
			Log::out << otRecv[0].mGens[0][0].get<block>() << Log::endl;
			Log::out << otRecv[0].mGens[0][1].get<block>() << Log::endl;
			Log::out << otSend[2].mGens[0].get<block>() << Log::endl;
		}

		if (myIdx == 2)
		{
			Log::out << "------2------" << Log::endl;
			Log::out << otRecv[1].mGens[0][0].get<block>() << Log::endl;
			Log::out << otRecv[1].mGens[0][1].get<block>() << Log::endl;
			Log::out << otSend[0].mGens[0].get<block>() << Log::endl;
		}
		std::cout << IoStream::unlock;
#endif

        auto initDone = timer.setTimePoint("initDone");

        //##########################
        //### Hashing
        //##########################
        bins.hashing2Bins(set, nParties);
        //bins.mSimpleBins.print(myIdx, true, false, false, false);
        //bins.mCuckooBins.print(myIdx, true, false, false);

        auto hashingDone = timer.setTimePoint("hashingDone");

        //##########################
        //### Online Phasing - compute OPRF
        //##########################

        pThrds.clear();
        pThrds.resize(nParties);
        for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
        {
            pThrds[pIdx] = std::thread([&, pIdx]() {
                if (pIdx == nextNeibough) {
                    //I am a sender to my next neigbour
                    send.getOPRFkeys(pIdx, bins, chls[pIdx], false);
                }
                else if (pIdx == prevNeibough) {
                    //I am a recv to my previous neigbour
                    recv.getOPRFkeys(pIdx, bins, chls[pIdx], false);

                }
            });
        }

        for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
            pThrds[pIdx].join();

        //if (myIdx == 2)
        //{
        //	//bins.mSimpleBins.print(2, true, true, false, false);
        //	bins.mCuckooBins.print(1, true, true, false);
        //	Log::out << "------------" << Log::endl;
        //}
        //if (myIdx == 1)
        //{
        //	bins.mSimpleBins.print(2, true, true, false, false);
        //	//bins.mCuckooBins.print(0, true, true, false);
        //}

        auto getOPRFDone = timer.setTimePoint("getOPRFDone");


        //##########################
        //### online phasing - secretsharing
        //##########################

        pThrds.clear();
        pThrds.resize(nParties - 1);

        if (myIdx == 0) {
        //for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
        //{
        //	pThrds[pIdx] = std::thread([&, pIdx]() {
        //		if (pIdx == 0) {
        //			send.sendSSTableBased(nextNeibough, bins, sendPayLoads, chls[nextNeibough]);
        //		}
        //		else if (pIdx == 1) {
        //			recv.recvSSTableBased(prevNeibough, bins, recvPayLoads, chls[prevNeibough]);
        //		}
        //	});
        //}
            send.sendSSTableBased(nextNeibough, bins, sendPayLoads, chls[nextNeibough]);
            recv.recvSSTableBased(prevNeibough, bins, recvPayLoads, chls[prevNeibough]);
        } else{
        /*for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
        {
        pThrds[pIdx] = std::thread([&, pIdx]() {
        if (pIdx == 0) {
        recv.recvSSTableBased(prevNeibough, bins, recvPayLoads, chls[prevNeibough]);
        }
        else if (pIdx == 1) {
        send.sendSSTableBased(nextNeibough, bins, recvPayLoads, chls[nextNeibough]);
        }
        });
        }	*/
            recv.recvSSTableBased(prevNeibough, bins, recvPayLoads, chls[prevNeibough]);
        //sendPayLoads = recvPayLoads;
            send.sendSSTableBased(nextNeibough, bins, recvPayLoads, chls[nextNeibough]);

        }

        /*for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
        pThrds[pIdx].join();*/

        auto getSSDone = timer.setTimePoint("getSSDone");

#ifdef PRINT
        std::cout << IoStream::lock;
		if (myIdx == 0)
		{
			for (int i = 0; i < 5; i++)
			{
				Log::out << sendPayLoads[i] << Log::endl;
				//Log::out << recvPayLoads[2][i] << Log::endl;
			}
			Log::out << "------------" << Log::endl;
		}
		if (myIdx == 1)
		{
			for (int i = 0; i < 5; i++)
			{
				//Log::out << recvPayLoads[i] << Log::endl;
				Log::out << sendPayLoads[i] << Log::endl;
			}
		}
		if (myIdx == 2)
		{
			for (int i = 0; i < 5; i++)
			{
				Log::out << sendPayLoads[i] << Log::endl;
			}
		}
		std::cout << IoStream::unlock;
#endif

        //##########################
        //### online phasing - compute intersection
        //##########################

        std::vector<block> mIntersection;
        std::vector<u64> mIntersectionPos;
        std::cout << "==========Begin leader exec online phasing - compute intersection==========" << "\n";
        std::vector<std::thread> sendPthrds(2);
        std::vector<u64> dummy(nParties);
        dummy[0] = 12;
        dummy[1] = 22;
        dummy[2] = 32;
        std::vector<u64> revDummy(nParties);
        std::mutex printMtx1, printMtx2;
        if (myIdx == 0){
            for (u64 i = 0; i < setSize; ++i)
            {
                if (!memcmp((u8*)&sendPayLoads[i], &recvPayLoads[i], bins.mMaskSize))
                {
                    mIntersection.push_back(set[i]);
                    mIntersectionPos.push_back(i);
                    std::cout << set[i] << std::endl;
                }
            }
            Log::out << "mIntersection.size(): " << mIntersection.size() << Log::endl;

            std::vector<u8> sendValue = to_bytes(mIntersectionPos);
            std::vector<u8> sendLength(8); // 创建一个大小为8的向量
            for (int i = 0; i < 8; i++) {
                sendLength[i] = uint8_t(sendValue.size() >> (8 * i)); // 将x的每个字节复制到向量中
            }
            chls[1][0]->send(&sendLength[0],8);
            chls[2][0]->send(&sendLength[0],8);

            chls[1][0]->send(&sendValue[0], sendValue.size());
            chls[2][0]->send(&sendValue[0], sendValue.size());
            std::cout << "/////""""" << sendValue.size() << std::endl;
        }else{

            std::vector<u8> recvLength(8);
            chls[0][0]->recv(&recvLength[0], 8);

            uint64_t length = 0; // 初始化为0
            for (int i = 0; i < 8; i++) {
                length |= uint64_t(recvLength[i]) << (8 * i); // 将向量的每个字节移位并合并到y中
            }

            std::vector<u8> recvValue(length);
            chls[0][0]->recv(&recvValue[0], length);
            mIntersectionPos = from_bytes(recvValue);
//            std::cout << "output: " << static_cast<int16_t>(revDummy[0]) << std::endl;
//            std::cout << "output: " << static_cast<int16_t>(revDummy[1]) << std::endl;
        }




        auto getIntersection = timer.setTimePoint("getIntersection");

        num_intersection = mIntersection.size();
        std::cout << "交集密文：" << "\n";
        for(auto &&intersection : mIntersection) {
            std::cout << intersection << "\n";
        }
        std::cout << "交集原文：" << "\n";
        for(auto &&intersectionPos : mIntersectionPos) {
            std::cout << intersectionPos << std::endl;
            std::cout << elementsLine[intersectionPos] << "\n";
        }
        write_elements(elementsLine, mIntersectionPos, outputFilename);



        //if (myIdx == 0) {
        auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(initDone - start).count();
        auto hashingTime = std::chrono::duration_cast<std::chrono::milliseconds>(hashingDone - initDone).count();
        auto getOPRFTime = std::chrono::duration_cast<std::chrono::milliseconds>(getOPRFDone - hashingDone).count();
        auto secretSharingTime = std::chrono::duration_cast<std::chrono::milliseconds>(getSSDone - getOPRFDone).count();
        auto intersectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(getIntersection - getSSDone).count();

        double onlineTime = hashingTime + getOPRFTime + secretSharingTime + intersectionTime;

        double time = offlineTime + onlineTime;
        time /= 1000;


        dataSent = 0;
        dateRecv = 0;
        Mbps = 0;
        MbpsRecv = 0;

        for (u64 i = 0; i < nParties; ++i)
        {
            if (i != myIdx) {
                chls[i].resize(numThreads);
                for (u64 j = 0; j < numThreads; ++j)
                {
                    dataSent += chls[i][j]->getTotalDataSent();
                    dateRecv += chls[i][j]->getTotalDataRecv();
                }
            }
        }

        Mbps = dataSent * 8 / time / (1 << 20);
        MbpsRecv = dataSent * 8 / time / (1 << 20);

        for (u64 i = 0; i < nParties; ++i)
        {
            if (i != myIdx) {
                chls[i].resize(numThreads);
                for (u64 j = 0; j < numThreads; ++j)
                {
                    chls[i][j]->resetStats();
                }
            }
        }


        Log::out << "#Output Intersection: " << num_intersection << Log::endl;
        Log::out << "#Expected Intersection: " << expected_intersection << Log::endl;

//        std::cout << "(ROUND OPPRF) numParty: " << nParties
//                  << "  setSize: " << setSize << "\n"
//                  << "offlineTime:  " << offlineTime << " ms\n"
//                  << "hashingTime:  " << hashingTime << " ms\n"
//                  << "getOPRFTime:  " << getOPRFTime << " ms\n"
//                  << "secretSharing:  " << secretSharingTime << " ms\n"
//                  << "intersection:  " << intersectionTime << " ms\n"
//                  << "onlineTime:  " << onlineTime << " ms\n"
//                  //<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
//                  << "Total time: " << time << " s\n"
//                  //<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
//                  //<< "\t Recv: " << (dateRecv / std::pow(2.0, 20)) << " MB\n"
//                  << "------------------\n";


        offlineAvgTime += offlineTime;
        hashingAvgTime += hashingTime;
        getOPRFAvgTime += getOPRFTime;
        secretSharingAvgTime += secretSharingTime;
        intersectionAvgTime += intersectionTime;
        onlineAvgTime += onlineTime;
        //}
    }

    //if (myIdx == 0) {
    double avgTime = (offlineAvgTime + onlineAvgTime);
    avgTime /= 1000;
//    std::cout << "=========avg==========\n"
//              << "(ROUND OPPRF) numParty: " << nParties
//              << "  setSize: " << setSize
//              << "  nTrials:" << nTrials << "\n"
//              << "offlineTime:  " << offlineAvgTime / nTrials << " ms\n"
//              << "hashingTime:  " << hashingAvgTime / nTrials << " ms\n"
//              << "getOPRFTime:  " << getOPRFAvgTime / nTrials << " ms\n"
//              << "secretSharing:  " << secretSharingAvgTime / nTrials << " ms\n"
//              << "intersection:  " << intersectionAvgTime / nTrials << " ms\n"
//              << "onlineTime:  " << onlineAvgTime / nTrials << " ms\n"
//              //<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
//              << "Total time: " << avgTime/ nTrials << " s\n"
//              //<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
//              //<< "\t Recv: " << (dateRecv / std::pow(2.0, 20)) << " MB\n"
//              << "------------------\n";

//    runtime << "(ROUND OPPRF) numParty: " << nParties
//            << "  setSize: " << setSize
//            << "  nTrials:" << nTrials << "\n"
//            << "offlineTime:  " << offlineAvgTime / nTrials << " ms\n"
//            << "hashingTime:  " << hashingAvgTime / nTrials << " ms\n"
//            << "getOPRFTime:  " << getOPRFAvgTime / nTrials << " ms\n"
//            << "secretSharing:  " << secretSharingAvgTime / nTrials << " ms\n"
//            << "intersection:  " << intersectionAvgTime / nTrials << " ms\n"
//            << "onlineTime:  " << onlineAvgTime / nTrials << " ms\n"
//            //<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
//            << "Total time: " << avgTime / nTrials << " s\n"
//            //<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
//            //<< "\t Recv: " << (dateRecv / std::pow(2.0, 20)) << " MB\n"
//            << "------------------\n";
//    runtime.close();
    //}

    for (u64 i = 0; i < nParties; ++i)
    {
        if (i != myIdx)
        {
            for (u64 j = 0; j < numThreads; ++j)
            {
                chls[i][j]->close();
            }
        }
    }

    for (u64 i = 0; i < nParties; ++i)
    {
        if (i != myIdx)
            ep[i].stop();
    }


    ios.stop();
}

// Convert a vector of uint64_t to a vector of uint8_t
std::vector<u8> to_bytes(const std::vector<uint64_t>& input) {
    std::vector<u8> output;
    output.reserve(input.size() * 8);
    for (auto x : input) {
        for (int i = 0; i < 8; i++) {
            output.push_back(static_cast<u8>(x & 0xFF));
            x >>= 8;
        }
    }
    return output;
}

// Convert a vector of uint8_t to a vector of uint64_t
std::vector<u64> from_bytes(const std::vector<u8>& input) {
    std::vector<u64> output;
    output.reserve(input.size() / 8);
    for (size_t i = 0; i < input.size(); i += 8) {
        u64 x = 0;
        for (int j = 7; j >= 0; j--) {
            x <<= 8;
            x |= input[i + j];
        }
        output.push_back(x);
    }
    return output;
}