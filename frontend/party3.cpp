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

#include "NChooseOne/Oos/OosNcoOtReceiver.h"
#include "NChooseOne/Oos/OosNcoOtSender.h"
#include "Common/Log.h"
#include "Common/Log1.h"
#include "Common/Timer.h"
#include "Crypto/PRNG.h"
#include "Crypto/Commit.h"
#include <numeric>
#include <iostream>
#include <string>
#include <sstream>
#include <functional>
#include <unordered_map>
#include <time.h>
#include <cstring>      ///< memset
#include <errno.h>      ///< errno
#include <sys/socket.h> ///< socket
#include <netinet/in.h> ///< sockaddr_in
#include <arpa/inet.h>  ///< getsockname
#include <unistd.h>     ///< close
#include <ifaddrs.h>
#include "OtBinMain.h"

//#define OOS
// #define PRINT
// #define PRINT_INPUT_ELEMENTS
#define pows  { 16/*8,12,,20*/ }
#define threadss {1/*1,4,16,64*/}
#define  numTrial 2

void party3(u64 myIdx, u64 setSize, u64 nTrials)
{
    u64 nParties(3);
    u64 opt = 0;
    std::fstream runtime;
    bool isNTLThreadSafe = false;
    if (myIdx == 0)
        runtime.open("./runtime3.txt", runtime.trunc | runtime.out);

    u64 offlineAvgTime(0), hashingAvgTime(0), getOPRFAvgTime(0),
            secretSharingAvgTime(0), intersectionAvgTime(0), onlineAvgTime(0);

    u64  psiSecParam = 40, bitSize = 128, numThreads = 1;
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    std::string name("psi");
    BtIOService ios(0);

    int btCount = nParties;
    std::vector<BtEndpoint> ep(nParties);

    u64 offlineTimeTot(0);
    u64 onlineTimeTot(0);
    Timer timer;

    for (u64 i = 0; i < nParties; ++i)
    {
        if (i < myIdx)
        {
            u32 port = 1120 + i * 100 + myIdx;//get the same port; i=1 & pIdx=2 =>port=102
            ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
        }
        else if (i > myIdx)
        {
            u32 port = 1120 + myIdx * 100 + i;//get the same port; i=2 & pIdx=1 =>port=102
            ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
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

        for (u64 i = 0; i < expected_intersection; ++i)
        {
            set[i] = prngSame.get<block>();
        }

        for (u64 i = expected_intersection; i < setSize; ++i)
        {
            set[i] = prngDiff.get<block>();
        }

        std::vector<block> sendPayLoads(setSize);
        std::vector<block> recvPayLoads(setSize);

        //only P0 genaretes secret sharing
        if (myIdx == 0)
        {
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

        if (myIdx == 0)
        {
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
        }
        else
        {
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

        std::vector<u64> mIntersection;

        if (myIdx == 0) {


            for (u64 i = 0; i < setSize; ++i)
            {
                if (!memcmp((u8*)&sendPayLoads[i], &recvPayLoads[i], bins.mMaskSize))
                {
                    mIntersection.push_back(i);
                }
            }
            Log::out << "mIntersection.size(): " << mIntersection.size() << Log::endl;
        }
        auto getIntersection = timer.setTimePoint("getIntersection");

        num_intersection = mIntersection.size();


        if (myIdx == 0) {
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

            std::cout << "(ROUND OPPRF) numParty: " << nParties
                      << "  setSize: " << setSize << "\n"
                      << "offlineTime:  " << offlineTime << " ms\n"
                      << "hashingTime:  " << hashingTime << " ms\n"
                      << "getOPRFTime:  " << getOPRFTime << " ms\n"
                      << "secretSharing:  " << secretSharingTime << " ms\n"
                      << "intersection:  " << intersectionTime << " ms\n"
                      << "onlineTime:  " << onlineTime << " ms\n"
                      //<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
                      << "Total time: " << time << " s\n"
                      //<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
                      //<< "\t Recv: " << (dateRecv / std::pow(2.0, 20)) << " MB\n"
                      << "------------------\n";


            offlineAvgTime += offlineTime;
            hashingAvgTime += hashingTime;
            getOPRFAvgTime += getOPRFTime;
            secretSharingAvgTime += secretSharingTime;
            intersectionAvgTime += intersectionTime;
            onlineAvgTime += onlineTime;
        }
    }

    if (myIdx == 0) {
        double avgTime = (offlineAvgTime + onlineAvgTime);
        avgTime /= 1000;
        std::cout << "=========avg==========\n"
                  << "(ROUND OPPRF) numParty: " << nParties
                  << "  setSize: " << setSize
                  << "  nTrials:" << nTrials << "\n"
                  << "offlineTime:  " << offlineAvgTime / nTrials << " ms\n"
                  << "hashingTime:  " << hashingAvgTime / nTrials << " ms\n"
                  << "getOPRFTime:  " << getOPRFAvgTime / nTrials << " ms\n"
                  << "secretSharing:  " << secretSharingAvgTime / nTrials << " ms\n"
                  << "intersection:  " << intersectionAvgTime / nTrials << " ms\n"
                  << "onlineTime:  " << onlineAvgTime / nTrials << " ms\n"
                  //<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
                  << "Total time: " << avgTime/ nTrials << " s\n"
                  //<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
                  //<< "\t Recv: " << (dateRecv / std::pow(2.0, 20)) << " MB\n"
                  << "------------------\n";

        runtime << "(ROUND OPPRF) numParty: " << nParties
                << "  setSize: " << setSize
                << "  nTrials:" << nTrials << "\n"
                << "offlineTime:  " << offlineAvgTime / nTrials << " ms\n"
                << "hashingTime:  " << hashingAvgTime / nTrials << " ms\n"
                << "getOPRFTime:  " << getOPRFAvgTime / nTrials << " ms\n"
                << "secretSharing:  " << secretSharingAvgTime / nTrials << " ms\n"
                << "intersection:  " << intersectionAvgTime / nTrials << " ms\n"
                << "onlineTime:  " << onlineAvgTime / nTrials << " ms\n"
                //<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
                << "Total time: " << avgTime / nTrials << " s\n"
                //<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
                //<< "\t Recv: " << (dateRecv / std::pow(2.0, 20)) << " MB\n"
                << "------------------\n";
        runtime.close();
    }

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