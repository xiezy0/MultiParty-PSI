# Programmable Oblivious PRF & multi-party PSI
This is the implementation of our [CCS 2017](http://dl.acm.org/xxx)  paper: **Practical Multi-party Private Set Intersection from Symmetric-Key Techniques**[[ePrint](https://eprint.iacr.org/2017/xxx)].

Evaluating on a single Intel Xeon server (`2 36-cores Intel Xeon CPU E5-2699 v3 @ 2.30GHz and 256GB of RAM`), ours protocol requires only `71` seconds to securely compute the intersection of `5` parties, each has `2^20`-size sets, regardless of the bit length of the items.

For programmable OPRF, this code implements:
* Table-based OPPRF
* Polynomial-based  OPPRF
* BloomFilter-based OPPRF

For PSI, we implement multi-party PSI (nPSI) in augmented-semihonest model and standard semihonest model.

## Installations

### Required libraries
C++ compiler with C++14 support. There are several library dependencies including [`Boost`](https://sourceforge.net/projects/boost/), [`Miracl`](https://github.com/miracl/MIRACL), [`NTL`](http://www.shoup.net/ntl/) , and [`libOTe`](https://github.com/osu-crypto/libOTe). For `libOTe`, it requires CPU supporting `PCLMUL`, `AES-NI`, and `SSE4.1`. Optional: `nasm` for improved SHA1 performance.   Our code has been tested on both Windows (Microsoft Visual Studio) and Linux. To install the required libraries:
* windows: open PowerShell,  `cd ./thirdparty`, and `.\all_win.ps1` (the script works with Visual Studio 2015. For other version, you should modify [`MSBuild`](https://github.com/osu-crypto/MultipartyPSI/blob/implement/thirdparty/win/getNTL.ps1#L3) at several places in the script.)
* linux: `cd ./thirdparty`, and `bash .\all_linux.get`.

NOTE: If you meet problem with `all_win.ps1` or `all_linux.get` which builds boost, miracl and libOTe, please follow the more manual instructions at [`libOTe`](https://github.com/osu-crypto/libOTe)

### Building the Project
After cloning project from git,
##### Windows:
1. build cryptoTools, libOTe, and libOPRF projects in order.
2. add argument for bOPRFmain project (for example: -u)
3. run bOPRFmain project

##### Linux:
1. `cmake .` (requirements: `CMake`, `Make`, `g++` or similar)
1. `make -j`


## Running the code
The database is generated randomly. The outputs include the average online/offline/total runtime that displayed on the screen and output.txt.
#### Flags:
```shell
-n		number of parties
-t		number of corrupted parties (in semihonest setting)
-m		set size
-p		party ID
-i		input file (every row means a item which will be PSI)
-o		output file (output the Intersection value in "/output/{outputfile}")
-ip     other party's IP, correspond to "-p" (ie. in "-p 0" -ip is {-p 1 ip},{-p 2 ip})
```
#### Examples:
nPSI: Compute PSI of 5 parties, no dishonestly colluding, each with set size 2^10 in semihonest setting

```shell
# build MultiParty PSI in 3 different machine(docker) or directly use ./bin/frontend.exe
# Player 0's ip:192.168.1.10,
./bin/frontend.exe -n 3 -t 0 -m 10 -p 0 -i data0.bin -o result0.txt -ip 192.168.1.11,192.168.1.12 > log0.log 
# Player 1's ip:192.168.1.11
./bin/frontend.exe -n 3 -t 0 -m 10 -p 1 -i data1.bin -o result1.txt -ip 192.168.1.10,192.168.1.12 > log1.log 
# Player 2's ip:192.168.1.12
./bin/frontend.exe -n 3 -t 0 -m 10 -p 2 -i data2.bin -o result2.txt -ip 192.168.1.10,192.168.1.11 > log2.log
```

## Summary

single machine?:

```shell
  1. git clone .......  
  2. cd thirdparty/
  3. bash all_linux.get 
  4. cd ..
  5. cmake .
  6.  make -j
  7. ./bin/frontend.exe -n 3 -t 0 -m 10 -p 0 -i data0.txt -o result0.txt -ip {yourIP},{yourIP} > log0.log &./bin/frontend.exe -n 3 -t 0 -m 10 -p 1 -i data1.txt -o result1.txt -ip {yourIP},{yourIP} > log1.log &./bin/frontend.exe -n 3 -t 0 -m 10 -p 2 -i data2.txt -o result2.txt -ip {yourIP},{yourIP} > log2.log
```


## Help
For any questions on building or running the library, please contact [`Ni Trieu`](http://people.oregonstate.edu/~trieun/) at trieun at oregonstate dot edu