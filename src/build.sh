g++ -std=c++14 -Wall -O2 -g -fopenmp -msse3 -msse2 -msse4.1 -maes -mpclmul \
-I ../thirdparty/cryptoTools \
-I ../ \
-I /opt/vcpkg/installed/x64-linux/include/ \
-L /opt/vcpkg/installed/x64-linux/lib/ \
'../thirdparty/cryptoTools/cryptoTools/Common/BitVector.cpp' \
'../thirdparty/cryptoTools/cryptoTools/Common/CLP.cpp' \
'../thirdparty/cryptoTools/cryptoTools/Common/Defines.cpp' \
'../thirdparty/cryptoTools/cryptoTools/Common/Log.cpp' \
'../thirdparty/cryptoTools/cryptoTools/Common/TestCollection.cpp' \
'../thirdparty/cryptoTools/cryptoTools/Common/Timer.cpp' \
'../thirdparty/cryptoTools/cryptoTools/Common/tools.cpp' \
'../thirdparty/cryptoTools/cryptoTools/Crypto/AES.cpp' \
'../thirdparty/cryptoTools/cryptoTools/Crypto/PRNG.cpp' \
'tools/buffersocket.cpp' \
'tools/fulog.cpp' \
'tools/tcpsocket.cpp' \
'hash/hasherimpl.cpp' \
'hash/hasher.cpp' \
'ecc/fuecc_open.cpp' \
'ecc/fuecc_botan.cpp' \
'ecc/fuecc.cpp' \
'ot/ot_base.cpp' \
'ot/iknp.cpp' \
'ot/kkrt.cpp' \
'ot/ot_interface.cpp' \
'pke/short_enc.cpp' \
'coder/bloomfilter.cpp' \
'psi/cm20.cpp' \
'ot/kkot.cpp' \
../tests/test_cm20.cpp \
-lpthread -lcrypto -lfmt -lbotan-2 -lblake3 \
-o exe