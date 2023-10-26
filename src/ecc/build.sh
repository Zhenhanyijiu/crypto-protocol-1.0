
CURR_PATH=${PWD}
echo "=========== CURR_PATH:${CURR_PATH}"
compile_openssl_ecc()
{
echo "=========== compile test_ecc"
g++ -std=c++11 -Wall -O3 \
-DECC_OPENSSL_TEST \
./eccopenssl.cpp \
-lcrypto -o test_ecc
echo "=========== run test_ecc"
time ./test_ecc
}
# USE_OPENSSL_SHA256
# compile_random_oracle_sha256()
# {
# echo "=========== compile test_ro"
# g++ -std=c++11 -Wall -O3 \
# -DRO_TEST -DUSE_OPENSSL_SHA256 \
# ./ro_impl.cpp -lcrypto \
# -o test_ro
# echo "=========== run test_ro,USE_OPENSSL_SHA256"
# time ./test_ro
# }
# 编译blake3
compile_blake3()
{
# 动态库
echo "=========== first compile libblake3_asm.so"
gcc -shared -fPIC -O3 -o libblake3_asm.so \
BLAKE3/c/blake3.c BLAKE3/c/blake3_dispatch.c BLAKE3/c/blake3_portable.c \
BLAKE3/c/blake3_sse2_x86-64_unix.S BLAKE3/c/blake3_sse41_x86-64_unix.S \
BLAKE3/c/blake3_avx2_x86-64_unix.S BLAKE3/c/blake3_avx512_x86-64_unix.S

# 静态库
gcc -shared -fPIC -O3 -c \
BLAKE3/c/blake3.c BLAKE3/c/blake3_dispatch.c BLAKE3/c/blake3_portable.c \
BLAKE3/c/blake3_sse2_x86-64_unix.S BLAKE3/c/blake3_sse41_x86-64_unix.S \
BLAKE3/c/blake3_avx2_x86-64_unix.S BLAKE3/c/blake3_avx512_x86-64_unix.S
ar rc libblake3_asm.a ./*.o
}
# USE_BLAKE3
compile_random_oracle_blake3()
{
echo "=========== check BLAKE3 source"
if [ -d BLAKE3 ];then
echo "=========== BLAKE3 exit"
else
echo "=========== BLAKE3 not exit"
git clone https://github.com/BLAKE3-team/BLAKE3.git
fi

# 用 gcc 编译成 目标文件 .o
gcc -shared -fPIC -O3 -c \
BLAKE3/c/blake3.c BLAKE3/c/blake3_dispatch.c BLAKE3/c/blake3_portable.c \
BLAKE3/c/blake3_sse2_x86-64_unix.S BLAKE3/c/blake3_sse41_x86-64_unix.S \
BLAKE3/c/blake3_avx2_x86-64_unix.S BLAKE3/c/blake3_avx512_x86-64_unix.S

echo "=========== compile test_hasher"
g++ -std=c++11 -Wall -O3 -DTEST_HASHER_IMPL \
-I. -I../.. -I BLAKE3/c \
./*.o ./hasherimpl.cpp \
-lcrypto \
-o test_hasher

# rm -rf BLAKE3
echo "=========== run test_hasher USE_BLAKE3"
# export LD_LIBRARY_PATH=.
rm ./*.o
time ./test_hasher
}

compile_use_blake3_vcpkg(){
g++ -std=c++11 -Wall -O3 -DTEST_HASHER_IMPL -pthread \
-I. -I../.. -I /opt/vcpkg/installed/x64-linux/include/ \
-L /opt/vcpkg/installed/x64-linux/lib \
./hasherimpl.cpp \
-lcrypto -lblake3 \
-o test_hasher

# rm -rf BLAKE3
echo "=========== run test_hasher USE_BLAKE3"
# export LD_LIBRARY_PATH=.
# rm ./*.o
time ./test_hasher
}
# compile_openssl_ecc
# compile_random_oracle_sha256
# compile_random_oracle_blake3
compile_use_blake3_vcpkg
# compile_blake3