#ifndef __FU_CM20_H__
#define __FU_CM20_H__
#include "crypto-protocol/fusocket.h"
#include "crypto-protocol/threadpool.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include <bits/stdc++.h>
using namespace oc;
using namespace std;

namespace fucrypto {
////////////////// cm20_sender ///////////////////////
class cm20_sender {
 private:
  int threadNumOmp;
  u64 matrixWidth;
  u64 matrixWidthInBytes;
  block commonSeed;
  u64 logHeight;
  u64 height;
  u64 heightInBytes;
  u64 senderSize;
  u64 senderSizeInBytes;
  u64 bucket1;
  u64 bucket2ForComputeH2Output;
  u64 hash2LengthInBytes;
  oc::BitVector choicesWidthInput;
  vector<oc::block> recoverMsgWidthOutput;
  //   vector<oc::block> uBuffOutput;
  //   vector<oc::u8> hashOutputBuff;
  vector<vector<oc::u8>> transHashInputs;
  vector<vector<oc::u8>> hashInputs;
  oc::u64 lowL;

 public:
  ~cm20_sender();
  cm20_sender() = delete;
  cm20_sender(conn *sock, oc::u8 *common_seed, oc::u64 sender_size,
              oc::u64 matrix_width, oc::u64 logHeight, int threadNum = 1,
              oc::u64 hash2LengthInBytes = 10,
              oc::u64 bucket2ForComputeH2Output = 256);
  int recoverMatrixC(conn *sock, vector<block> &senderSet);
  int computeHashOutputToReceiverOnce(conn *sock);
  int get_count() {
    return (senderSize + bucket2ForComputeH2Output - 1) /
           bucket2ForComputeH2Output;
  };
};
void transform_input_to_block(const vector<string> &dataSetInput,
                              vector<block> &dataSetOutput, int threadNum);
////////////////// cm20_receiver ///////////////////////
class cm20_receiver {
 private:
  // 目前w<=512*1024
  int threadNumOmp;
  u64 matrixWidth;
  u64 matrixWidthInBytes;
  u64 receiverSize;
  u64 senderSize;
  u64 receiverSizeInBytes;
  u64 logHeight;
  u64 height;
  u64 heightInBytes;
  u64 bucket1;
  u64 bucket2ForComputeH2Output;

  u64 hash2LengthInBytes;
  vector<array<block, 2>> encMsgOutput;
  block commonSeed;
  //   vector<u8> sendMatrixADBuff;
  vector<vector<u8>> transHashInputs;
  // std::unordered_map<u64, std::vector<std::pair<block, u32>>> allHashes;
  vector<unordered_map<u64, std::vector<std::pair<block, u32>>>> HashMapVector;
  //   IknpOtExtSender iknpOteSender;
  u64 lowL;
  u32 indexId;
  ThreadPool *psiComputePool;
  vector<vector<u32>> psiResults;
  vector<vector<vector<u32>>> psiResultPirQuery;
  std::vector<std::future<u32>> psiResultsIndex;

 public:
  ~cm20_receiver();
  cm20_receiver() = delete;
  cm20_receiver(conn *sock, u8 *commonSeed, u64 receiverSize, u64 senderSize,
                u64 matrixWidth, u64 logHeight, int threadNum = 1,
                u64 hash2LengthInBytes = 10,
                u64 bucket2ForComputeH2Output = 256);
  int getSendMatrixADBuff(conn *sock, vector<block> &receiverSet);

  int genenateAllHashesMap();

  int recvFromSenderAndComputePSIOnce(conn *sock);
  int recvFromSenderAndComputePSIOnce_pir(conn *sock);
  int getPsiResultsForAll(vector<u32> &psiResultsOutput);
  int getPsiResultsForAllPirQuery(vector<vector<u32>> &psiResultsOutput);

  int get_count() {
    return (senderSize + bucket2ForComputeH2Output - 1) /
           bucket2ForComputeH2Output;
  };
};

}  // namespace fucrypto
#endif