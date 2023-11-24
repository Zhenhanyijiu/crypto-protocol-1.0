#ifndef __FU_CM20_H__
#define __FU_CM20_H__
#include "crypto-protocol/fusocket.h"
#include "crypto-protocol/threadpool.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include <bits/stdc++.h>
#define err_code_cm20 2001
using namespace oc;
using namespace std;

namespace fucrypto {
////////////////// cm20_sender ///////////////////////
class cm20_sender {
 private:
  int _omp_num;
  u64 _mat_width;
  u64 _mat_width_bytes;
  block _common_seed;
  u64 _log_height;
  u64 _height;
  u64 _height_bytes;
  u64 _sender_size;
  u64 _sender_size_in_bytes;
  u64 _bucket1;
  u64 _bucket2_send_hash;
  u64 _h2_len_in_bytes;
  oc::BitVector _choice_ote;
  vector<oc::block> _m_gens;
  vector<vector<oc::u8>> _trans_hash_inputs;
  vector<vector<oc::u8>> _hash_inputs;
  oc::u64 _low_left;
  bool _has_base_ot = false;

 public:
  ~cm20_sender();
  cm20_sender() = delete;
  cm20_sender(u8 *common_seed, u64 sender_size, u64 mat_width, u64 log_height,
              int omp_num = 1, u64 h2_len_in_bytes = 10,
              u64 bucket2_send_hash = 256);
  int set_base_ot(const oc::BitVector &choice_ote,
                  const vector<oc::block> &m_gens);
  int recoverMatrixC(conn *sock, vector<block> &senderSet);
  int computeHashOutputToReceiverOnce(conn *sock);
  int get_count() {
    return (_sender_size + _bucket2_send_hash - 1) / _bucket2_send_hash;
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