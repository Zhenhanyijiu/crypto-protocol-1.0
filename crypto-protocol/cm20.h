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
  bool _has_base_ot = false;
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

 public:
  ~cm20_sender();
  cm20_sender() = delete;
  cm20_sender(const string &common_seed, u64 sender_size, int mat_width,
              int log_height, int omp_num = 1, int h2_len_in_bytes = 10,
              int bucket2_send_hash = 256);
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
  bool _has_base_ot = false;
  int _omp_num;
  u64 _mat_width;
  u64 _mat_width_bytes;
  u64 _recver_size;
  u64 _recver_size_in_bytes;
  u64 _sender_size;
  u64 _log_height;
  u64 _height;
  u64 _height_bytes;
  u64 _bucket1;
  u64 _bucket2_send_hash;
  u64 _h2_len_in_bytes;
  vector<array<block, 2>> _m_gens_pair;
  block _common_seed;
  vector<vector<u8>> _trans_hash_inputs;
  vector<unordered_map<u64, std::vector<std::pair<block, u32>>>>
      _hash_map_vector;
  u64 _low_left;
  u32 _index_id;
  ThreadPool *_psi_compute_pool;
  vector<vector<u32>> _psi_results;
  vector<vector<vector<u32>>> _psi_result_pir;
  std::vector<std::future<u32>> _psi_result_index;

 public:
  ~cm20_receiver();
  cm20_receiver() = delete;
  cm20_receiver(const string &common_seed, u64 recver_size, u64 sender_size,
                int mat_width, int log_height, int omp_num = 1,
                int h2_len_in_bytes = 10, int bucket2_send_hash = 256);
  int set_base_ot(const vector<array<block, 2>> &m_gens_pair);
  int getSendMatrixADBuff(conn *sock, vector<block> &receiverSet);

  int genenateAllHashesMap();

  int recvFromSenderAndComputePSIOnce(conn *sock);
  int recvFromSenderAndComputePSIOnce_pir(conn *sock);
  int getPsiResultsForAll(vector<u32> &psiResultsOutput);
  int getPsiResultsForAllPirQuery(vector<vector<u32>> &psiResultsOutput);

  int get_count() {
    return (_sender_size + _bucket2_send_hash - 1) / _bucket2_send_hash;
  };
};

}  // namespace fucrypto
#endif