#ifndef __FU_CM20_H__
#define __FU_CM20_H__
#include "crypto-protocol/config.h"
#include "crypto-protocol/utils.h"
#include "crypto-protocol/fusocket.h"
#include "crypto-protocol/threadpool.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include <bits/stdc++.h>
#define err_code_cm20 2001
// using namespace oc;
// using namespace std;

namespace fucrypto {
////////////////// cm20_sender ///////////////////////
class cm20_sender {
 private:
  bool _has_base_ot = false;
  int _omp_num;
  oc::u64 _mat_width;
  oc::u64 _mat_width_bytes;
  oc::block _common_seed;
  oc::u64 _log_height;
  oc::u64 _height;
  oc::u64 _height_bytes;
  oc::u64 _sender_size;
  oc::u64 _sender_size_in_bytes;
  oc::u64 _bucket1;
  oc::u64 _bucket2_send_hash;
  oc::u64 _h2_len_in_bytes;
  oc::BitVector _choice_ote;
  std::vector<oc::block> _m_gens;
  std::vector<std::vector<oc::u8>> _trans_hash_inputs;
  std::vector<std::vector<oc::u8>> _hash_inputs;
  oc::u64 _low_left;
  config_param _conf;
  time_point _tp;
  std::stringstream _ss;

 public:
  ~cm20_sender();
  cm20_sender() = delete;
  cm20_sender(const std::string &common_seed, oc::u64 sender_size,
              int mat_width, int log_height, int omp_num = 1,
              int h2_len_in_bytes = 10, int bucket2_send_hash = 256);
  int set_base_ot(const oc::BitVector &choice_ote,
                  const std::vector<oc::block> &m_gens);
  int recover_matrix_c(conn *sock, std::vector<oc::block> &sender_set);
  int send_hash2_output(conn *sock);
  int get_count() {
    return (_sender_size + _bucket2_send_hash - 1) / _bucket2_send_hash;
  };
  std::string get_time_point_info() {
    _ss.clear(), _ss.str("");
    _ss << " [time]:" << _tp.get_time_point_ms() << " ms";
    return _ss.str();
  };
};
void transform_input_to_block(const std::vector<std::string> &data_set_input,
                              std::vector<oc::block> &data_set_output,
                              int omp_num);
////////////////// cm20_receiver ///////////////////////
class cm20_receiver {
 private:
  // 目前w<=512*1024
  bool _has_base_ot = false;
  int _omp_num;
  oc::u64 _mat_width;
  oc::u64 _mat_width_bytes;
  oc::u64 _recver_size;
  oc::u64 _recver_size_in_bytes;
  oc::u64 _sender_size;
  oc::u64 _log_height;
  oc::u64 _height;
  oc::u64 _height_bytes;
  oc::u64 _bucket1;
  oc::u64 _bucket2_send_hash;
  oc::u64 _h2_len_in_bytes;
  std::vector<std::array<oc::block, 2>> _m_gens_pair;
  oc::block _common_seed;
  std::vector<std::vector<oc::u8>> _trans_hash_inputs;
  std::vector<
      std::unordered_map<oc::u64, std::vector<std::pair<oc::block, oc::u32>>>>
      _hash_map_vector;
  oc::u64 _low_left;
  oc::u32 _index_id;
  ThreadPool *_psi_compute_pool;
  std::vector<std::vector<oc::u32>> _psi_results;
  std::vector<std::vector<std::vector<oc::u32>>> _psi_result_pir;
  std::vector<std::future<oc::u32>> _psi_result_index;
  int gen_hash_map();
  time_point _tp;
  std::stringstream _ss;

 public:
  ~cm20_receiver();
  cm20_receiver() = delete;
  cm20_receiver(const std::string &common_seed, oc::u64 recver_size,
                oc::u64 sender_size, int mat_width, int log_height,
                int omp_num = 1, int h2_len_in_bytes = 10,
                int bucket2_send_hash = 256);
  int set_base_ot(const std::vector<std::array<oc::block, 2>> &m_gens_pair);
  int gen_matrix_u_a_d(conn *sock, std::vector<oc::block> &receiverSet);
  int recv_hash2_output(conn *sock);
  int recv_hash2_output_pir(conn *sock);
  int get_psi_results(std::vector<oc::u32> &result_output);
  int get_psi_results_pir(std::vector<std::vector<oc::u32>> &result_output);
  int get_count() {
    return (_sender_size + _bucket2_send_hash - 1) / _bucket2_send_hash;
  };
  std::string get_time_point_info() {
    _ss.clear(), _ss.str("");
    _ss << " [time]:" << _tp.get_time_point_ms() << " ms";
    return _ss.str();
  };
};

}  // namespace fucrypto
#endif