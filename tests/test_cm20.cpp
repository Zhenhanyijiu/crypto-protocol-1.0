#include "crypto-protocol/cm20.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/tcpsocket.h"
#include "crypto-protocol/ot_interface.h"
#include "cryptoTools/Common/Defines.h"
#include <bits/stdc++.h>
using namespace std;
using namespace fucrypto;
struct param {
  string common_seed = "0123456789abcdef";
  oc::u64 sender_size = 100000;
  oc::u64 matrix_width = 128;
  oc::u64 logHeight = 20;
  int threadNum = 1;
  oc::u64 hash2LengthInBytes = 10;
  //   oc::u64 bucket2ForComputeH2Output = 256;
  oc::u64 bucket2_send_hash = 2000000;
  oc::u64 recver_size = 3100;
};
param default_param;
void get_data(vector<block> &senderSet, vector<block> &recverSet) {
  oc::PRNG rng(toBlock(123456, 654321));
  for (size_t i = 0; i < default_param.recver_size; i++) {
    block tmp = rng.get<block>();
    senderSet.push_back(tmp);
    recverSet.push_back(tmp);
  };
  oc::PRNG rng2(toBlock(123456, 666666));
  for (size_t i = default_param.recver_size; i < default_param.sender_size;
       i++) {
    senderSet.push_back(rng2.get<block>());
  }
}
static void run_cm20_sender(vector<block> &senderSet) {
  connection c(1, "127.0.0.1", 9300);
  cm20_sender cm20sender(default_param.common_seed, default_param.sender_size,
                         default_param.matrix_width, default_param.logHeight,
                         default_param.threadNum,
                         default_param.hash2LengthInBytes,
                         default_param.bucket2_send_hash);
  cm20sender.recover_matrix_c(&c, senderSet);

  cm20sender.send_hash2_output(&c);

  //   cout << "cm20sender.get_count:" << cm20sender.get_count() << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), ">> cm20sender.get_count:{}",
                     cm20sender.get_count());
}
static void run_cm20_recver(vector<block> &recverSet) {
  connection c(0, "127.0.0.1", 9300);
  auto receiverSize = recverSet.size();
  cm20_receiver cm20recver(
      default_param.common_seed, receiverSize, default_param.sender_size,
      default_param.matrix_width, default_param.logHeight,
      default_param.threadNum, default_param.hash2LengthInBytes,
      default_param.bucket2_send_hash);
  cm20recver.gen_matrix_u_a_d(&c, recverSet);
  //   cout << "============== 3" << endl;
  //   cm20recver.gen_hash_map();
  //   cout << "============== 4" << endl;

  cm20recver.recv_hash2_output(&c);
  //   cout << "============== 5" << endl;

  vector<u32> psiResultsOutput;
  cm20recver.get_psi_results(psiResultsOutput);
  //   cout << "============== 6" << endl;

  //   cout << "=== psiResultsOutput.size:" << psiResultsOutput.size() << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     ">> === psiResultsOutput.size:{}",
                     psiResultsOutput.size());
  //   cout << "cm20recver.get_count:" << cm20recver.get_count() << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), ">> cm20recver.get_count:{}",
                     cm20recver.get_count());
}
static void test_cm20_psi() {
  vector<block> senderSet;
  vector<block> recverSet;
  get_data(senderSet, recverSet);
  cout << "=== sender_size:" << senderSet.size() << endl;
  cout << "=== recver_size:" << recverSet.size() << endl;
  thread th1(run_cm20_sender, ref(senderSet));
  thread th2(run_cm20_recver, ref(recverSet));
  th1.join();
  th2.join();
}
// pir
static void run_cm20_sender_pir(vector<block> &senderSet) {
  connection c(1, "127.0.0.1", 9300);
  cm20_sender cm20sender(default_param.common_seed, default_param.sender_size,
                         default_param.matrix_width, default_param.logHeight,
                         default_param.threadNum,
                         default_param.hash2LengthInBytes,
                         default_param.bucket2_send_hash);
  cm20sender.recover_matrix_c(&c, senderSet);
  //   cout << "============== 1" << endl;
  cm20sender.send_hash2_output(&c);
  //   cout << "============== 2" << endl;
}
static void run_cm20_recver_pir(vector<block> &recverSet) {
  connection c(0, "127.0.0.1", 9300);
  auto receiverSize = recverSet.size();
  cm20_receiver cm20recver(
      default_param.common_seed, receiverSize, default_param.sender_size,
      default_param.matrix_width, default_param.logHeight,
      default_param.threadNum, default_param.hash2LengthInBytes,
      default_param.bucket2_send_hash);
  cm20recver.gen_matrix_u_a_d(&c, recverSet);
  //   cout << "============== 3" << endl;
  //   cm20recver.gen_hash_map();
  //   cout << "============== 4" << endl;

  cm20recver.recv_hash2_output_pir(&c);
  //   cout << "============== 5" << endl;

  vector<vector<u32>> psiResultsOutput;
  cm20recver.get_psi_results_pir(psiResultsOutput);
  cout << "============== 6" << endl;

  cout << "=== psiResultsOutput.size:" << psiResultsOutput.size() << endl;
  for (size_t i = 0; i < 5; i++) {
    cout << "=== i:" << i << endl;

    for (size_t i2 = 0; i2 < psiResultsOutput[i].size(); i2++) {
      cout << "i2:" << i2 << "," << psiResultsOutput[i][i2] << endl;
      //   cout << "i2:" << i2 << psiResultsOutput[i][i2] << endl;
    }
  }
}
static void test_cm20_psi_pir() {
  vector<block> senderSet;
  vector<block> recverSet;
  get_data(senderSet, recverSet);
  cout << "=== sender_size:" << senderSet.size() << endl;
  cout << "=== recver_size:" << recverSet.size() << endl;
  thread th1(run_cm20_sender_pir, ref(senderSet));
  thread th2(run_cm20_recver_pir, ref(recverSet));
  th1.join();
  th2.join();
}

// use set baset ot test psi
static void run_cm20_sender_set_base_ot(vector<block> &senderSet) {
  connection c(1, "127.0.0.1", 9300);
  cm20_sender cm20sender(default_param.common_seed, default_param.sender_size,
                         default_param.matrix_width, default_param.logHeight,
                         default_param.threadNum,
                         default_param.hash2LengthInBytes,
                         default_param.bucket2_send_hash);

  PRNG rng(oc::sysRandomSeed());
  oc::BitVector choice_ote(default_param.matrix_width);
  choice_ote.randomize(rng);
  vector<block> m_gens;
  config_param param;
  auto ote = new_ote_receiver(param);
  ote->receive(choice_ote, m_gens, &c);
  cm20sender.set_base_ot(choice_ote, m_gens);
  //
  cm20sender.recover_matrix_c(&c, senderSet);

  cm20sender.send_hash2_output(&c);

  //   cout << "cm20sender.get_count:" << cm20sender.get_count() << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), ">> cm20sender.get_count:{}",
                     cm20sender.get_count());
}
static void run_cm20_recver_set_base_ot(vector<block> &recverSet) {
  connection c(0, "127.0.0.1", 9300);
  auto receiverSize = recverSet.size();
  cm20_receiver cm20recver(
      default_param.common_seed, receiverSize, default_param.sender_size,
      default_param.matrix_width, default_param.logHeight,
      default_param.threadNum, default_param.hash2LengthInBytes,
      default_param.bucket2_send_hash);

  //
  vector<array<block, 2>> m_gens_pair(default_param.matrix_width);
  config_param param;
  auto ote = new_ote_sender(param);
  ote->send(m_gens_pair, &c);
  cm20recver.set_base_ot(m_gens_pair);
  //
  cm20recver.gen_matrix_u_a_d(&c, recverSet);
  //   cout << "============== 3" << endl;
  //   cm20recver.gen_hash_map();
  //   cout << "============== 4" << endl;

  cm20recver.recv_hash2_output(&c);
  //   cout << "============== 5" << endl;

  vector<u32> psiResultsOutput;
  cm20recver.get_psi_results(psiResultsOutput);
  //   cout << "============== 6" << endl;

  //   cout << "=== psiResultsOutput.size:" << psiResultsOutput.size() << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     ">> === psiResultsOutput.size:{}",
                     psiResultsOutput.size());
  //   cout << "cm20recver.get_count:" << cm20recver.get_count() << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), ">> cm20recver.get_count:{}",
                     cm20recver.get_count());
}
static void test_cm20_psi_set_base_ot() {
  vector<block> senderSet;
  vector<block> recverSet;
  get_data(senderSet, recverSet);
  cout << "=== sender_size:" << senderSet.size() << endl;
  cout << "=== recver_size:" << recverSet.size() << endl;
  thread th1(run_cm20_sender_set_base_ot, ref(senderSet));
  thread th2(run_cm20_recver_set_base_ot, ref(recverSet));
  th1.join();
  th2.join();
}

int main(int argc, char **argv) {
  cout << "======= test cm20 ========" << endl;
  //   test_cm20_psi();
  //   test_cm20_psi_pir();
  test_cm20_psi_set_base_ot();
  return 0;
}