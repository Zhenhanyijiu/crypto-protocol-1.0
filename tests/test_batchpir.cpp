#include <bits/stdc++.h>
#include "cryptoTools/Common/Defines.h"
#include "crypto-protocol/fusocket.h"
#include "crypto-protocol/tcpsocket.h"
#include "crypto-protocol/cm20.h"
#include "crypto-protocol/ot_interface.h"
// #include "crypto-protocol/config.h"
#define STEP_LEN 20000
using namespace std;
using namespace oc;
using namespace fucrypto;
class batch_pir_param {
 public:
  int omp_num = 1;
  int width = 192;
  int log_height = 21;
};

void get_data(vector<block> &senderSet, vector<block> &recverSet, int recv_size,
              int send_size) {
  assert(recv_size < send_size);
  oc::PRNG rng(toBlock(123456, 654321));
  for (size_t i = 0; i < recv_size; i++) {
    block tmp = rng.get<block>();
    senderSet.push_back(tmp);
    recverSet.push_back(tmp);
  };
  oc::PRNG rng2(toBlock(123456, 666666));
  for (size_t i = recv_size; i < send_size; i++) {
    senderSet.push_back(rng2.get<block>());
  }
}
static void batch_pir_client(std::vector<oc::block> &idno_array,
                             vector<string> &ret, fucrypto::conn *sock,
                             batch_pir_param *param) {
  //   128用于下次扩展
  vector<array<block, 2>> m_gens_pair_all(param->width + 128);
  config_param param2;
  auto ote = new_ote_sender(param2);
  ote->send(m_gens_pair_all, sock);
  //   生成所需的基本 OT 资源结束
  oc::u32 recver_size = idno_array.size();
  string send_size_and_seed = sock->recv();                     // 4+16字节
  oc::u32 sender_size = *(oc::u32 *)send_size_and_seed.data();  // 4B
  std::string common_seed(send_size_and_seed.data() + 4, 16);   // 16B
  //   接收公共参数 end
  cm20_receiver cm20recver(common_seed, recver_size, sender_size, param->width,
                           param->log_height, param->omp_num, 10, STEP_LEN);
  vector<array<block, 2>> m_gens_pair(param->width);
  for (size_t i = 0; i < param->width; i++) {
    m_gens_pair[i] = m_gens_pair_all[i];
  }
  cm20recver.set_base_ot(m_gens_pair);
  // 设置base ot
  cm20recver.gen_matrix_u_a_d(sock, idno_array);
  cm20recver.recv_hash2_output_pir(sock);
  vector<vector<u32>> psiResultsOutput;
  cm20recver.get_psi_results_pir(psiResultsOutput);
  cout << "=== psiResultsOutput.size:" << psiResultsOutput.size() << endl;
  for (size_t i = 0; i < 5 && i < psiResultsOutput.size(); i++) {
    cout << "=== i:" << i << endl;
    for (size_t i2 = 0; i2 < psiResultsOutput[i].size(); i2++) {
      cout << "i2:" << i2 << "," << psiResultsOutput[i][i2] << endl;
      //   cout << "i2:" << i2 << psiResultsOutput[i][i2] << endl;
    }
  }
  //   求交 end
  unordered_map<int, int> index_in_idarray_map;
  vector<oc::u8> sigma(sender_size, 0);
  for (size_t i = 0; i < psiResultsOutput.size(); i++) {
    sigma[psiResultsOutput[i][1]] = 1;
    index_in_idarray_map[psiResultsOutput[i][1]] = psiResultsOutput[i][0];
  }
  if (index_in_idarray_map.size() != psiResultsOutput.size()) {
    string err_msg = "id repeat";
    // return err_code_batch_pir;
    return;
  }
  //   做 0-1 向量 end
  oc::BitVector bit_vector_choices(sender_size);
  oc::PRNG rng;
  rng.SetSeed(oc::sysRandomSeed());
  bit_vector_choices.randomize(rng);
  auto ote2 = new_ote_receiver(param2);
  vector<array<block, 2>> m_gens_pair2(128);
  for (size_t i = param->width; i < param->width + 128; i++) {
    m_gens_pair2[i] = m_gens_pair_all[i];
  }
  ote2->set_base_ot(m_gens_pair2);
  std::vector<oc::block> single_keys;
  ote2->receive(bit_vector_choices, single_keys, sock);
}
static void batch_pir_server(std::vector<oc::block> &idList,
                             const std::vector<std::string> &attrList,
                             fucrypto::conn *sock, batch_pir_param *param) {
  PRNG rng(oc::sysRandomSeed());
  oc::BitVector choice_ote_all(param->width + 128);
  choice_ote_all.randomize(rng);
  vector<block> m_gens_all;
  config_param param2;
  auto ote = new_ote_receiver(param2);
  ote->receive(choice_ote_all, m_gens_all, sock);
  //   基本 OT 结束
  oc::u32 sender_size = idList.size();
  char send_size_and_com_seed[20];
  memcpy(send_size_and_com_seed, &sender_size, 4);
  //   string common_seed(16, 0);
  rng.get<char>(send_size_and_com_seed + 4, 16);
  //   memcpy(send_size_and_com_seed + 4, common_seed.data(), 16);
  sock->send(string(send_size_and_com_seed, 20));
  //   公共参数 end
  cm20_sender cm20sender(string(send_size_and_com_seed + 4, 16), sender_size,
                         param->width, param->log_height, param->omp_num, 10,
                         STEP_LEN);
  //
  vector<block> m_gens(param->width);
  oc::BitVector choice_ote(param->width);
  for (size_t i = 0; i < param->width; i++) {
    m_gens[i] = m_gens_all[i];
    choice_ote[i] = choice_ote_all[i];
  }

  cm20sender.set_base_ot(choice_ote, m_gens);
  cm20sender.recover_matrix_c(sock, idList);
  //   cout << "============== 1" << endl;
  cm20sender.send_hash2_output(sock);
}
static void test_batch_pir() {
  int send_size = 10000 * 100, recv_size = 10000;
  vector<block> idList;
  vector<block> idno_array;
  vector<string> attrList;
  get_data(idList, idno_array, recv_size, send_size);
  cout << "=== idList sender_size:" << idList.size() << endl;
  cout << "=== idno_array recver_size:" << idno_array.size() << endl;
  batch_pir_param param;
  thread th1([&]() {
    connection c(1, "127.0.0.1", 9300);
    batch_pir_server(idList, attrList, &c, &param);
    ;
  });
  vector<string> ret;
  thread th2([&]() {
    connection c(0, "127.0.0.1", 9300);
    batch_pir_client(idno_array, ret, &c, &param);
    ;
  });
  th1.join();
  th2.join();
}

int main(int argc, char **argv) {
  test_batch_pir();
  return 0;
}