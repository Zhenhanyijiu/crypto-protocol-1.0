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

static void get_data(vector<block> &idList, vector<block> &idno_array,
                     vector<string> &attrList, int recv_size, int send_size) {
  assert(recv_size < send_size);

  block tmp;
  for (size_t i = 0; i < recv_size; i++) {
    sprintf((char *)&tmp, "%d", 1000000 + i);
    idno_array.push_back(tmp);
    idList.push_back(tmp);
    if (i == recv_size - 1) {
      sprintf((char *)&tmp, "%d", 3000000 + i);
      idno_array[i] = tmp;
    }
  };

  for (size_t i = recv_size; i < send_size; i++) {
    sprintf((char *)&tmp, "%d", 1000000 + i);
    idList.push_back(tmp);
  }

  string prefix =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?.,!"
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?.,!"
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?.,!"
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?.,!"
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?.,!";
  for (size_t i = 0; i < send_size; i++) {
    string s((char *)&idList[i]);
    attrList.push_back(prefix + s);
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
  uint16_t ATTR_PAD_16B_SIZE = *(uint16_t *)(send_size_and_seed.data() + 20);
  //   接收公共参数 end
  cm20_receiver cm20recver(common_seed, recver_size, sender_size, param->width,
                           param->log_height, param->omp_num, 10, sender_size);
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
    }
    cout << endl;
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
  //   构造 0-1 向量 end
  oc::BitVector bit_vector_choices(sender_size);
  oc::PRNG rng;
  rng.SetSeed(oc::sysRandomSeed());
  bit_vector_choices.randomize(rng);
  auto ote2 = new_ote_receiver(param2);
  vector<array<block, 2>> m_gens_pair2(128);
  for (size_t i = 0; i < 128; i++) {
    m_gens_pair2[i] = m_gens_pair_all[i + param->width];
  }
  //   1oo2 ot recver start
  ote2->set_base_ot(m_gens_pair2);
  std::vector<oc::block> single_keys;
  ote2->receive(bit_vector_choices, single_keys, sock);
  //   1oo2 ot send end
  vector<oc::u8> b_choices(sender_size, 0);
  for (uint32_t i = 0; i < sender_size; i++) {
    b_choices[i] = bit_vector_choices[i];
    b_choices[i] = b_choices[i] ^ sigma[i];
  }
  //   发送 delta=b*sigma
  sock->send(string((char *)b_choices.data(), b_choices.size()));
  int cipher_block_size = ATTR_PAD_16B_SIZE / sizeof(oc::block);
  string cipher_p = sock->recv();
  assert(cipher_p.size() == sender_size * cipher_block_size * 16);
  vector<oc::block> cipher_vec(cipher_p.size() / sizeof(oc::block));
  memcpy(cipher_vec.data(), cipher_p.data(), cipher_p.size());
  oc::block *all_cipher = cipher_vec.data();
  oc::AESDec aes;
  int offset = 0;
  uint32_t length = idno_array.size();
  ret.resize(length);
  //   for (int i = 0; i < length; i++) {
  //     // ret[i].resize(ATTR_PAD_16B_SIZE, '\0');
  //     ret[i] = "";
  //   }
  //   string per_cipher;
  vector<char> per_cipher(ATTR_PAD_16B_SIZE);
  //   per_cipher.resize(ATTR_PAD_16B_SIZE, '\0');
  int debug_count_ret = 0;
  for (size_t i = 0; i < sender_size; i++) {
    aes.setKey(single_keys[i]);
    // offset += cipher_block_size;
    // c1
    if ((int)sigma[i] == 1) {
      //   ret[index_in_idarray_map[i]].resize(ATTR_PAD_16B_SIZE, '\0');
      for (int ind = 0; ind < cipher_block_size; ind++) {
        aes.ecbDecBlock(*(all_cipher + offset + ind),
                        *((oc::block *)(per_cipher.data()) + ind));
      }
      ret[index_in_idarray_map[i]] = string(per_cipher.data());
      debug_count_ret++;
    }
    offset += cipher_block_size;
  }
}
uint16_t get_attribute_padding_16bytes_size(uint16_t n) {
  return ((n + 15) / 16) * 16;
}
// 获取属性最长的值并且是16的倍数
static uint16_t get_attr_max_size(const std::vector<std::string> &attrList) {
  int length = attrList.size();
  // 获取属性长度最大值
  oc::u16 max_attribute_length = 0;
  for (int i = 0; i < length; i++) {
    size_t temp_len = attrList[i].size();
    if (max_attribute_length < temp_len) {
      max_attribute_length = temp_len;
    }
  }
  return get_attribute_padding_16bytes_size(max_attribute_length);
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
  char send_size_and_com_seed[22];
  memcpy(send_size_and_com_seed, &sender_size, 4);
  //   string common_seed(16, 0);
  rng.get<char>(send_size_and_com_seed + 4, 16);
  uint16_t ATTR_PAD_16B_SIZE = get_attr_max_size(attrList);
  memcpy(send_size_and_com_seed + 20, &ATTR_PAD_16B_SIZE, 2);
  sock->send(string(send_size_and_com_seed, 22));
  //   公共参数 end
  cm20_sender cm20sender(string(send_size_and_com_seed + 4, 16), sender_size,
                         param->width, param->log_height, param->omp_num, 10,
                         sender_size);
  //   求交开始
  vector<block> m_gens(param->width);
  oc::BitVector choice_ote(param->width);
  for (size_t i = 0; i < param->width; i++) {
    m_gens[i] = m_gens_all[i];
    choice_ote[i] = choice_ote_all[i];
  }
  cm20sender.set_base_ot(choice_ote, m_gens);
  cm20sender.recover_matrix_c(sock, idList);
  cm20sender.send_hash2_output(sock);
  //   求交结束
  //   开始 1oo2 OT
  auto ote2 = new_ote_sender(param2);
  BitVector base_choice(128);
  vector<block> base_single_key(128);
  for (size_t i = 0; i < 128; i++) {
    base_choice[i] = choice_ote_all[param->width + i];
    base_single_key[i] = m_gens_all[param->width + i];
  }
  ote2->set_base_ot(base_choice, base_single_key);
  vector<array<block, 2>> pair_keys(sender_size);
  ote2->send(pair_keys, sock);
  //   1oo2 OT 结束
  string buf_delta = sock->recv();

  int cipher_block_size = ATTR_PAD_16B_SIZE / sizeof(oc::block);
  vector<oc::block> all_cipher(sender_size * cipher_block_size);

  oc::block *cipher_begin = all_cipher.data();
  oc::AES aes;
  int offset = 0;

  unique_ptr<oc::block[]> m1_arr(new oc::block[cipher_block_size]);

  oc::block *m1 = m1_arr.get();
  for (size_t i = 0; i < sender_size; i++) {
    // m0 事实上, m0 可以不需要处理
    memset(m1, 0, cipher_block_size * sizeof(oc::block));
    memcpy((char *)m1, attrList[i].data(), attrList[i].size());
    aes.setKey(pair_keys[i][(int)(buf_delta[i] ^ 0x01)]);
    aes.ecbEncBlocks(m1, cipher_block_size, cipher_begin + offset);
    offset += cipher_block_size;
  }

  // for send_data
  sock->send(string((char *)(all_cipher.data()),
                    all_cipher.size() * sizeof(oc::block)));
}
static void test_batch_pir() {
  int send_size = 10000 * 100, recv_size = 10000;
  vector<block> idList;
  vector<block> idno_array;
  vector<string> attrList;
  get_data(idList, idno_array, attrList, recv_size, send_size);
  cout << "=== idList sender_size:" << idList.size() << endl;
  cout << "=== idno_array recver_size:" << idno_array.size() << endl;
  batch_pir_param param;
  thread th1([&]() {
    connection c(1, "127.0.0.1", 9300);
    batch_pir_server(idList, attrList, &c, &param);
    cout << "pir_server recv:" << c.recv_bytes_count() << " B" << endl;
    cout << "pir_server send:" << c.send_bytes_count() << " B" << endl;
  });
  vector<string> ret;
  thread th2([&]() {
    connection c(0, "127.0.0.1", 9300);
    batch_pir_client(idno_array, ret, &c, &param);
    for (size_t i = 0; i < 5 && i < ret.size(); i++) {
      printf("[%d]:", i);
      cout << ret[i] << endl;
    };
    printf("[%d]:", recv_size - 1);
    cout << ret[recv_size - 1] << endl;
    cout << "pir_client recv:" << c.recv_bytes_count() << " B" << endl;
    cout << "pir_client send:" << c.send_bytes_count() << " B" << endl;
  });
  th1.join();
  th2.join();
}

int main(int argc, char **argv) {
  test_batch_pir();
  return 0;
}