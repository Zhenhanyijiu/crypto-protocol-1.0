#include "crypto-protocol/tcpsocket.h"
#include "crypto-protocol/kkot.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/ote_iknp.h"
#include "crypto-protocol/utils.h"
#include <bits/stdc++.h>
using namespace std;
using namespace oc;
using namespace fucrypto;

void test_kkot_sender(const vector<vector<u32>>& inputs,
                      vector<vector<block>>& out_masks, config_param& param) {
  int numOTExt = inputs.size();
  connection c(0, "127.0.0.1", 9001);
  kkot_sender kkot(param);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot_sender create");
#if 0
  int base_ot_num = kkot.get_base_ot_count();
  BitVector base_choices(base_ot_num);
  PRNG rng(sysRandomSeed());
  base_choices.randomize(rng);
  //   iknp_receiver iknp;
  //   ote_receiver* ote = &iknp;
  auto ote = new_ote_receiver(param);
  vector<block> single_keys(base_ot_num);
  int fg = ote->receive(base_choices, single_keys, &c);
  if (fg) {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "ote error");
  }

  kkot.set_base_ot(base_choices, single_keys);
#endif
  kkot.recv_correction(&c, numOTExt);
  kkot.encode_all(numOTExt, inputs, out_masks);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot sender sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot sender recvBytes:{} B",
                     (&c)->recv_bytes_count());
}

void test_kkot_receiver(const vector<u32>& choices, vector<block>& out_masks,
                        config_param& param) {
  int numOTExt = choices.size();
  connection c(1, "127.0.0.1", 9001);
  kkot_receiver kkot(param);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkrt_receiver create");

#if 0
  int base_ot_num = kkot.get_base_ot_count();
  //   iknp_sender iknp;
  //   ote_sender* ote = &iknp;
  auto ote = new_ote_sender(param);
  vector<array<block, 2>> pair_keys(base_ot_num);
  int fg = ote->send(pair_keys, &c);
  if (fg) {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "ote sender error");
  }
  //
  kkot.set_base_ot(pair_keys);
#endif
  kkot.encode_all(numOTExt, choices, out_masks, &c);
  kkot.send_correction(&c, numOTExt);
  //  解密

  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot recver sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot recver recvBytes:{} B",
                     (&c)->recv_bytes_count());
}
int main_test(int argc, char** argv) {
  srand(time(NULL));
  int num_Ote = 1 << 19;
  if (argc > 1) num_Ote = atoi(argv[1]);
  int N = 16;
  if (argc > 2) N = atoi(argv[2]);
  config_param param;
  param.hasher_name = "blake3";
  //   ;
  vector<vector<u32>> inputs(num_Ote);
  for (size_t i = 0; i < num_Ote; i++) {
    for (size_t j = 0; j < N; j++) {
      inputs[i].push_back(j);
    }
  }
  vector<u32> choices(num_Ote);
  for (size_t i = 0; i < num_Ote; i++) {
    choices[i] = rand() % N;
  }
  time_point tp;
  //
  cout << "========== start time " << tp.get_time_piont_ms() << " ms" << endl;
  vector<vector<block>> out_masks;
  thread th1(test_kkot_sender, ref(inputs), ref(out_masks), ref(param));

  vector<block> out_dec_masks;
  thread th2(test_kkot_receiver, ref(choices), ref(out_dec_masks), ref(param));
  th1.join();
  th2.join();
  cout << "========== end time " << tp.get_time_piont_ms() << " ms" << endl;
  //   check
  for (size_t i = 0; i < num_Ote; i++) {
    if (i < 10 && i < num_Ote) {
      // if (i < num_Ote) {
      //   set<block> tmp;
      for (size_t j = 0; j < N; j++) {
        cout << "[" << j << "]" << out_masks[i][j] << endl;
        // tmp.insert(out_masks[i][j]);
      }
      //   if (tmp.size() != N) {
      //     cout << "tmp.size()!=N error i:" << i << endl;
      //     return 0;
      //   }
      cout << "[" << choices[i] << "]" << out_dec_masks[i] << endl;
      cout << "[" << choices[i] << "]" << out_masks[i][choices[i]] << endl;
      cout << endl;
    }
    if (neq(out_dec_masks[i], out_masks[i][choices[i]])) {
      cout << "kkot check not ok ,i:" << i << endl;
      return 0;
    }
    // return 0;
  }
  cout << "kkot check ok" << endl;
  cout << "ote_num:" << num_Ote << ",N:" << N << endl;
  return 0;
}

uint64_t get64() {
  int tmp1 = rand();
  int tmp2 = rand();
  int tmp3 = rand();
  uint64_t tmp;
  char* p = (char*)&tmp;
  memcpy(p, &tmp1, 3);
  memcpy(p + 3, &tmp2, 3);
  memcpy(p + 6, &tmp3, 2);
  return tmp;
}
void test_gen_wh_code() {
  srand(time(NULL));
  //   uint64_t WH_Code[256][8];
  int count = 256;
  cout << hex << "{" << endl;
  for (size_t i = 0; i < count; i++) {
    cout << "{0x" << get64() << ",";
    cout << "0x" << get64() << ",";
    cout << "0x" << get64() << ",";
    cout << "0x" << get64() << ",";
    cout << "0x" << get64() << ",";
    cout << "0x" << get64() << ",";
    cout << "0x" << get64() << ",";
    cout << "0x" << get64() << "},";
  }
  cout << "}" << endl;
}
int main(int argc, char** argv) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== test kkot ===");
  main_test(argc, argv);
  //   int tmp[4];
  for (int i = 0; i < 4; i++) {
    cout << hex << rand() << ",";
  }
  cout << endl;
  //   test_gen_wh_code();
  return 0;
}