#include "crypto-protocol/tcpsocket.h"
#include "crypto-protocol/kkot.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/ote_iknp.h"
#include "crypto-protocol/utils.h"
#include <bits/stdc++.h>
using namespace std;
using namespace oc;
using namespace fucrypto;

void test_kkot_sender(int num_ot, vector<vector<block>>& out_masks,
                      config_param& param) {
  int numOTExt = num_ot;
  connection c(0, "127.0.0.1", 9001);
  kkot_sender kkot(param, 16);
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
  kkot.encode_all(numOTExt, out_masks);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot sender sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot sender recvBytes:{} B",
                     (&c)->recv_bytes_count());
}

void test_kkot_receiver(const vector<int>& choices, vector<block>& out_masks,
                        config_param& param) {
  int numOTExt = choices.size();
  connection c(1, "127.0.0.1", 9001);
  kkot_receiver kkot(param, 16);
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
  //   vector<vector<u32>> inputs(num_Ote);
  //   for (size_t i = 0; i < num_Ote; i++) {
  //     for (size_t j = 0; j < N; j++) {
  //       inputs[i].push_back(j);
  //     }
  //   }
  vector<int> choices(num_Ote);
  for (size_t i = 0; i < num_Ote; i++) {
    choices[i] = rand() % N;
  }
  time_point tp;
  //
  cout << "========== start time " << tp.get_time_piont_ms() << " ms" << endl;
  vector<vector<block>> out_masks;
  thread th1(test_kkot_sender, num_Ote, ref(out_masks), ref(param));

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
      cout << "[" << (uint32_t)choices[i] << "]" << out_dec_masks[i] << endl;
      cout << "[" << (uint32_t)choices[i] << "]"
           << out_masks[i][(uint32_t)choices[i]] << endl;
      cout << endl;
    }
    if (neq(out_dec_masks[i], out_masks[i][(uint32_t)choices[i]])) {
      cout << "kkot check not ok ,i:" << i << endl;
      return 0;
    }
    // return 0;
  }
  cout << "kkot check ok" << endl;
  cout << "ote_num:" << num_Ote << ",N:" << N << endl;
  return 0;
}

void test_kkot_sender2(int num_ot, vector<vector<uint8_t>>& in_data,
                       config_param& param) {
  int numOTExt = num_ot;
  connection c(0, "127.0.0.1", 9001);
  kkot_sender kkot(param, 16);
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
  kkot.send(&c, in_data, 2);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot sender sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot sender recvBytes:{} B",
                     (&c)->recv_bytes_count());
}

void test_kkot_receiver2(const vector<int>& r_i, vector<uint8_t>& out_data,
                         config_param& param) {
  //   int numOTExt = choices.size();
  connection c(1, "127.0.0.1", 9001);
  kkot_receiver kkot(param, 16);
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
  kkot.recv(&c, r_i, out_data, 2);
  //  解密

  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot recver sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot recver recvBytes:{} B",
                     (&c)->recv_bytes_count());
}
int main_test2(int argc, char** argv) {
  srand(time(NULL));
  int num_Ote = 1 << 19;
  if (argc > 1) num_Ote = atoi(argv[1]);
  int N = 16;
  if (argc > 2) N = atoi(argv[2]);
  config_param param;
  param.hasher_name = "blake3";
  int mask = (1 << 2) - 1;

  vector<vector<uint8_t>> inputs(num_Ote);
  for (size_t i = 0; i < num_Ote; i++) {
    for (size_t j = 0; j < N; j++) {
      inputs[i].push_back((j & mask));
    }
  }
  vector<int> choices(num_Ote);
  for (size_t i = 0; i < num_Ote; i++) {
    choices[i] = rand() % N;
  }
  time_point tp;
  //
  cout << "========== start time " << tp.get_time_piont_ms() << " ms" << endl;
  //   vector<vector<block>> out_masks;
  thread th1(test_kkot_sender2, num_Ote, ref(inputs), ref(param));

  vector<uint8_t> out_data;
  thread th2(test_kkot_receiver2, ref(choices), ref(out_data), ref(param));
  th1.join();
  th2.join();
  cout << "========== end time " << tp.get_time_piont_ms() << " ms" << endl;
  //   check
  for (size_t i = 0; i < num_Ote; i++) {
    if (i < 10 && i < num_Ote) {
      // if (i < num_Ote) {
      //   set<block> tmp;
      for (size_t j = 0; j < N; j++) {
        cout << "[" << j << "]" << uint32_t(inputs[i][j]) << endl;
        // tmp.insert(out_masks[i][j]);
      }
      //   if (tmp.size() != N) {
      //     cout << "tmp.size()!=N error i:" << i << endl;
      //     return 0;
      //   }
      cout << "[" << (uint32_t)choices[i] << "]" << uint32_t(out_data[i])
           << endl;
      cout << "[" << (uint32_t)choices[i] << "]"
           << uint32_t(inputs[i][choices[i]]) << endl;
      cout << endl;
    }
    if (out_data[i] != inputs[i][(uint32_t)choices[i]]) {
      cout << "kkot check not ok ,i:" << i << endl;
      return 0;
    }
    // return 0;
  }
  cout << "kkot2 check ok" << endl;
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
  //   main_test(argc, argv);
  main_test2(argc, argv);
  //   int tmp[4];
  for (int i = 0; i < 4; i++) {
    cout << hex << rand() << ",";
  }
  cout << endl;
  //   test_gen_wh_code();
  return 0;
}