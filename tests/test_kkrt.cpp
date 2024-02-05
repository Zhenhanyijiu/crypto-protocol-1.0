#include "crypto-protocol/tcpsocket.h"
#include "crypto-protocol/kkrt.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/iknp.h"
#include "crypto-protocol/utils.h"
#include <bits/stdc++.h>
// #define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
// #include <doctest/doctest.h>

using namespace std;
using namespace oc;
using namespace fucrypto;

void test_kkrt_sender(const vector<vector<block>>& inputs,
                      vector<vector<block>>& out_masks, config_param& param) {
  int numOTExt = inputs.size();
  connection c(0, "127.0.0.1", 9001);
  kkrt_sender kkrt(param);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkrt_sender create");
#if 0
  int base_ot_num = kkrt.get_base_ot_count();
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

  kkrt.set_base_ot(base_choices, single_keys);
#endif
  kkrt.recv_correction(&c, numOTExt);
  kkrt.encode_all(numOTExt, inputs, out_masks);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkrt sender sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkrt sender recvBytes:{} B",
                     (&c)->recv_bytes_count());
}

void test_kkrt_receiver(const vector<block>& choices, vector<block>& out_masks,
                        config_param& param) {
  int numOTExt = choices.size();
  connection c(1, "127.0.0.1", 9001);
  kkrt_receiver kkrt(param);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkrt_receiver create");

#if 0
  int base_ot_num = kkrt.get_base_ot_count();
  //   iknp_sender iknp;
  //   ote_sender* ote = &iknp;
  auto ote = new_ote_sender(param);
  vector<array<block, 2>> pair_keys(base_ot_num);
  int fg = ote->send(pair_keys, &c);
  if (fg) {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "ote sender error");
  }
  //
  kkrt.set_base_ot(pair_keys);
#endif
  kkrt.encode_all(numOTExt, choices, out_masks, &c);
  kkrt.send_correction(&c, numOTExt);
  //  解密

  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkrt recver sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkrt recver recvBytes:{} B",
                     (&c)->recv_bytes_count());
}
int main_test(int argc, char** argv) {
  srand(time(NULL));
  int num_Ote = 1;
  if (argc > 1) num_Ote = atoi(argv[1]);
  int N = 3;
  if (argc > 2) N = atoi(argv[2]);
  config_param param;
  param.hasher_name = "blake3";
  //   ;
  vector<vector<block>> inputs(num_Ote);
  for (size_t i = 0; i < num_Ote; i++) {
    for (size_t j = 0; j < N; j++) {
      inputs[i].push_back(toBlock(rand(), rand()));
    }
  }
  vector<block> choices(num_Ote);
  vector<u32> choices_id(num_Ote);
  for (size_t i = 0; i < num_Ote; i++) {
    int j = rand() % N;
    choices_id[i] = j;
    choices[i] = inputs[i][j];
  }
  time_point tp;
  //
  cout << "========== start time " << tp.get_time_piont_ms() << " ms" << endl;
  vector<vector<block>> out_masks;
  thread th1(test_kkrt_sender, ref(inputs), ref(out_masks), ref(param));

  vector<block> out_dec_masks;
  thread th2(test_kkrt_receiver, ref(choices), ref(out_dec_masks), ref(param));
  th1.join();
  th2.join();
  cout << "========== end time " << tp.get_time_piont_ms() << " ms" << endl;
  //   check
  for (size_t i = 0; i < num_Ote; i++) {
    if (i < 5 && i < num_Ote) {
      for (size_t j = 0; j < N; j++) {
        cout << "[" << j << "]" << out_masks[i][j] << endl;
      }
      cout << "[" << choices_id[i] << "]" << out_dec_masks[i] << endl;
      cout << "[" << choices_id[i] << "]" << out_masks[i][choices_id[i]]
           << endl;
      cout << endl;
    }
    if (neq(out_dec_masks[i], out_masks[i][choices_id[i]]))
      cout << "check not ok" << endl;
    // return 0;
  }
  cout << "check ok" << endl;
  cout << "ote_num:" << num_Ote << ",N:" << N << endl;
  return 0;
}

int main(int argc, char** argv) {
  main_test(argc, argv);
  return 0;
}

// int add(int x, int y) {
//   //   CHECK(1 == 10);
//   ;
//   return x + y;
// }
// TEST_CASE("TEST CASE TEST") {
//   SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== test kkrt ===");
//   //   CHECK(1 == 1);
//   //   main_test(argc, argv);
//   //   for (size_t i = 0; i < 10; i++) {
//   //     CHECK(add(1, 4) == 5);
//   //   }
// }
