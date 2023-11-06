#include "crypto-protocol/tcpsocket.h"
#include "crypto-protocol/kkrt.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/ote_iknp.h"
#include <bits/stdc++.h>
using namespace std;
using namespace oc;
using namespace fucrypto;

void test_kkrt_sender(const vector<vector<u32>>& inputs,
                      vector<vector<block>>& out_masks) {
  int numOTExt = inputs.size();
  connection c(0, "127.0.0.1", 9001);
  kkrt_sender kkrt;
  int base_ot_num = kkrt.get_base_ot_count();
  BitVector base_choices(base_ot_num);
  PRNG rng(sysRandomSeed());
  base_choices.randomize(rng);
  iknp_receiver iknp;
  ote_receiver* ote = &iknp;
  vector<block> single_keys(base_ot_num);
  int fg = ote->receive(base_choices, single_keys, &c);
  if (fg) {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ote error");
  }
  //
  kkrt.set_base_ot(base_choices, single_keys);
  kkrt.init(numOTExt);
  kkrt.recvCorrection(&c, numOTExt);
  kkrt.encode_all(numOTExt, inputs, out_masks);
}

void test_kkrt_receiver(const vector<u32>& choices, vector<block>& out_masks) {
  int numOTExt = choices.size();
  connection c(1, "127.0.0.1", 9001);
  kkrt_receiver kkrt;
  int base_ot_num = kkrt.get_base_ot_count();
  //   BitVector base_choices(base_ot_num);
  //   PRNG rng(sysRandomSeed());
  //   base_choices.randomize(rng);
  iknp_sender iknp;
  ote_sender* ote = &iknp;
  vector<array<block, 2>> pair_keys(base_ot_num);
  int fg = ote->send(pair_keys, &c);
  if (fg) {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ote sender error");
  }
  //
  kkrt.set_base_ot(pair_keys);
  kkrt.init(numOTExt);
  kkrt.encode_all(numOTExt, choices, out_masks);

  kkrt.sendCorrection(&c, numOTExt);
}
int main_test(int argc, char** argv) {
  srand(time(NULL));
  int num_Ote = 1;
  if (argc > 1) num_Ote = atoi(argv[1]);
  int N = 3;
  if (argc > 2) N = atoi(argv[2]);
  vector<vector<u32>> inputs(num_Ote);
  for (size_t i = 0; i < num_Ote; i++) {
    for (size_t j = 0; j < N; j++) {
      inputs[i].push_back(j);
    }
  }
  vector<vector<block>> out_masks;
  thread th1(test_kkrt_sender, ref(inputs), ref(out_masks));
  vector<u32> choices(num_Ote);
  for (size_t i = 0; i < num_Ote; i++) {
    choices[i] = rand() % N;
  }
  vector<block> out_dec_masks;
  thread th2(test_kkrt_receiver, ref(choices), ref(out_dec_masks));
  th1.join();
  th2.join();
  //   check
  for (size_t i = 0; i < num_Ote; i++) {
    if (i < 5 && i < num_Ote) {
      for (size_t j = 0; j < N; j++) {
        cout << "[" << j << "]" << out_masks[i][j] << endl;
      }
      cout << "[" << choices[i] << "]" << out_dec_masks[i] << endl;
      cout << endl;
    }
    if (neq(out_dec_masks[i], out_masks[i][choices[i]]))
      cout << "check not ok" << endl;
    // return 0;
  }
  cout << "check ok" << endl;
  cout << "ote_num:" << num_Ote << ",N:" << N << endl;
  return 0;
}

int main(int argc, char** argv) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== test kkrt ===");
  main_test(argc, argv);
  return 0;
}