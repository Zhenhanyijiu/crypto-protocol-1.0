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

void test_kkrt_receiver(const vector<u32>& choices, vector<block>& out_mask) {
  int numOTExt = choices.size();
  connection c(1, "127.0.0.1", 9001);
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
int main(int argc, char** argv) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== test kkrt ===");
  return 0;
}
