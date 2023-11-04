#include "crypto-protocol/tcpsocket.h"
#include "crypto-protocol/kkrt.h"
#include "crypto-protocol/fulog.h"
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
  kkrt.set_base_ot(, );
  kkrt.init(numOTExt);
}

void test_kkrt_sender(const vector<u32>& choices, vector<block>& out_mask) {
  connection c(1, "127.0.0.1", 9001);
  ;
  ;
}
int main(int argc, char** argv) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== test kkrt ===");
  return 0;
}
