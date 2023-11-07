#include "crypto-protocol/ot_base.h"
#include "crypto-protocol/ote_iknp.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/tcpsocket.h"
#include <bits/stdc++.h>
using namespace std;
using namespace fucrypto;
static void test_iknp_sender(vector<array<oc::block, 2>>& pair_keys,
                             config_param& param) {
  connection c(0, "127.0.0.1", 9000);
  //   np99receiver baserecver;
  //   otreceiver* ot = &baserecver;
  auto ote = new_ote_sender(param);
#if 0
  auto ot = new_base_ot_receiver(param);
  oc::PRNG rng(oc::sysRandomSeed());
  oc::BitVector chs(128);
  chs.randomize(rng);
  vector<oc::block> single_k(128);
  ot->receive(chs, single_k, &c);
  //   iknp_sender iknpsender;
  //   ote_sender* ote = &iknpsender;
  ote->set_base_ot(chs, single_k);
#endif
  ote->send(pair_keys, &c);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ote sender sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ote sender recvBytes:{} B",
                     (&c)->recv_bytes_count());
}
static void test_iknp_recver(oc::BitVector& choices,
                             vector<oc::block>& single_keys,
                             config_param& param) {
  connection c(1, "127.0.0.1", 9000);
  //   np99sender basesender;
  //   otsender* ot = &basesender;
  //   oc::PRNG rng(oc::sysRandomSeed());
  //   oc::BitVector chs(128);
  //   chs.randomize(rng);
  auto ote = new_ote_receiver(param);
#if 0
  auto ot = new_base_ot_sender(param);
  vector<array<oc::block, 2>> pair_k(128);
  ot->send(pair_k, &c);
  //   iknp_receiver iknprecver;
  //   ote_receiver* ote = &iknprecver;
  ote->set_base_ot(pair_k);
#endif
  ote->receive(choices, single_keys, &c);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ote recver sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ote recver recvBytes:{} B",
                     (&c)->recv_bytes_count());
}

static void check(oc::BitVector& choices, vector<oc::block>& single_keys,
                  vector<array<oc::block, 2>>& pair_keys) {
  int ot_num = single_keys.size();
  for (size_t i = 0; i < ot_num; i++) {
    if (i < 10 && i < ot_num) {
      cout << "i:" << i << "," << pair_keys[i][0] << "," << pair_keys[i][1]
           << endl;
      cout << "i:" << i << "," << single_keys[i] << ",c:" << choices[i] << endl;
    }
    bool fg = eq(single_keys[i], pair_keys[i][choices[i]]);
    if (!fg) {
      cout << "=== error i:" << i << endl;
      return;
    }
    // oc::block
  }
  cout << "========= check ok" << endl;
  cout << "========= ot_num:" << ot_num << endl;
}
int main(int argc, char** argv) {
  int ote_num = 128;
  if (argc > 1) ote_num = atoi(argv[1]);
  config_param param;
  param.hasher_name = "blake3";
  oc::PRNG rng(oc::sysRandomSeed());
  oc::BitVector choices(ote_num);
  choices.randomize(rng);
  vector<array<oc::block, 2>> pair_keys(ote_num);
  thread th1(test_iknp_sender, ref(pair_keys), ref(param));
  vector<oc::block> single_keys(ote_num);
  thread th2(test_iknp_recver, ref(choices), ref(single_keys), ref(param));
  th1.join();
  th2.join();
  check(choices, single_keys, pair_keys);
  return 0;
}