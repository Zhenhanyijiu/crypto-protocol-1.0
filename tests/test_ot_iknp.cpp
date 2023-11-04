#include "crypto-protocol/ot_base.h"
#include "crypto-protocol/ote_iknp.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/tcpsocket.h"
#include <bits/stdc++.h>
using namespace std;
using namespace fucrypto;
static void test_iknp_sender(vector<array<oc::block, 2>>& pair_keys) {
  connection c(0, "127.0.0.1", 9000);
  np99receiver baserecver;
  otreceiver* ot = &baserecver;
  oc::PRNG rng(oc::sysRandomSeed());
  oc::BitVector chs(128);
  chs.randomize(rng);
  vector<oc::block> single_k(128);
  ot->receive(chs, single_k, &c);
  iknp_sender iknpsender;
  ote_sender* ote = &iknpsender;
  //   ote->set_base_ot(chs, single_k);
  ote->send(pair_keys, &c);
}
static void test_iknp_recver(oc::BitVector& choices,
                             vector<oc::block>& single_keys) {
  connection c(1, "127.0.0.1", 9000);
  np99sender basesender;
  otsender* ot = &basesender;
  //   oc::PRNG rng(oc::sysRandomSeed());
  //   oc::BitVector chs(128);
  //   chs.randomize(rng);
  vector<array<oc::block, 2>> pair_k(128);
  ot->send(pair_k, &c);
  iknp_receiver iknprecver;
  ote_receiver* ote = &iknprecver;
  //   ote->set_base_ot(pair_k);
  ote->receive(choices, single_keys, &c);
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
  oc::PRNG rng(oc::sysRandomSeed());
  oc::BitVector choices(ote_num);
  choices.randomize(rng);
  vector<array<oc::block, 2>> pair_keys(ote_num);
  thread th1(test_iknp_sender, ref(pair_keys));
  vector<oc::block> single_keys(ote_num);
  thread th2(test_iknp_recver, ref(choices), ref(single_keys));
  th1.join();
  th2.join();
  check(choices, single_keys, pair_keys);
  return 0;
}