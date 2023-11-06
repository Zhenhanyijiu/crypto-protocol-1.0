#include "crypto-protocol/ot_base.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/tcpsocket.h"
#include <cereal/types/memory.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/array.hpp>
#include <cereal/archives/binary.hpp>
#include <bits/stdc++.h>
using namespace std;
using namespace fucrypto;
vector<string> curve_list = {
    "secp256k1",
    // "prime256v1",
    // "secp384r1",
};
static void test_np99sender(int ot_num,
                            vector<array<oc::block, 2>>& pair_keys) {
  connection c(0, "127.0.0.1", 9001);
  config_param param, param2;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ecc_lib_name:{},curve_name:{}",
                     param.ecc_lib_name, param.curve_name);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ecc_lib_name:{},curve_name:{}",
                     param2.ecc_lib_name, param2.curve_name);
  //   for (auto& name : curve_list) {
  //   param.curve_name = name;
  np99sender np_sender(param);
  otsender* ot = &np_sender;
  // vector<array<oc::block, 2>> pair_keys(ot_num);
  int fg = ot->send(pair_keys, &c);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ot sender sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ot sender recvBytes:{} B",
                     (&c)->recv_bytes_count());

  if (fg) {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "ot send error fg:{}", fg);
  } else {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ot send fg:{} , ok", fg);
  }
  // np99sender np_sender2;
  //   }
}
static void test_np99receiver(int ot_num, vector<oc::block>& single_keys,
                              oc::BitVector& choices) {
  connection c(1, "127.0.0.1", 9001);
  config_param param, param2;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ecc_lib_name:{},curve_name:{}",
                     param.ecc_lib_name, param.curve_name);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ecc_lib_name:{},curve_name:{}",
                     param2.ecc_lib_name, param2.curve_name);
  auto seed = oc::sysRandomSeed();
  //   oc::PRNG rng(seed);
  //   vector<oc::block> single_keys(ot_num);
  //   for (auto& name : curve_list) {
  //   param.curve_name = name;
  np99receiver np_recver(param);
  otreceiver* ot = &np_recver;
  //   oc::BitVector choices(ot_num);
  //   choices.randomize(rng);
  int fg = ot->receive(choices, single_keys, &c);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ot receive sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ot receive recvBytes:{} B",
                     (&c)->recv_bytes_count());
  if (fg) {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "ot receive error fg:{}", fg);
  } else {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ot receive fg:{}, ok", fg);
  }
  //   }
  //   check
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
// void test_cereal_block() {
//   vector<char> buf = {
//       //   oc::toBlock(0xff11, 0xee22),
//       //   oc::toBlock(0xff11, 0xee22),
//       //   oc::toBlock(0xff11, 0xee22),
//       'a',
//       'b',
//       'c',
//   };
//   stringstream ss;
//   cereal::BinaryOutputArchive out_ar(ss);
//   out_ar(buf);
//   cout << "out ar:" << ss.str() << "," << ss.str().size() << endl;
// }
int main(int argc, char** argv) {
  spdlog_set_level("info");
  int ot_num = 1;
  if (argc > 1) ot_num = atoi(argv[1]);
  vector<oc::block> single_keys(ot_num);
  vector<array<oc::block, 2>> pair_keys(ot_num);
  auto seed = oc::sysRandomSeed();
  oc::PRNG rng(seed);
  oc::BitVector choices(ot_num);
  choices.randomize(rng);
  //
  thread th1(test_np99sender, ot_num, ref(pair_keys));
  thread th2(test_np99receiver, ot_num, ref(single_keys), ref(choices));
  th1.join();
  th2.join();
  //   check
  check(choices, single_keys, pair_keys);
  //   test_cereal_block();
  return 0;
}