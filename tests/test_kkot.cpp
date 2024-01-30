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
  int N = 16;
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
  kkot.encode_all(numOTExt, N, out_masks);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot sender sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot sender recvBytes:{} B",
                     (&c)->recv_bytes_count());
}

void test_kkot_receiver(const vector<int>& choices, vector<block>& out_masks,
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
                       config_param& param, int N, int bit_l) {
  int numOTExt = num_ot;
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
  kkot.send(&c, in_data, N, bit_l);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot sender sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot sender recvBytes:{} B",
                     (&c)->recv_bytes_count());
}

void test_kkot_receiver2(const vector<int>& r_i, vector<uint8_t>& out_data,
                         config_param& param, int N, int bit_l) {
  //   int numOTExt = choices.size();
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
  kkot.recv(&c, r_i, out_data, N, bit_l);
  //  解密

  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot recver sendBytes:{} B",
                     (&c)->send_bytes_count());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "kkot recver recvBytes:{} B",
                     (&c)->recv_bytes_count());
}
int main_test2(int argc, char** argv) {
  srand(time(NULL));
  bool is_power = false;
  int num_Ote = 1 << 19;
  if (argc > 1) {
    if (is_power)
      num_Ote = 1 << atoi(argv[1]);
    else
      num_Ote = atoi(argv[1]);
  }
  //   if (argc > 1) num_Ote = atoi(argv[1]);
  int N = 16, bit_l = 1;
  if (argc > 2) N = atoi(argv[2]);
  if (argc > 3) bit_l = atoi(argv[3]);
  config_param param;
  param.hasher_name = "blake3";
  uint8_t mask = (1 << bit_l) - 1;
  if (bit_l == 8) mask = -1;
  printf("===== mask:%d\n", mask);
  vector<vector<uint8_t>> inputs(num_Ote);
  for (size_t i = 0; i < num_Ote; i++) {
    for (size_t j = 0; j < N; j++) {
      inputs[i].push_back((rand() & mask));
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
  thread th1(test_kkot_sender2, num_Ote, ref(inputs), ref(param), N, bit_l);

  vector<uint8_t> out_data;
  thread th2(test_kkot_receiver2, ref(choices), ref(out_data), ref(param), N,
             bit_l);
  th1.join();
  th2.join();
  cout << "========== end time " << tp.get_time_piont_ms() << " ms" << endl;
  //   check
  for (size_t i = 0; i < num_Ote; i++) {
    if (i < 3 && i < num_Ote) {
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
  cout << "ote_num:" << num_Ote << ",N:" << N << ",bit_l:" << bit_l << endl;
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

void test_N_bit_l() {
  int N = 16, bit_l = 3;
  uint8_t mask = (1 << bit_l) - 1;
  cout << "mask:" << (uint32_t)mask << endl;
  vector<uint8_t> inputs(16);
  vector<uint8_t> key(16);
  stringstream ss1, ss2;
  char tmp2[16];
  for (size_t i = 0; i < 16; i++) {
    inputs[i] = rand() & mask;
    key[i] = rand() & mask;
    sprintf(tmp2, "(%d,%d),", i, inputs[i]);
    ss1 << string(tmp2);
    sprintf(tmp2, "(%d,%d),", i, key[i]);
    ss2 << string(tmp2);
  }
  cout << "inputs:" << ss1.str() << endl;
  cout << "key   :" << ss2.str() << endl;
  //
  int min_num = (N * bit_l + 7) / 8;
  printf("need min_num:%d\n", min_num);
  uint8_t tmp[min_num];
  memset(tmp, 0, min_num);
  int print = 4;
  for (size_t j = 0; j < N; j++) {
    int bit_pos = j * bit_l;
    uint8_t x = inputs[j] ^ key[j];
    uint8_t shift = 0;
    //
    if (j < print) cout << "j:" << j << ",x:" << (uint32_t)x << endl;
    for (size_t k = bit_pos; k < bit_pos + bit_l; k++, shift++) {
      if (j < print) cout << "bit_pos:" << k;
      int b_index = k / 8;
      int bit_index = k % 8;
      if (j < print)
        cout << "||b_index:" << b_index << ",bit_index:" << bit_index << endl;
      uint8_t tt = ((x >> shift) & uint8_t(0x1));
      uint8_t t = tt << bit_index;
      tmp[b_index] |= t;
    }
    if (j < print) cout << endl;
  }
  for (size_t i = 0; i < min_num; i++) {
    cout << hex << (uint32_t)tmp[i] << ",";
    for (size_t j = 0; j < 8; j++) {
      printf("%d", ((tmp[i] >> j) & 0x1));
    }
    cout << endl;
  }
  cout << endl;
  //
  cout << "............. recover ................" << endl;
  uint8_t r = 4;
  uint8_t k_r = key[r];
  printf("r:%d,k_r:%d\n", r, k_r);
  int bit_pos = r * bit_l;
  printf("bit_pos:%d \n", bit_pos);
  int shift = 0;
  uint8_t ret = 0;
  for (size_t k = bit_pos; k < bit_pos + bit_l; k++, shift++) {
    int byte_index = k / 8;
    int bit_index = k % 8;
    cout << "bit_pos:" << k;
    cout << "||b_index:" << byte_index << ",bit_index:" << bit_index << endl;
    ret |= (((tmp[byte_index] >> bit_index) & 0x1) << shift);
    printf(">>>ret:%d\n", ret);
  }
  printf("ret:%d,ok:%d\n", (ret ^ k_r), inputs[r]);
}
int main(int argc, char** argv) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== test kkot ===");
  //   main_test(argc, argv);
  main_test2(argc, argv);
  //   int tmp[4];
  //   test_N_bit_l();
  for (int i = 0; i < 4; i++) {
    // cout << hex << rand() << ",";
  }
  cout << endl;
  uint8_t mask = (1 << 8) - 1;
  printf(">>>>>>>>>.mask:%d\n", mask);
  //   test_gen_wh_code();
  return 0;
}