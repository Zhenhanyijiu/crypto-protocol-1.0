#include "crypto-protocol/fuecc_open.h"
#include "crypto-protocol/fulog.h"
#include <bits/stdc++.h>
using namespace std;
using namespace fucrypto;

void test_print_open_bn() {
  open_bn bn;
  //   open_bn bn1(bn);
  //   open_bn bn2 = bn;
  bigint* bn_ptr = &bn;
  bn_ptr->set_one();
  bn_ptr->print();
  bn_ptr->set_zero();
  bn_ptr->print();
  bn_ptr->set_long(255);
  bn_ptr->print();
  bn_ptr->set_long(-1);
  bn_ptr->print();
}
void test_check_open_bn() {
  open_bn bn;
  bigint* p = &bn;
  p->from_dec("15");
  p->print();
  p->from_dec("-255");
  p->print();
  p->set_long(-255);
  p->print();

  p->from_hex("FFFFFFFFFFFFFF01");
  p->print();
  unsigned char bin[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1};
  p->from_bin((char*)bin, 8);
  p->print();
}

void test_curve_gen_rand_bn() {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test curve gen_rand_bn");
  open_curve op_cur(0);
  auto rand_bn1 = op_cur.gen_rand_bn();
  rand_bn1->print();
  //   SPDLOG_LOGGER_INFO(spdlog::default_logger(), "获取生成元 G");
  //   auto G = op_cur.get_generator();
  //   G->print();
  //   cout << endl;
}

void test_curve_new_bn() {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "========= test curve new_bn");
  open_curve op_cur(0);
  auto rand_bn1 = op_cur.new_bn();
  rand_bn1->print();
  rand_bn1->from_dec("-1000");
  rand_bn1->print();
  //   cout << endl;
}

void test_curve_new_point() {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test curve new_point");
  open_curve op_cur(0);
  auto rand_bn1 = op_cur.new_point();
  rand_bn1->print();
}
void test_curve_get_generator() {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test curve get_generator");
  open_curve op_cur(0);
  auto G = op_cur.get_generator();
  G->print();
  auto bin = G->to_bin();
  auto new_point = op_cur.new_point();
}
int main(int argc, char** argv) {
  cout << "======= test ecc_open ========" << endl;
  spdlog_set_level("info");
  //   test_print_open_bn();
  //   test_check_open_bn();
  test_curve_gen_rand_bn();
  test_curve_new_bn();
  test_curve_new_point();
  return 0;
}