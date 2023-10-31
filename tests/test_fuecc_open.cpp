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
  new_point->from_bin(bin.data(), bin.size());
  new_point->print();
  bool fg = op_cur.is_on_curve(new_point.get());
  if (fg)
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "on curve ok");
  else
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "not on curve");
}

void test_curve_add_const() {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test_curve_add_const");
  open_curve open_cvr(0);
  curve* c = &open_cvr;
  auto k1 = c->new_bn();
  k1->from_dec("2");
  auto G = c->get_generator();
  auto P1 = c->scalar_base_mul(k1.get());  // p1=2G
  P1->print();
  unique_ptr<point> P2 = c->add_const(G.get(), G.get());
  P2->print();
}

void test_curve_add() {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "========= test_curve_add");
  open_curve open_cvr(0);
  curve* c = &open_cvr;
  auto k1 = c->new_bn();
  k1->from_dec("2");
  auto G = c->get_generator();
  auto P1 = c->scalar_base_mul(k1.get());  // p1=2G
  P1->print();
  bool fg = c->add(G.get(), P1.get());
  if (fg) SPDLOG_LOGGER_INFO(spdlog::default_logger(), "fg:{}", fg);
  P1->print();
  k1->from_dec("3");
  auto P2 = c->scalar_base_mul(k1.get());  // p1=3G
  P2->print();
  bool fg2 = c->equal(P2.get(), P1.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "equal:{}", fg2);
}
void test_curve_scalar_mul_const() {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test_curve_scalar_mul_const");
  open_curve open_cvr(0);
  curve* c = &open_cvr;
  auto k1 = c->new_bn();
  k1->from_dec("2");
  auto G = c->get_generator();
  auto P1 = c->scalar_base_mul(k1.get());  // p1=2G
  k1->from_dec("3");
  auto P2 = c->scalar_mul_const(k1.get(), P1.get());  // p2=3*p1
  P2->print();
  k1->from_dec("6");
  unique_ptr<point> P3 = c->scalar_base_mul(k1.get());  // p3=6*G
  P3->print();
  bool fg = c->equal(P2.get(), P3.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "equal:{}", fg);
}

void test_curve_scalar_mul() {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test_curve_scalar_mul");
  open_curve open_cvr(0);
  curve* c = &open_cvr;
  auto k1 = c->new_bn();
  k1->from_dec("2");
  auto G = c->get_generator();
  auto P1 = c->scalar_base_mul(k1.get());  // p1=2G
  P1->print();
  k1->from_dec("4");
  bool fg = c->scalar_mul(k1.get(), P1.get());  // p2=8*G
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "mul:{}", fg);
  P1->print();
  k1->from_dec("8");
  auto P2 = c->scalar_base_mul(k1.get());  // p2=8G
  P2->print();
  bool fg2 = c->equal(P2.get(), P1.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "equal:{}", fg2);
}

void test_curve_inv_const() {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test_curve_inv_const");
  open_curve open_cvr(0);
  curve* c = &open_cvr;
  auto k1 = c->new_bn();
  k1->from_dec("2");
  auto G = c->get_generator();
  auto p1 = c->scalar_base_mul(k1.get());  // p1=2G
  p1->print();
  unique_ptr<point> p1_inv = c->inv_const(p1.get());
  p1_inv->print();
  auto O_inf = c->add_const(p1.get(), p1_inv.get());
  O_inf->print();
  bool fg = false;
  fg = c->is_at_infinity(O_inf.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "is_at_infinity:{}", fg);
}

void test_curve_inv() {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "========= test_curve_inv");
  open_curve open_cvr(0);
  curve* c = &open_cvr;
  auto k1 = c->new_bn();
  k1->from_dec("5");
  auto G = c->get_generator();
  auto p1 = c->scalar_base_mul(k1.get());  // p1=5G
  p1->print();
  c->copy(p1.get(), G.get());
  G->print();
  c->inv(p1.get());
  p1->print();
  auto O_inf = c->add_const(p1.get(), G.get());
  O_inf->print();
  bool fg = false;
  fg = c->is_at_infinity(O_inf.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "is_at_infinity:{}", fg);
}

void test_curve_set_to_infinity() {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test_curve_set_to_infinity");
  open_curve open_cvr(0);
  curve* c = &open_cvr;
  auto k1 = c->new_bn();
  k1->from_dec("5");
  auto G = c->get_generator();
  auto p1 = c->scalar_base_mul(k1.get());  // p1=5G
  p1->print();
  c->set_to_infinity(p1.get());
  p1->print();
}
int main(int argc, char** argv) {
  cout << "======= test ecc_open ========" << endl;
  spdlog_set_level("info");
  //   test_print_open_bn();
  //   test_check_open_bn();
  test_curve_gen_rand_bn();
  test_curve_new_bn();
  test_curve_new_point();
  test_curve_get_generator();
  test_curve_add_const();
  test_curve_add();
  test_curve_scalar_mul_const();
  test_curve_scalar_mul();
  test_curve_inv_const();
  test_curve_inv();
  test_curve_set_to_infinity();
  return 0;
}