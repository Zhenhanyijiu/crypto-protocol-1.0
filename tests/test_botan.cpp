#include <bits/stdc++.h>
#include <botan/bigint.h>
#include "crypto-protocol/utils.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/fuecc_botan.h"

using namespace std;
using namespace Botan;
using namespace fucrypto;

void test_bigint() {
  BigInt s;
  //   s.set_bit(10);
  string ret = s.to_dec_string();
  cout << "ret:" << ret << ",size:" << ret.size() << endl;
  ret = s.to_hex_string();
  cout << "ret:" << ret << ",size:" << ret.size() << endl;
}
void test_botan_bn_set_one_set_zero() {
  botan_bn bn;
  bn.set_one();
  bn.print();
  botan_bn bn2;
  bn2.from_dec("1");
  auto ret = bn.cmp(&bn2);
  assert(ret == 0);
  botan_bn bn3, bn4;
  bn3.from_dec("255");
  bn4.from_hex("ff");
  auto ret2 = bn3.cmp(&bn4);
  assert(ret2 == 0);
  cout << "=== ok" << endl;
  bn3.print();
  bn3.set_zero();
  bn3.print();
}
void test_botan_bn_to_bin() {
  botan_bn bn;
  bn.from_hex("1234567812345678ab");
  bn.from_dec("123456781234567877");
  string ret = bn.to_bin();
  bn.print();
  botan_bn bn2;
  bn2.from_bin(ret.data(), ret.size());
  //
  auto fg = bn.cmp(&bn2);
  assert(fg == 0);
  cout << "=== ok" << endl;
}
void test_botan_curve_gen_rand_bn(const config_param& conf) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== test_botan_curve_gen_rand_bn ===");
  auto c = new_lib_curve(conf);
  auto rbn = c->gen_rand_bn();
  rbn->print();
  bool fg = c->gen_rand_bn(rbn.get());
  assert(fg);
  rbn->print();
  auto rbn2 = c->gen_rand_bn();
  auto rbn3 = c->gen_rand_bn();
  fg = rbn2->cmp(rbn3.get());
  assert(fg != 0);
  rbn2->from_dec("1234567");
  rbn3->from_dec("1234567");
  fg = rbn2->cmp(rbn3.get());
  assert(fg == 0);
  cout << "=== ok" << endl;
}

void test_botan_curve_new_bn(const config_param& conf) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== test_botan_curve_new_bn ===");
  auto c = new_lib_curve(conf);
  auto rbn = c->new_bn();
  rbn->from_dec("3333333333");
  rbn->print();
  auto rbn2 = c->new_bn();
  auto rbn3 = c->new_bn();

  rbn2->from_dec("1234567");
  rbn3->from_dec("1234567");
  bool fg = rbn2->cmp(rbn3.get());
  assert(fg == 0);
  fg = rbn->cmp(rbn3.get());
  assert(fg != 0);

  cout << "=== ok" << endl;
}

void test_botan_curve_new_point(const config_param& conf) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== test_botan_curve_new_point ===");
  auto c = new_lib_curve(conf);
  auto p1 = c->new_point();
  assert(p1);
  p1->print();
  bool fg = c->is_at_infinity(p1.get());
  assert(fg);
  cout << "=== ok" << endl;
}
void test_botan_curve_is_on_curve(const config_param& conf) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== test_botan_curve_is_on_curve ===");
  auto c = new_lib_curve(conf);
  auto p1 = c->new_point();
  assert(p1);
  p1->print();
  bool fg = c->is_at_infinity(p1.get());
  assert(fg);
  fg = c->is_on_curve(p1.get());
  assert(fg);
  cout << "=== ok" << endl;
}

void test_botan_curve_add(const config_param& conf) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== test_botan_curve_add ===");
  auto c = new_lib_curve(conf);
  auto G = c->get_generator();
  cout << "==== 1" << endl;
  auto k1 = c->new_bn();
  k1->from_dec("2");
  auto p1 = c->new_point();
  auto p2 = c->new_point();
  auto p3 = c->new_point();
  assert(p1);
  assert(p2);
  assert(p3);
  c->add(G.get(), p1.get());
  c->add(G.get(), p2.get());
  bool fg = c->is_on_curve(p1.get());
  assert(fg);
  fg = c->is_on_curve(p2.get());
  assert(fg);
  p1->print();
  p2->print();
  c->add(G.get(), G.get(), p1.get());
  c->add(G.get(), G.get(), p2.get());
  c->scalar_base_mul(k1.get(), p3.get());
  fg = c->is_on_curve(p1.get());
  assert(fg);
  fg = c->is_on_curve(p2.get());
  assert(fg);
  fg = c->is_on_curve(p3.get());
  assert(fg);
  p1->print();
  p2->print();
  p3->print();
  c->set_to_infinity(p1.get());
  c->set_to_infinity(p2.get());
  c->set_to_infinity(p3.get());
}

void test_botan_scalar_mul(const config_param& conf) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== test_botan_scalar_mul ===");
  auto c = new_lib_curve(conf);
  auto G = c->get_generator();
  auto k1 = c->gen_rand_bn();
  auto k2 = c->gen_rand_bn();
  auto k3 = c->gen_rand_bn();
  k1->print();
  k2->print();
  k3->print();
  auto p1 = c->new_point();
  auto p2 = c->new_point();
  auto p3 = c->new_point();
  assert(p1);
  assert(p2);
  assert(p3);
  c->scalar_base_mul(k1.get(), p1.get());
  c->scalar_base_mul(k2.get(), p2.get());
  c->scalar_base_mul(k3.get(), p3.get());
  bool fg = c->is_on_curve(p1.get());
  assert(fg);
  fg = c->is_on_curve(p2.get());
  assert(fg);
  fg = c->is_on_curve(p3.get());
  assert(fg);
  p1->print();
  p2->print();
  p3->print();
  c->scalar_mul(k1.get(), p1.get());
  c->scalar_mul(k2.get(), p2.get());
  c->scalar_mul(k3.get(), p3.get());
  fg = c->is_on_curve(p1.get());
  assert(fg);
  fg = c->is_on_curve(p2.get());
  assert(fg);
  fg = c->is_on_curve(p3.get());
  assert(fg);
  p1->print();
  p2->print();
  p3->print();

  c->scalar_mul(k1.get(), p1.get(), p1.get());
  c->scalar_mul(k2.get(), p2.get(), p2.get());
  c->scalar_mul(k3.get(), p3.get(), p3.get());
  fg = c->is_on_curve(p1.get());
  assert(fg);
  fg = c->is_on_curve(p2.get());
  assert(fg);
  fg = c->is_on_curve(p3.get());
  assert(fg);
  p1->print();
  p2->print();
  p3->print();
  c->set_to_infinity(p1.get());
  c->set_to_infinity(p2.get());
  c->set_to_infinity(p3.get());
}

void test_botan_scalar_inv(const config_param& conf) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== test_botan_scalar_inv ===");
  auto c = new_lib_curve(conf);
  auto G = c->get_generator();
  auto k1 = c->gen_rand_bn();
  auto p1 = c->new_point();
  auto p2 = c->new_point();
  c->scalar_base_mul(k1.get(), p1.get());
  p1->print();
  c->inv(p1.get());
  p1->print();
  c->inv(p1.get(), p2.get());
  p2->print();
  bool fg = c->equal(p2.get(), p2.get());
  assert(fg);
  fg = c->equal(p1.get(), p2.get());
  assert(fg == false);
  auto p3 = c->new_point();
  //   auto p4 = c->new_point();
  c->copy(p1.get(), p3.get());
  auto p4 = c->copy(p1.get());
  fg = c->equal(p3.get(), p4.get());
  assert(fg);
  p3->print();
  p4->print();
}
int main(int argc, char** argv) {
  spdlog_set_level("info");
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== test botan ===");
  //   test_bigint();
  //   test_botan_bn_set_one_set_zero();
  //   test_botan_bn_to_bin();
  ///////////////////////////
  config_param conf;
  conf.ecc_lib_name = "botan";
  //   conf.ecc_lib_name = "openssl";
  test_botan_curve_gen_rand_bn(conf);
  test_botan_curve_new_bn(conf);
  test_botan_curve_new_point(conf);
  test_botan_curve_is_on_curve(conf);
  test_botan_curve_add(conf);
  test_botan_scalar_mul(conf);
  test_botan_scalar_inv(conf);
  return 0;
}