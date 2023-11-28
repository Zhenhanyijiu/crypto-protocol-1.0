#include <bits/stdc++.h>
#include <botan/bigint.h>
#include <botan/base64.h>
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
void test_bench_mul_little(const config_param& conf) {
  time_point tp;
  auto c = new_lib_curve(conf);
  //   auto k1 = c->gen_rand_bn();
  auto k1 = c->new_bn();
  k1->from_dec("1");
  auto p1 = c->new_point();
  auto G = c->get_generator();
  for (size_t i = 0; i < 200; i++) {
    c->scalar_mul(k1.get(), G.get(), p1.get());
  }
  cout << "======== test_bench_mul_little little k use time:"
       << tp.get_time_piont_ms() << " ms" << endl;
}
void test_bench_mul_big(const config_param& conf) {
  time_point tp;
  auto c = new_lib_curve(conf);
  auto k1 = c->gen_rand_bn();
  k1->print();
  //   auto k1 = c->new_bn();
  k1->from_dec(
      "113873244849146753239066719301511572321549855000129812990552382434725991"
      "349921");
  auto p1 = c->new_point();
  auto G = c->get_generator();
  for (size_t i = 0; i < 200; i++) {
    c->scalar_mul(k1.get(), G.get(), p1.get());
  }
  cout << "======== test_bench_mul_big big k use time:"
       << tp.get_time_piont_ms() << " ms" << endl;
}

void test_botan_point_encode(const config_param& conf) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "=== test_botan_point_encode ===");
  time_point tp;
  auto c = new_lib_curve(conf);
  auto k1 = c->gen_rand_bn();
  //   auto k1 = c->new_bn();
  k1->from_dec(
      "113873244849146753239066719301511572321549855000129812990552382434725991"
      "349921");
  k1->print();

  auto p1 = c->new_point();
  auto p2 = c->new_point();
  auto G = c->get_generator();
  c->scalar_mul(k1.get(), G.get(), p1.get());
  p1->print();
  string bin_s = p1->to_bin();
  bool fg = p2->from_bin(bin_s.data(), bin_s.size());
  assert(fg);
  p2->print();
}
void test_base64(const config_param& conf) {
  cout << endl;
  auto c = new_lib_curve(conf);
  auto k1 = c->gen_rand_bn();
  string bin_ = k1->to_bin();
  cout << "bin_ size:" << bin_.size() << endl;
  string ret = base64_encode((uint8_t*)bin_.data(), bin_.size());
  cout << "base64:" << ret << ",len:" << ret.size() << endl;
}
using namespace Botan;
void test_bigint(const config_param& conf2) {
  cout << endl;
  auto conf = conf2;
  conf.ecc_lib_name = "botan";
  auto c = new_lib_curve(conf);
  auto k1 = c->gen_rand_bn();
  string bin_ = k1->to_bin();
  cout << "bin_ size:" << bin_.size() << endl;
  k1->print();
  k1->from_dec("10000");
  string s10 = k1->to_dec();
  k1->print();
  auto k2 = c->new_bn();
  k2->from_dec(s10);
  bool fg = k2->cmp(k1.get());
  assert(fg == 0);
  cout << boolalpha << "fg:" << fg << endl;
  //   BigInt B("-1");
  //   BigInt B("0xf");
  //   //   B.set_sign(B.Sign::Negative);
  //   //   auto xx = B.reverse_sign();
  //   auto xx = B.sign();
  //   cout << "-1 dec:" << B.to_dec_string() << endl;
  //   cout << "-1 hex:" << B.to_hex_string() << endl;
  //   cout << "sign :" << xx << endl;

  cout << "========= 65517 =========" << endl;
  auto b1 = c->new_bn();
  b1->from_dec("65517");
  b1->print();

  cout << "========= -65517 =========" << endl;
  b1->from_dec("-65517");
  b1->print();

  cout << "========= afde2a =========" << endl;
  b1->from_hex("afde2a");
  b1->print();

  cout << "========= -afde2a =========" << endl;
  b1->from_hex("-afde2a");
  b1->print();
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

  //
  test_bench_mul_little(conf);
  conf.ecc_lib_name = "openssl";
  test_bench_mul_little(conf);
  conf.ecc_lib_name = "botan";
  test_bench_mul_big(conf);
  conf.ecc_lib_name = "openssl";
  test_bench_mul_big(conf);
  //
  test_botan_point_encode(conf);
  test_base64(conf);
  test_bigint(conf);
  return 0;
}