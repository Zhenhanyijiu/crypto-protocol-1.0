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

void test_curve_gen_rand_bn(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test curve gen_rand_bn");
  //   open_curve op_cur(param.curve_name);
  auto op_cur = new_lib_curve(param);
  auto rand_bn1 = op_cur->gen_rand_bn();
  rand_bn1->print();
  //   SPDLOG_LOGGER_INFO(spdlog::default_logger(), "获取生成元 G");
  //   auto G = op_cur.get_generator();
  //   G->print();
  //   cout << endl;
}

void test_curve_new_bn(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "========= test curve new_bn");
  //   open_curve op_cur(curve_name);
  auto op_cur = new_lib_curve(param);
  auto rand_bn1 = op_cur->new_bn();
  rand_bn1->print();
  rand_bn1->from_dec("-1000");
  rand_bn1->print();
  //   cout << endl;
}

void test_curve_new_point(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test curve new_point");
  //   open_curve op_cur(curve_name);
  auto op_cur = new_lib_curve(param);
  auto rand_bn1 = op_cur->new_point();
  rand_bn1->print();
}
void test_curve_get_generator(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test curve get_generator");
  //   open_curve op_cur(curve_name);
  auto op_cur = new_lib_curve(param);
  auto G = op_cur->get_generator();
  G->print();
  auto bin = G->to_bin();
  auto new_point = op_cur->new_point();
  new_point->from_bin(bin.data(), bin.size());
  new_point->print();
  bool fg = op_cur->is_on_curve(new_point.get());
  if (fg)
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "on curve ok");
  else
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "not on curve");
}

void test_curve_add_const(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test_curve_add_const");
  //   open_curve open_cvr(curve_name);
  auto c = new_lib_curve(param);
  auto k1 = c->new_bn();
  k1->from_dec("2");
  auto G = c->get_generator();
  auto P1 = c->new_point();
  c->scalar_base_mul(k1.get(), P1.get());  // p1=2G
  P1->print();
  unique_ptr<point> P2 = c->new_point();
  c->add(G.get(), G.get(), P2.get());
  P2->print();
}

void test_curve_add(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "========= test_curve_add");
  //   open_curve open_cvr(curve_name);
  //   curve* c = &open_cvr;
  auto c = new_lib_curve(param);
  auto k1 = c->new_bn();
  k1->from_dec("2");
  auto G = c->get_generator();
  auto P1 = c->new_point();
  c->scalar_base_mul(k1.get(), P1.get());  // p1=2G
  P1->print();
  bool fg = c->add(G.get(), P1.get());
  if (fg) SPDLOG_LOGGER_INFO(spdlog::default_logger(), "fg:{}", fg);
  P1->print();
  k1->from_dec("3");
  auto P2 = c->new_point();
  c->scalar_base_mul(k1.get(), P2.get());  // p1=3G
  P2->print();
  bool fg2 = c->equal(P2.get(), P1.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "equal:{}", fg2);
}
void test_curve_scalar_mul_const(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test_curve_scalar_mul_const");
  //   open_curve open_cvr(curve_name);
  //   curve* c = &open_cvr;
  auto c = new_lib_curve(param);
  auto k1 = c->new_bn();
  k1->from_dec("2");
  auto G = c->get_generator();
  auto P1 = c->new_point();
  c->scalar_base_mul(k1.get(), P1.get());  // p1=2G
  k1->from_dec("3");
  auto P2 = c->new_point();
  c->scalar_mul(k1.get(), P1.get(), P2.get());  // p2=3*p1
  P2->print();
  k1->from_dec("6");
  unique_ptr<point> P3 = c->new_point();
  c->scalar_base_mul(k1.get(), P3.get());  // p3=6*G
  P3->print();
  bool fg = c->equal(P2.get(), P3.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "equal:{}", fg);
}

void test_curve_scalar_mul(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test_curve_scalar_mul");
  //   open_curve open_cvr(curve_name);
  //   curve* c = &open_cvr;
  auto c = new_lib_curve(param);
  auto k1 = c->new_bn();
  k1->from_dec("2");
  auto G = c->get_generator();
  auto P1 = c->new_point();
  c->scalar_base_mul(k1.get(), P1.get());  // p1=2G
  P1->print();
  k1->from_dec("4");
  bool fg = c->scalar_mul(k1.get(), P1.get());  // p2=8*G
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "mul:{}", fg);
  P1->print();
  k1->from_dec("8");
  auto P2 = c->new_point();
  c->scalar_base_mul(k1.get(), P2.get());  // p2=8G
  P2->print();
  bool fg2 = c->equal(P2.get(), P1.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "equal:{}", fg2);
}

void test_curve_inv_const(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test_curve_inv_const");
  //   open_curve open_cvr(curve_name);
  //   curve* c = &open_cvr;
  auto c = new_lib_curve(param);
  auto k1 = c->new_bn();
  k1->from_dec("2");
  auto G = c->get_generator();
  auto p1 = c->new_point();
  c->scalar_base_mul(k1.get(), p1.get());  // p1=2G
  p1->print();
  unique_ptr<point> p1_inv = c->new_point();
  c->inv(p1.get(), p1_inv.get());
  p1_inv->print();
  auto O_inf = c->new_point();
  c->add(p1.get(), p1_inv.get(), O_inf.get());
  O_inf->print();
  bool fg = false;
  fg = c->is_at_infinity(O_inf.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "is_at_infinity:{}", fg);
}

void test_curve_inv(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "========= test_curve_inv");
  //   open_curve open_cvr(curve_name);
  //   curve* c = &open_cvr;
  auto c = new_lib_curve(param);
  auto k1 = c->new_bn();
  k1->from_dec("5");
  auto G = c->get_generator();
  auto p1 = c->new_point();
  c->scalar_base_mul(k1.get(), p1.get());  // p1=5G
  p1->print();
  c->copy(p1.get(), G.get());
  G->print();
  c->inv(p1.get());
  p1->print();
  auto O_inf = c->new_point();
  c->add(p1.get(), G.get(), O_inf.get());
  O_inf->print();
  bool fg = false;
  fg = c->is_at_infinity(O_inf.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "is_at_infinity:{}", fg);
}

void test_curve_set_to_infinity(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test_curve_set_to_infinity");
  //   open_curve open_cvr(curve_name);
  //   curve* c = &open_cvr;
  auto c = new_lib_curve(param);
  auto k1 = c->new_bn();
  k1->from_dec("5");
  auto G = c->get_generator();
  auto p1 = c->new_point();
  c->scalar_base_mul(k1.get(), p1.get());  // p1=5G
  p1->print();
  c->set_to_infinity(p1.get());
  p1->print();
}
void test_curve_openssl_factory(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test_curve_openssl_factory");
  //   EccLibFactory* openssl = (*ecc_lib_map)["openssl"];
  //   auto cv = new_openssl_curve(curve_name);
  //   config_param param;
  //   param.curve_name = curve_name;
  auto cv = new_lib_curve(param);
  auto bn1 = cv->gen_rand_bn();
  bn1->print();
  auto bn2 = cv->new_bn();
  bn2->from_dec("2");
  bn2->print();
  auto p1 = cv->new_point();
  cv->scalar_base_mul(bn2.get(), p1.get());
  p1->print();
  bn2->from_dec("20");
  auto p2 = cv->new_point();
  cv->scalar_mul(bn2.get(), p1.get(), p2.get());
  p2->print();
  bn2->from_dec("40");
  auto p3 = cv->new_point();
  cv->scalar_base_mul(bn2.get(), p3.get());
  bool fg = cv->equal(p2.get(), p3.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "equal:{}", fg);
  auto p3_inv = cv->new_point();
  cv->inv(p3.get(), p3_inv.get());
  bn2->from_dec("-1");
  auto p3_inv2 = cv->new_point();
  cv->scalar_mul(bn2.get(), p3.get(), p3_inv2.get());

  bool fg2 = cv->equal(p3_inv.get(), p3_inv2.get());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "inv equal:{}", fg2);
}

void test_curve_open_point_2hex(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test_curve_open_point_2hex");
  //   EccLibFactory* openssl = (*ecc_lib_map)["openssl"];
  //   auto cv = new_openssl_curve(curve_name);
  //   config_param param;
  //   param.curve_name = curve_name;
  auto cv = new_lib_curve(param);
  auto bn1 = cv->new_bn();
  bn1->from_dec("11111");
  bn1->print();
  auto bn2 = cv->new_bn();
  unsigned char buf[2] = {0x2b, 0x67};
  bn2->from_bin((char*)buf, 2);
  bn2->print();
  bn1->from_dec("2");
  auto p1 = cv->new_point();
  cv->scalar_base_mul(bn1.get(), p1.get());
  p1->print();
  auto p2 = cv->new_point();
  p2->from_hex(p1->to_hex().c_str());
  p2->print();
}

void test_curve_open_point_2bn(const config_param& param) {
  cout << endl;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "========= test_curve_open_point_2bn");
  //   EccLibFactory* openssl = (*ecc_lib_map)["openssl"];
  //   config_param param;
  //   param.curve_name = curve_name;
  auto cv = new_lib_curve(param);
  auto bn1 = cv->new_bn();
  bn1->from_dec("11111");
  bn1->print();
  auto p1 = cv->new_point();
  cv->scalar_base_mul(bn1.get(), p1.get());
  cout << ">>> print point:" << endl;
  p1->print();
  cout << ">>> to_bn1:" << endl;
  auto to_bn1 = p1->to_bn();
  to_bn1->print();
  cout << ">>> debug from bn:" << endl;
  auto p2 = cv->new_point();
  auto r_bn = cv->gen_rand_bn();
  r_bn->print();
  int fg = p2->from_bn(r_bn.get());
  cout << ">>> fg:" << fg << endl;
  p2->print();

  //   auto p2 = cv->new_point();
  //   p2->from_hex(p1->to_hex().c_str());
  //   p2->print();
}

int main(int argc, char** argv) {
  cout << "======= test ecc_open ========" << endl;
  spdlog_set_level("info");
  //   test_print_open_bn();
  //   test_check_open_bn();
  vector<string> curve_lists = {
      "secp256k1",
      "prime256v1",
      "secp384r1",
  };
  //   for (size_t i = 0; i < curve_lists.size(); i++) {
  config_param param;
  param.ecc_lib_name = "botan";
  for (size_t i = 0; i < 1; i++) {
    param.curve_name = curve_lists[i];
    test_curve_gen_rand_bn(param);
    test_curve_new_bn(param);
    test_curve_new_point(param);
    test_curve_get_generator(param);
    test_curve_add_const(param);
    test_curve_add(param);
    test_curve_scalar_mul_const(param);
    test_curve_scalar_mul(param);
    test_curve_inv_const(param);
    test_curve_inv(param);
    test_curve_set_to_infinity(param);
    test_curve_openssl_factory(param);
    test_curve_open_point_2hex(param);
    test_curve_open_point_2bn(param);
  }

  return 0;
}