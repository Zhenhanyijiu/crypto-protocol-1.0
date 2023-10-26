// #define ECC_OPENSSL_TEST
// #ifdef ECC_OPENSSL_TEST
// #include <unordered_map>
// oc::
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <chrono>
#include <vector>
#include "crypto-protocol/eccopenssl.h"
namespace oc = fucrypto;
std::chrono::steady_clock::time_point get_start() {
  return std::chrono::steady_clock::now();
}
float get_use_time(std::chrono::steady_clock::time_point &st) {
  std::chrono::steady_clock::time_point cur_time =
      std::chrono::steady_clock::now();
  auto dur =
      std::chrono::duration_cast<std::chrono::milliseconds>(cur_time - st);
  return dur.count();
}
int test1() {
  int curve_type = 0, err_no = 0;
  oc::Curve c(curve_type, err_no);
  assert(err_no);
  oc::Point G = c.get_generator(err_no);
  assert(err_no);
  unsigned char buf[512];
  int buf_len = 512;
  // int fg = G.to_bin(buf, buf_len);
  // assert(fg == 0);
  // int G_size = G.size();
  // printf("G_size:%d\n", G_size);
  print_point_debug("", G);
  G.inv(err_no);
  assert(err_no == 0);
  oc::Point G2(&c, err_no);
  // fg = G2.to_bin(buf, buf_len);
  // assert(fg == 0);
  // int G2_size = G2.size();
  // printf("G2_size:%d\n", G2.size());
  // print_point_debug("", buf, G2.size());
  return 0;
}
int test2_right() {
  int curve_type = 0, err_no = 0, buf_len = 512;
  // unsigned char buf[512];
  oc::Curve c(curve_type, err_no);
  assert(err_no == 0);
  oc::Point G = c.get_generator(err_no);
  assert(err_no == 0);
  // G.to_bin(buf, buf_len);
  print_point_debug("gen_g", G);
  oc::BigInt r1, r2;
  c.get_rand_bn(r1), c.get_rand_bn(r2);
  oc::Point r1_point(&c, err_no);
  assert(err_no == 0);
  oc::Point r12_point(&c, err_no);
  assert(err_no == 0);
  r1_point = G.mul(r1, err_no);
  assert(err_no == 0);
  // unsigned char buf_r1[512];
  // r1_point.to_bin(buf, buf_len);
  print_point_debug("g_r1 ", r1_point);
  r12_point = c.mul_gen(r1, err_no);
  assert(err_no == 0);
  // unsigned char buf[512];
  // r12_point.to_bin(buf, buf_len);
  print_point_debug("g_r1 ", r12_point);
  printf("\ng_ab test ............\n");
  oc::BigInt a, b;
  c.get_rand_bn(a), c.get_rand_bn(b);
  oc::Point g_a(&c, err_no);
  assert(err_no == 0);
  oc::Point g_b(&c, err_no);
  assert(err_no == 0);
  oc::Point g_ab(&c, err_no);
  assert(err_no == 0);
  oc::Point g_ba(&c, err_no);
  assert(err_no == 0);
  g_a = c.mul_gen(a, err_no);
  assert(err_no == 0);
  g_b = c.mul_gen(b, err_no);
  assert(err_no == 0);
  g_ab = g_a.mul(b, err_no);
  assert(err_no == 0);
  // g_ab.to_bin(buf, buf_len);
  assert(err_no == 0);
  print_point_debug("g_ab", g_ab);
  g_ba = g_b.mul(a, err_no);
  assert(err_no == 0);
  // g_ba.to_bin(buf, buf_len);
  print_point_debug("g_ba", g_ba);
  printf("\na+b test ............\n");
  oc::BigInt x, y;
  c.get_rand_bn(x), c.get_rand_bn(y);
  oc::Point g_x(&c, err_no), g_y(&c, err_no), g_y_1(&c, err_no),
      g_z(&c, err_no), res(&c, err_no);
  g_x = c.mul_gen(x, err_no);
  oc::print_point_debug("g_x  ", g_x);
  g_y = c.mul_gen(y, err_no);
  oc::print_point_debug("g_y  ", g_y);
  g_z = g_x.add(g_y, err_no);
  oc::print_point_debug("g_z  ", g_z);
  g_y_1 = g_y.inv(err_no);
  res = g_z.add(g_y_1, err_no);
  oc::print_point_debug("res_x", res);
  g_y_1 = g_x.inv(err_no);
  res = g_z.add(g_y_1, err_no);
  oc::print_point_debug("res_y", res);
  return 0;
}
// #include <map>
int test_bench(int count) {
  int err_no = 0;
  oc::Curve c(0, err_no);
  assert(err_no == 0);
  std::vector<oc::Point *> g1_vec;
  std::vector<oc::Point *> g2_vec;
  std::vector<oc::BigInt> k_vec;
  std::chrono::steady_clock::time_point now = get_start();
  for (int i = 0; i < count; i++) {
    oc::BigInt k1, k2;
    c.get_rand_bn(k1), c.get_rand_bn(k2);
    // oc::Point g_k1(&c, err_no);
    oc::Point *g_k1 = new oc::Point(&c, err_no);
    assert(err_no == 0);
    // printf("---------1\n");
    oc::Point *g_k2 = new oc::Point(&c, err_no);
    assert(err_no == 0);
    *g_k1 = c.mul_gen(k1, err_no);
    assert(err_no == 0);
    g1_vec.push_back(g_k1);
    *g_k2 = c.mul_gen(k2, err_no);
    assert(err_no == 0);
    g2_vec.push_back(g_k2);
    k_vec.push_back(k1);
    // oc::print_point_debug("g2_vec", g_k2);
  }
  printf("gen g1,g2 use time:%f ms\n", get_use_time(now));
  now = get_start();
  for (int i = 0; i < count; i++) {
    oc::Point tmp(&c, err_no);
    assert(err_no == 0);
    tmp = (*(g1_vec[i])).add(*(g2_vec[i]), err_no);
    assert(err_no == 0);
    // oc::print_point_debug("tmp", tmp);
  }
  printf("gen add use time:%f ms\n", get_use_time(now));

  now = get_start();
  for (int i = 0; i < count; i++) {
    oc::Point tmp(&c, err_no);
    assert(err_no == 0);
    tmp = g1_vec[i]->mul(k_vec[i], err_no);
    assert(err_no == 0);
    // oc::print_point_debug("tmp", tmp);
  }
  printf("gen mul use time:%f ms\n", get_use_time(now));
  return 0;
}
int test_bench_is_33(int count) {
  int err_no = 0;
  oc::Curve c(0, err_no);
  assert(err_no == 0);
  // std::vector<oc::Point *> g1_vec;
  // std::vector<oc::Point *> g2_vec;
  // std::vector<oc::BigInt> k_vec;
  std::chrono::steady_clock::time_point now = get_start();
  for (int i = 0; i < count; i++) {
    oc::BigInt k1, k2;
    c.get_rand_bn(k1), c.get_rand_bn(k2);
    print_bigint_debug("k1", k1);
    print_bigint_debug("k2", k2);
    // oc::Point g_k1(&c, err_no);
    oc::Point g_k1 = oc::Point(&c, err_no);
    assert(err_no == 0);
    // printf("---------1\n");
    oc::Point g_k2 = oc::Point(&c, err_no);
    assert(err_no == 0);
    g_k1 = c.mul_gen(k1, err_no);
    assert(err_no == 0);
    assert(g_k1.size() == 33);
    g_k2 = c.mul_gen(k2, err_no);
    assert(err_no == 0);
    assert(g_k2.size() == 33);
    printf("........test %d end \n", i);
  }
  printf("test point size is 33 use time:%f ms\n", get_use_time(now));
  return 0;
}
int main(int argc, char **argv) {
  int testnum = 1;
  if (argc > 1) {
    testnum = atoi(argv[1]);
  }
  printf("testnum:%d\n", testnum);
  for (int i = 0; i < 1; i++) {
    // test2_right();
    // putchar('\n');
    // test_bench(testnum);
    test_bench_is_33(testnum);
  }
}
