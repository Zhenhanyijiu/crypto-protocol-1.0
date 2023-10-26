#include <stdio.h>
#include <stdint.h>
#include <bits/stdc++.h>
#include "crypto-protocol/futime.h"
#include "crypto-protocol/hasherimpl.h"
using namespace fucrypto;
using namespace std;
void print_out(uint8_t *buf, int count) {
  for (int i = 0; i < count; i++) printf("%2x,", buf[i]);
  printf("\n");
}
string all_type[10] = {"sha256", "blake3"};
void test_hasher_check(int hash_type) {
  string s1 = "hello", s2 = "world", s3 = "helloworld";
  hasher *hh = nullptr;
  switch (hash_type) {
    case 0:
      hh = new (sha256);
      break;
    case 1:
      hh = new (blake3);
    default:
      break;
  }
  char out1[32], out2[32];
  hh->hasher_reset();
  hh->hasher_update(s1.data(), s1.length());
  hh->hasher_update(s2.data(), s2.length());
  hh->hasher_final(out1, 32);
  print_out((uint8_t *)out1, 32);
  //
  hh->hasher_reset();
  hh->hasher_update(s3.data(), s3.length());
  //   hh->hasher_update(s2.data(), s2.length());
  hh->hasher_final(out2, 32);
  print_out((uint8_t *)out2, 32);
}
void test_hasher(int hash_type) {
  uint8_t buf[32] = {0xb6, 0x60, 0x79, 0x41, 0x8c, 0x89, 0xb1, 0x6b,
                     0x52, 0xd0, 0x79, 0x5f, 0xd8, 0x60, 0x38, 0xb5,
                     0x98, 0x5d, 0x26, 0x13, 0x4b, 0xe8, 0x38, 0x13,
                     0x48, 0x1e, 0x31, 0xf3, 0x33, 0x20, 0x03, 0xb3};
  hasher *hh = nullptr;
  switch (hash_type) {
    case 0:
      hh = new (sha256);
      break;
    case 1:
      hh = new (blake3);
    default:
      break;
  }
  uint64_t start_t = get_time_now<uint64_t>();
  //   oc::ROracle ro;
  for (int i = 0; i < 10000000; i++) {
    hh->hasher_reset();
    hh->hasher_update((char *)buf, 32);
    char out[32];
    hh->hasher_final(out, 32);
    // print_out((uint8_t *)out, 32);
  }
  float ret = get_use_time<float>(start_t, MS);
  cout << all_type[hash_type] << " use time:" << ret << " ms" << endl;
}

int main() {
  test_hasher(0);
  test_hasher(1);
  //   test_hasher_check(0);
  //   test_hasher_check(1);
  return 0;
}
