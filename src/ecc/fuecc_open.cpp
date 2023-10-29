#include "crypto-protocol/fuecc_open.h"
#include "crypto-protocol/fulog.h"
#include <bits/stdc++.h>
using namespace std;
namespace fucrypto {
/****************** open_bn begin *******************/
#define ptr(n) ((BIGNUM*)n)
static string get_bin_stream(const char* bg, int len) {
  if (len == 0) return "[]";
  //   stringstream ss;
  //   ss << hex;
  char ss[1024];
  //   for_each(bg, bg + len, [&](const char& c) {});
  char* p = ss;
  p[0] = '[';
  p = p + 1;
  for (size_t i = 0; i < len; i++) {
    if (i < len - 1)
      sprintf(p + 5 * i, "0x%2x,", (uint8_t)bg[i]);
    else
      sprintf(p + 5 * i, "0x%2x]", (uint8_t)bg[i]);
  }

  //   cout << hex << 255 << endl;
  return string(ss);
}
open_bn::open_bn() {
  n = BN_new();
  BN_zero(ptr(n));
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "addr init:{:p}", n);
};
open_bn::~open_bn() {
  if (n) BN_free(ptr(n));
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~open_bn free");
}
int open_bn::set_one() { return BN_one(ptr(n)); }
int open_bn::set_zero() { return BN_zero(ptr(n)); }
int open_bn::set_long(long a) { return BN_set_word(ptr(n), (BN_ULONG)a); }
std::string open_bn::to_bin() {
  unsigned char to[64];
  int n_bytes = BN_bn2bin(ptr(n), to);
  return string((char*)to, n_bytes);
}
std::string open_bn::to_hex() {
  char* s = BN_bn2hex(ptr(n));
  string ret(s);
  OPENSSL_free(s);
  return ret;
}
std::string open_bn::to_dec() {
  char* s = BN_bn2dec(ptr(n));
  string ret(s);
  OPENSSL_free(s);
  return ret;
}
int open_bn::from_bin(const char* bin, int len) {
  printf("===1 n_ptr:%p\n", n);
  n = BN_bin2bn((unsigned char*)bin, len, ptr(n));
  printf("===2 n_ptr:%p\n", n);
  return 0;
}
int open_bn::from_hex(std::string hex) {
  return BN_hex2bn((BIGNUM**)&n, hex.c_str());
}
int open_bn::from_dec(std::string dec) {
  return BN_dec2bn((BIGNUM**)&n, dec.c_str());
}
int open_bn::cmp(const bigint* a, const bigint* b) {
  return BN_cmp(ptr(a->n), ptr(b->n));
}
void open_bn::print() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "bn address:{:p}", n);
  //   cout << hex << "bn address:" << (uint64_t)n << endl;
  //   printf("bn address:%lld\n", (uint64_t)n);
  string hex = to_hex();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "hex:{},len:{}", hex,
                     hex.size());
  string dec = to_dec();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "dec:{},len:{}", dec,
                     dec.size());
  string bin = to_bin();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "bin:{},len:{}\n",
                     get_bin_stream(bin.data(), bin.size()), bin.size());
}
/****************** open_bn end *******************/

/*************************************/

}  // namespace fucrypto
