#ifndef __FU_ECC_OPEN_H__
#define __FU_ECC_OPEN_H__
#include "crypto-protocol/fuecc.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
using namespace std;
namespace fucrypto {
class open_bn : public bigint {
 private:
  //   BIGNUM* n = nullptr;

 public:
  open_bn();
  open_bn(const open_bn& n) = delete;
  ~open_bn();
  int set_one();
  int set_zero();
  int set_long(long a);
  std::string to_bin();
  std::string to_hex();
  std::string to_dec();
  int from_bin(const char* bin, int len);
  int from_hex(std::string hex);
  int from_dec(std::string dec);
  int cmp(const bigint* a, const bigint* b);
  void print();
};
}  // namespace fucrypto

#endif