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
  open_bn(open_bn&& n);
  open_bn& operator=(const open_bn& n) = delete;
  open_bn& operator=(open_bn&& n);
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
class open_curve;
class open_point : public point {
 public:
  EC_POINT* _p = nullptr;
  const open_curve* _open_c = nullptr;

 public:
  open_point() = delete;
  open_point(const curve* c);
  open_point(const open_point&) = delete;
  ~open_point();
  std::string to_bin();
  int from_bin(const char* bin, int len);
  void print();
  //   bool add(const point* p1, const point* p2, point* res, void* ctx);
  //   bool add(const point* p1, point* p2, void* ctx);
  //   bool scalar_mul(const bigint* bn, const point* p1, point* p2, void* ctx);
  //   bool scalar_mul(const bigint* bn, point* p1, void* ctx);
};
class open_curve : public curve {
 public:
  EC_GROUP* _ec_group = nullptr;
  BN_CTX* _bn_ctx = nullptr;
  BIGNUM* _order = nullptr;
  //
  open_curve() = delete;
  open_curve(int curve_id);
  ~open_curve();
  std::unique_ptr<bigint> gen_rand_bn();
  std::unique_ptr<bigint> new_bn();
  std::unique_ptr<point> new_point();
  bool is_on_curve(const point* p);
  std::unique_ptr<point> add(const point* p1, const point* p2);
  bool add(const point* p1, point* p2);
  std::unique_ptr<point> scalar_mul(const bigint* bn, const point* p1);
  bool scalar_mul(const bigint* bn, point* p1);
  std::unique_ptr<point> scalar_base_mul(const bigint* bn);
  std::unique_ptr<point> get_generator();
};
}  // namespace fucrypto

#endif