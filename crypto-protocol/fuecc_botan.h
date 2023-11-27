#ifndef __FU_ECC_BOTAN_LIB_H__
#define __FU_ECC_BOTAN_LIB_H__
#include "crypto-protocol/fuecc.h"
#include <botan/bigint.h>
#include <botan/ec_group.h>
#include <botan/point_gfp.h>
using namespace std;
using namespace Botan;
namespace fucrypto {
class botan_bn : public bigint {
 public:
  //   BIGNUM* n = nullptr;
  BigInt _bn;

 public:
  botan_bn();
  botan_bn(const botan_bn& n) = delete;
  botan_bn(botan_bn&& n);
  botan_bn& operator=(const botan_bn& n) = delete;
  botan_bn& operator=(botan_bn&& n);
  ~botan_bn();
  int set_one();
  int set_zero();
  int set_long(long a);
  std::string to_bin();
  std::string to_hex();
  std::string to_dec();
  bool from_bin(const char* bin, int len) override;
  bool from_hex(std::string hex) override;
  bool from_dec(std::string dec) override;
  //   int cmp(const bigint* a, const bigint* b);
  int cmp(const bigint* a);
  void print();
};
class botan_curve;
class botan_point : public point {
 public:
  //   EC_POINT* _p = nullptr;
  PointGFp _p;
  const botan_curve* _botan_c = nullptr;

 public:
  botan_point() = delete;
  botan_point(const curve* c);
  botan_point(const botan_point&) = delete;
  ~botan_point();
  std::string to_bin();
  std::string to_hex();
  std::unique_ptr<bigint> to_bn();
  bool from_bin(const char* bin, int len);
  bool from_hex(const char* hex);
  bool from_bn(const bigint* bn);
  void print();
};
class botan_curve : public curve {
 public:
  EC_Group _ec_group;
  std::unique_ptr<RandomNumberGenerator> _rng;
  //   BN_CTX* _bn_ctx = nullptr;
  //   BIGNUM* _order = nullptr;
  //
  botan_curve() = delete;
  botan_curve(string curve_name);
  ~botan_curve();
  std::unique_ptr<bigint> gen_rand_bn();
  bool gen_rand_bn(bigint* bn);
  std::unique_ptr<bigint> new_bn();
  std::unique_ptr<point> new_point();
  bool is_on_curve(const point* p);
  bool add(const point* p1, const point* p2, point* ret);
  bool add(const point* p1, point* p2);
  //   std::unique_ptr<point> scalar_mul_const(const bigint* bn, const point*
  //   p1);
  bool scalar_mul(const bigint* bn, point* p1);
  bool scalar_mul(const bigint* bn, const point* p1, point* p2);
  bool scalar_base_mul(const bigint* bn, point* ret);
  std::unique_ptr<point> get_generator();
  bool inv(const point* p, point* ret);
  bool inv(point* p);
  std::unique_ptr<point> copy(const point* p);
  bool copy(const point* p, point* dst);
  bool equal(const point* p, const point* q);
  bool is_at_infinity(const point* p);
  bool set_to_infinity(point* p);
};
// extern EccLibFactory* openssl_factory_ptr;
// EccLibFactory* get_openssl_factory_ptr();
}  // namespace fucrypto

#endif