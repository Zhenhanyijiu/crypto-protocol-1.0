#ifndef __FU_ECC_BOTAN_LIB_H__
#define __FU_ECC_BOTAN_LIB_H__
#include "crypto-protocol/fuecc.h"
#include <botan/bigint.h>
#include <botan/ec_group.h>
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
  bool from_bin(const char* bin, int len) override;
  bool from_hex(std::string hex) override;
  bool from_dec(std::string dec) override;
  int cmp(const bigint* a, const bigint* b);
  void print();
};
// class open_curve;
// class open_point : public point {
//  public:
//   EC_POINT* _p = nullptr;
//   const open_curve* _open_c = nullptr;

//  public:
//   open_point() = delete;
//   open_point(const curve* c);
//   open_point(const open_point&) = delete;
//   ~open_point();
//   std::string to_bin();
//   std::string to_hex();
//   std::unique_ptr<bigint> to_bn();
//   bool from_bin(const char* bin, int len);
//   bool from_hex(const char* hex);
//   bool from_bn(const bigint* bn);
//   void print();
//   //   bool add(const point* p1, const point* p2, point* res, void* ctx);
//   //   bool add(const point* p1, point* p2, void* ctx);
//   //   bool scalar_mul(const bigint* bn, const point* p1, point* p2, void*
//   ctx);
//   //   bool scalar_mul(const bigint* bn, point* p1, void* ctx);
// };
// class open_curve : public curve {
//  public:
//   EC_GROUP* _ec_group = nullptr;
//   BN_CTX* _bn_ctx = nullptr;
//   BIGNUM* _order = nullptr;
//   //
//   open_curve() = delete;
//   open_curve(string curve_name);
//   ~open_curve();
//   std::unique_ptr<bigint> gen_rand_bn();
//   bool gen_rand_bn(bigint* bn);
//   std::unique_ptr<bigint> new_bn();
//   std::unique_ptr<point> new_point();
//   bool is_on_curve(const point* p);
//   bool add(const point* p1, const point* p2, point* ret);
//   bool add(const point* p1, point* p2);
//   //   std::unique_ptr<point> scalar_mul_const(const bigint* bn, const point*
//   //   p1);
//   bool scalar_mul(const bigint* bn, point* p1);
//   bool scalar_mul(const bigint* bn, const point* p1, point* p2);
//   bool scalar_base_mul(const bigint* bn, point* ret);
//   std::unique_ptr<point> get_generator();
//   bool inv(const point* p, point* ret);
//   bool inv(point* p);
//   std::unique_ptr<point> copy(const point* p);
//   bool copy(const point* p, point* dst);
//   bool equal(const point* p, const point* q);
//   bool is_at_infinity(const point* p);
//   bool set_to_infinity(point* p);
// };
// extern EccLibFactory* openssl_factory_ptr;
// EccLibFactory* get_openssl_factory_ptr();
}  // namespace fucrypto

#endif