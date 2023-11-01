#ifndef __FU_ECC_INTERFACE_H__
#define __FU_ECC_INTERFACE_H__
#include <bits/stdc++.h>
namespace fucrypto {
// 先定义 3 个
class bigint {
 public:
  void* _n = nullptr;
  //
  bigint(){};
  virtual ~bigint(){};
  virtual int set_one() = 0;
  virtual int set_zero() = 0;
  virtual int set_long(long a) = 0;
  virtual std::string to_bin() = 0;
  virtual std::string to_hex() = 0;
  virtual std::string to_dec() = 0;
  virtual int from_bin(const char* bin, int len) = 0;
  virtual int from_hex(std::string hex) = 0;
  virtual int from_dec(std::string dec) = 0;
  virtual int cmp(const bigint* a, const bigint* b) = 0;
  virtual void print() = 0;

  //   virtual
};
class point {
 public:
  int _err_code = 0;
  //
  virtual ~point(){};
  virtual std::string to_bin() = 0;
  virtual std::string to_hex() = 0;
  virtual std::unique_ptr<bigint> to_bn() = 0;
  virtual int from_bin(const char* bin, int len) = 0;
  virtual int from_hex(const char* hex) = 0;
  virtual int from_bn(const bigint* bn) = 0;
  virtual void print() = 0;
  //   virtual bool add(const point* p1, const point* p2, point* res, void* ctx)
  //   = 0; virtual bool add(const point* p1, point* p2, void* ctx) = 0; virtual
  //   bool scalar_mul(const bigint* bn, const point* p1, point* p2,
  //                           void* ctx) = 0;
  //   virtual bool scalar_mul(const bigint* bn, point* p1, void* ctx) = 0;
};

class curve {
 public:
  std::string _ecc_curve_list[512] = {
      "secp256k1",
      "prime256v1",
      "secp384r1",
  };
  std::string _curve_name;
  //   int _curve_num = 3;

 public:
  curve() { _curve_name = "secp256k1"; };
  curve(std::string curve_name) { _curve_name = curve_name; };
  virtual ~curve(){};
  virtual std::unique_ptr<bigint> gen_rand_bn() = 0;
  virtual std::unique_ptr<bigint> new_bn() = 0;
  virtual std::unique_ptr<point> new_point() = 0;
  //   virtual std::unique_ptr<bigint> set_hex2bn(std::string hex) = 0;
  //   virtual std::unique_ptr<bigint> set_hex2bn(std::string hex) = 0;
  virtual bool is_on_curve(const point* p) = 0;
  virtual std::unique_ptr<point> add_const(const point* p1,
                                           const point* p2) = 0;
  virtual bool add(const point* p1, point* p2) = 0;
  virtual std::unique_ptr<point> scalar_mul_const(const bigint* bn,
                                                  const point* p1) = 0;
  virtual bool scalar_mul(const bigint* bn, point* p1) = 0;
  virtual std::unique_ptr<point> scalar_base_mul(const bigint* bn) = 0;
  virtual std::unique_ptr<point> get_generator() = 0;
  virtual std::unique_ptr<point> inv_const(const point* p) = 0;
  virtual bool inv(point* p) = 0;
  virtual std::unique_ptr<point> copy(const point* p) = 0;
  virtual bool copy(const point* p, point* dst) = 0;
  virtual bool equal(const point* p, const point* q) = 0;
  virtual bool is_at_infinity(const point* p) = 0;
  virtual bool set_to_infinity(point* p) = 0;
};

class EccLibFactory {
 private:
  std::string _ecc_lib_list[512] = {"openssl", "relic"};

 public:
  virtual ~EccLibFactory() { printf("[info]~EccLibFactory free\n"); };
  virtual std::unique_ptr<curve> new_curve(std::string curve_name) = 0;
};
extern std::unordered_map<std::string, EccLibFactory*>* ecc_lib_map;
}  // namespace fucrypto
#endif