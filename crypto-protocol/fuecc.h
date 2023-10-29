#ifndef __FU_ECC_INTERFACE_H__
#define __FU_ECC_INTERFACE_H__
#include <string>
namespace fucrypto {
class bigint {
 public:
  void* n = nullptr;

 public:
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
 private:
 public:
  virtual ~point() = 0;
  virtual bool add(const point* p1, const point* p2, point* res, void* ctx) = 0;
  virtual bool add(const point* p1, point* p2, void* ctx) = 0;
  virtual bool scalar_mul(const bigint* bn, const point* p1, point* p2,
                          void* ctx) = 0;
  virtual bool scalar_mul(const bigint* bn, point* p1, void* ctx) = 0;
};

class curve {
 private:
 public:
  curve();
  virtual ~curve(){};
  virtual bool is_on_curve(const point& p) = 0;
  virtual bool add(const point* p1, const point* p2, point* res) = 0;
  virtual bool add(const point* p1, point* p2) = 0;
  virtual bool scalar_mul(const bigint* bn, const point* p1, point* res) = 0;
  virtual bool scalar_base_mul(const bigint* bn, point* p2) = 0;
};

}  // namespace fucrypto
#endif