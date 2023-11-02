#include "crypto-protocol/fuecc_open.h"
#include "crypto-protocol/fulog.h"
#include <bits/stdc++.h>
#include <openssl/obj_mac.h>

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
  _n = BN_new();
  BN_zero(ptr(_n));
  //   SPDLOG_LOGGER_INFO(spdlog::default_logger(), "addr init:{:p}", _n);
};
open_bn::open_bn(open_bn&& n) {
  _n = n._n;
  n._n = nullptr;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "open_bn 移动构造:{:p}", _n);
}
open_bn& open_bn::operator=(open_bn&& n) {
  _n = n._n;
  n._n = nullptr;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "open_bn 移动赋值:{:p}", _n);
  return *this;
}
open_bn::~open_bn() {
  if (_n) {
    BN_free(ptr(_n));
    _n = nullptr;
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~open_bn free");
}
int open_bn::set_one() { return BN_one(ptr(_n)); }
int open_bn::set_zero() { return BN_zero(ptr(_n)); }
int open_bn::set_long(long a) { return BN_set_word(ptr(_n), (BN_ULONG)a); }
std::string open_bn::to_bin() {
  unsigned char to[512];
  int n_bytes = BN_bn2bin(ptr(_n), to);
  return string((char*)to, n_bytes);
}
std::string open_bn::to_hex() {
  char* s = BN_bn2hex(ptr(_n));
  string ret(s);
  OPENSSL_free(s);
  return ret;
}
std::string open_bn::to_dec() {
  char* s = BN_bn2dec(ptr(_n));
  string ret(s);
  OPENSSL_free(s);
  return ret;
}
int open_bn::from_bin(const char* bin, int len) {
  printf("===1 n_ptr:%p\n", _n);
  auto res = BN_bin2bn((unsigned char*)bin, len, ptr(_n));
  printf("===2 res:%p,_n:%p\n", res, ptr(_n));
  return res ? 0 : -1;
}
int open_bn::from_hex(std::string hex) {
  return BN_hex2bn((BIGNUM**)&_n, hex.c_str());
}
int open_bn::from_dec(std::string dec) {
  return BN_dec2bn((BIGNUM**)&_n, dec.c_str());
}
int open_bn::cmp(const bigint* a, const bigint* b) {
  return BN_cmp(ptr(a->_n), ptr(b->_n));
}
void open_bn::print() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "bn address:{:p}", _n);
  //   cout << hex << "bn address:" << (uint64_t)n << endl;
  //   printf("bn address:%lld\n", (uint64_t)n);
  string hex = to_hex();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "hex:{},len:{}", hex,
                     hex.size());
  string dec = to_dec();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "dec:{},len:{}", dec,
                     dec.size());
  string bin = to_bin();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "bin:{},len:{}",
                     get_bin_stream(bin.data(), bin.size()), bin.size());
}
/****************** open_bn end *******************/

/****************** open_ecc_point begin *******************/

open_point::open_point(const curve* c) {
  _open_c = (open_curve*)c;
  _p = EC_POINT_new(_open_c->_ec_group);
  if (!_p) _err_code = -1;
};
open_point::~open_point() {
  if (_p) EC_POINT_free(_p);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~open_point free");
};
std::string open_point::to_bin() {
  //   unsigned char buf[512];
  //   size_t buf_len = 512;
  char* pbuf = nullptr;
  int ret =
      EC_POINT_point2buf(_open_c->_ec_group, _p, POINT_CONVERSION_COMPRESSED,
                         (unsigned char**)&pbuf, _open_c->_bn_ctx);
  if (ret == 0) return "";
  return string(pbuf, ret);
};
std::string open_point::to_hex() {
  char* res = EC_POINT_point2hex(_open_c->_ec_group, _p,
                                 POINT_CONVERSION_COMPRESSED, _open_c->_bn_ctx);
  string ret(res);
  OPENSSL_free(res);
  return ret;
}
std::unique_ptr<bigint> open_point::to_bn() {
  unique_ptr<bigint> ret = make_unique<open_bn>();
  BIGNUM* res =
      EC_POINT_point2bn(_open_c->_ec_group, _p, POINT_CONVERSION_COMPRESSED,
                        ptr(ret->_n), _open_c->_bn_ctx);
  if (res) return ret;
  return nullptr;
}
int open_point::from_bin(const char* bin, int len) {
  int ret = EC_POINT_oct2point(_open_c->_ec_group, _p, (unsigned char*)bin, len,
                               _open_c->_bn_ctx);
  if (ret == 0) return -1;
  return 0;
};
int open_point::from_hex(const char* hex) {
  printf("===1 point _p:%p\n", _p);
  EC_POINT* res =
      EC_POINT_hex2point(_open_c->_ec_group, hex, _p, _open_c->_bn_ctx);
  printf("===2 point _p:%p,res:%p\n", _p, res);

  return res ? 0 : -1;
}
int open_point::from_bn(const bigint* bn) {
  EC_POINT* res =
      EC_POINT_bn2point(_open_c->_ec_group, ptr(bn->_n), _p, _open_c->_bn_ctx);
  return res ? 0 : -1;
}
void open_point::print() {
  string bin = to_bin();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "bin:{},len:{}",
                     get_bin_stream(bin.data(), bin.size()), bin.size());
  string hex = to_hex();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "hex:{},len:{}", hex,
                     hex.size());
};

/****************** open_ecc_point end *******************/
/****************** open_ecc_curve start *******************/
unordered_map<string, int> curve_map{
    {"secp256k1", NID_secp256k1},
    {"prime256v1", NID_X9_62_prime256v1},
    {"secp384r1", NID_secp384r1},
};
open_curve::open_curve(string curve_name) : curve(curve_name) {
  auto is_find = curve_map.find(_curve_name);
  if (is_find == curve_map.end()) _curve_name = "secp256k1";
  int id = curve_map[_curve_name];
  _ec_group = EC_GROUP_new_by_curve_name(id);  // NIST P-256
  _bn_ctx = BN_CTX_new();
  _order = BN_new();
  EC_GROUP_get_order(_ec_group, _order, _bn_ctx);
  //   BIGNUM* bn = BN_CTX_get(_bn_ctx);
  const EC_POINT* G_1 = EC_GROUP_get0_generator(_ec_group);
  const EC_POINT* G_2 = EC_GROUP_get0_generator(_ec_group);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), ">>>{}: G_1:{},G_2:{}",
                     _curve_name, (uint64_t)G_1, (uint64_t)G_2);
};
open_curve::~open_curve() {
  if (_ec_group) EC_GROUP_free(_ec_group);
  if (_bn_ctx) BN_CTX_free(_bn_ctx);
  if (_order) BN_free(_order);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~open_curve free");
};
std::unique_ptr<bigint> open_curve::gen_rand_bn() {
  auto bn = make_unique<open_bn>();
  int fg = BN_rand_range(ptr(bn->_n), _order);
  if (fg) return bn;
  return nullptr;
};
std::unique_ptr<bigint> open_curve::new_bn() { return make_unique<open_bn>(); };
std::unique_ptr<point> open_curve::new_point() {
  return make_unique<open_point>(this);
};
bool open_curve::is_on_curve(const point* p) {
  auto pt = (open_point*)p;
  return EC_POINT_is_on_curve(_ec_group, pt->_p, _bn_ctx);
};
std::unique_ptr<point> open_curve::add_const(const point* p1, const point* p2) {
  auto p_a = (open_point*)p1;
  auto p_b = (open_point*)p2;
  auto ret = make_unique<open_point>(this);
  int res = EC_POINT_add(_ec_group, ret->_p, p_a->_p, p_b->_p, _bn_ctx);
  if (res) return ret;
  return nullptr;
};
bool open_curve::add(const point* p1, point* p2) {
  auto p_a = (open_point*)p1;
  auto p_b = (open_point*)p2;
  return EC_POINT_add(_ec_group, p_b->_p, p_a->_p, p_b->_p, _bn_ctx);
};
std::unique_ptr<point> open_curve::scalar_mul_const(const bigint* bn,
                                                    const point* p1) {
  auto p_a = (open_point*)p1;
  auto ret = make_unique<open_point>(this);
  int res =
      EC_POINT_mul(_ec_group, ret->_p, NULL, p_a->_p, ptr(bn->_n), _bn_ctx);
  if (res) return ret;
  return nullptr;
};
bool open_curve::scalar_mul(const bigint* bn, point* p1) {
  auto p_a = (open_point*)p1;
  int res =
      EC_POINT_mul(_ec_group, p_a->_p, NULL, p_a->_p, ptr(bn->_n), _bn_ctx);
  return res;
};
bool open_curve::scalar_mul(const bigint* bn, const point* p1, point* p2) {
  auto p_a = (open_point*)p1;
  auto p_b = (open_point*)p2;
  int res =
      EC_POINT_mul(_ec_group, p_b->_p, NULL, p_a->_p, ptr(bn->_n), _bn_ctx);
  return res;
}
std::unique_ptr<point> open_curve::scalar_base_mul(const bigint* bn) {
  auto ret = make_unique<open_point>(this);
  int res = EC_POINT_mul(_ec_group, ret->_p, ptr(bn->_n), NULL, NULL, _bn_ctx);
  if (res) return ret;
  return nullptr;
};
std::unique_ptr<point> open_curve::get_generator() {
  auto ret = make_unique<open_point>(this);
  int res = EC_POINT_copy(ret->_p, EC_GROUP_get0_generator(_ec_group));
  if (res) return ret;
  return nullptr;
};
std::unique_ptr<point> open_curve::inv_const(const point* p) {
  auto p_a = (open_point*)p;
  auto ret = make_unique<open_point>(this);
  int fg = EC_POINT_copy(ret->_p, p_a->_p);
  if (!fg) return nullptr;
  fg = EC_POINT_invert(_ec_group, ret->_p, _bn_ctx);
  if (fg) return ret;
  return nullptr;
};
bool open_curve::inv(point* p) {
  auto p_a = (open_point*)p;
  int fg = EC_POINT_invert(_ec_group, p_a->_p, _bn_ctx);
  return fg ? true : false;
}
std::unique_ptr<point> open_curve::copy(const point* p) {
  auto p_a = (open_point*)p;
  auto ret = make_unique<open_point>(this);
  int fg = EC_POINT_copy(ret->_p, p_a->_p);
  if (fg) return ret;
  return nullptr;
}
bool open_curve::copy(const point* p, point* dst) {
  auto p_a = (open_point*)p;
  auto p_d = (open_point*)dst;
  int fg = EC_POINT_copy(p_d->_p, p_a->_p);
  if (fg) return true;
  return false;
}

bool open_curve::equal(const point* p, const point* q) {
  open_point *pa = (open_point*)p, *pb = (open_point*)q;
  //   1 if the points are not equal, 0 if they are, or -1 on error
  int fg = EC_POINT_cmp(_ec_group, pa->_p, pb->_p, _bn_ctx);
  return fg == 0 ? true : false;
}
bool open_curve::is_at_infinity(const point* p) {
  open_point* pa = (open_point*)p;
  int fg = EC_POINT_is_at_infinity(_ec_group, pa->_p);
  return fg;
};
bool open_curve::set_to_infinity(point* p) {
  open_point* pa = (open_point*)p;
  int fg = EC_POINT_set_to_infinity(_ec_group, pa->_p);
  return fg ? true : false;
};
/****************** open_ecc_curve end *******************/
class openssl_factory : public EccLibFactory {
 private:
  /* data */
 public:
  openssl_factory(){};
  ~openssl_factory() { cout << "[info]~openssl_factory" << endl; };
  std::unique_ptr<curve> new_curve(std::string curve_name) {
    return make_unique<open_curve>(curve_name);
  };
};
openssl_factory openssl_lib_factory;
// EccLibFactory* get_openssl_factory_ptr() { return new openssl_factory; };
EccLibFactory* openssl_factory_ptr = &openssl_lib_factory;
}  // namespace fucrypto
