#include "crypto-protocol/fuecc_botan.h"
#include "crypto-protocol/fulog.h"
#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <bits/stdc++.h>
// #include <openssl/obj_mac.h>

using namespace std;
namespace fucrypto {
/****************** botan_bn begin *******************/
// #define ptr(n) ((BIGNUM*)n)
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
botan_bn::botan_bn() { _bn = BigInt("0"); };
botan_bn::botan_bn(botan_bn&& n) { _bn = n._bn; }
botan_bn& botan_bn::operator=(botan_bn&& n) {
  _bn = n._bn;
  return *this;
}
botan_bn::~botan_bn() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~botan_bn free");
}
int botan_bn::set_one() {
  _bn.set_bit(0);
  return 1;
}
int botan_bn::set_zero() {
  _bn = BigInt("0");
  return 1;
}
int botan_bn::set_long(long a) {
  _bn.set_word_at(0, a);
  return 1;
}
std::string botan_bn::to_bin() {
  string ret(_bn.bytes(), '\0');
  _bn.binary_encode((uint8_t*)ret.data());
  return ret;
}
std::string botan_bn::to_hex() { return _bn.to_hex_string(); }
std::string botan_bn::to_dec() { return _bn.to_dec_string(); }
bool botan_bn::from_bin(const char* bin, int len) {
  _bn.binary_decode((uint8_t*)bin, len);
  return 1;
}
bool botan_bn::from_hex(std::string hex) {
  _bn = _bn.decode((uint8_t*)hex.data(), hex.size(), BigInt::Base::Hexadecimal);
  return 1;
}
bool botan_bn::from_dec(std::string dec) {
  _bn = _bn.decode((uint8_t*)dec.data(), dec.size(), BigInt::Base::Decimal);
  return 1;
}
int botan_bn::cmp(const bigint* a) {
  // returns -1 if a < b, 0 if a == b and 1 if a > b
  //   return BN_cmp(ptr(a->_n), ptr(b->_n));
  botan_bn* a_bn = (botan_bn*)a;
  return _bn.cmp(a_bn->_bn);
}
void botan_bn::print() {
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
/****************** botan_bn end *******************/

/****************** botan_ecc_point begin *******************/

botan_point::botan_point(const curve* c) {
  _botan_c = (botan_curve*)c;
  _p = _botan_c->_ec_group.zero_point();
};
botan_point::~botan_point() {
  //   if (_p) EC_POINT_free(_p);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~botan_point free");
};
std::string botan_point::to_bin() {
  auto ret = _p.encode(PointGFp::COMPRESSED);
  //   auto ret = EC2OSP(_p, PointGFp::COMPRESSED);
  return string((char*)ret.data(), ret.size());
};
std::string botan_point::to_hex() {
  string tobin = to_bin();
  if (tobin.empty()) return "";
  botan_bn bn;
  bn.from_bin(tobin.data(), tobin.size());
  return bn.to_hex();
}
std::unique_ptr<bigint> botan_point::to_bn() {
  unique_ptr<botan_bn> ret = make_unique<botan_bn>();
  if (!ret) return ret;
  ret->_bn = _p.get_affine_x();
  return ret;
}
bool botan_point::from_bin(const char* bin, int len) {
  //   vector<uint8_t> bin_vec(len);
  //   memcpy(bin_vec.data(), bin, len);
  //   _p = OS2ECP(bin, len, _botan_c->_ec_group);
  _p = _botan_c->_ec_group.OS2ECP((uint8_t*)bin, len);
  //   bool fg = _p.on_the_curve();
  return _p.on_the_curve();
};
bool botan_point::from_hex(const char* hex) {
  botan_bn bn;
  bn.from_hex(hex);
  string bin_ = bn.to_bin();
  return from_bin(bin_.data(), bin_.size());
}
bool botan_point::from_bn(const bigint* bn) {
  //   EC_POINT* res =
  //       EC_POINT_bn2point(_open_c->_ec_group, ptr(bn->_n), _p,
  //       _open_c->_bn_ctx);
  //   if (!res) return 0;
  //   if (!_p) _p = res;
  //   botan_bn* bn_ = (botan_bn*)bn;
  //   bn_.
  return 1;
}
void botan_point::print() {
  string bin = to_bin();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "bin:{},len:{}",
                     get_bin_stream(bin.data(), bin.size()), bin.size());
  string hex = to_hex();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "hex:{},len:{}", hex,
                     hex.size());
};

/****************** botan_ecc_point end *******************/
/****************** botan_ecc_curve start *******************/
// unordered_map<string, int> curve_map{
//     {"secp256k1", NID_secp256k1},
//     {"prime256v1", NID_X9_62_prime256v1},
//     {"secp384r1", NID_secp384r1},
// };
botan_curve::botan_curve(string curve_name) : curve(curve_name) {
  _rng = make_unique<AutoSeeded_RNG>();
  //   auto is_find = curve_map.find(_curve_name);
  //   if (is_find == curve_map.end()) _curve_name = "secp256k1";
  _ec_group = EC_Group(_curve_name);
  auto G = _ec_group.get_base_point();
  //   BIGNUM* bn = BN_CTX_get(_bn_ctx);
  //   const EC_POINT* G_1 = EC_GROUP_get0_generator(_ec_group);
  //   const EC_POINT* G_2 = EC_GROUP_get0_generator(_ec_group);
  auto x = G.get_affine_x();
  auto y = G.get_affine_y();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     ">>_curve_name:{}: G_x:{},G_y:{}", _curve_name,
                     x.to_hex_string(), y.to_hex_string());
};
botan_curve::~botan_curve() {
  //   if (_ec_group) EC_GROUP_free(_ec_group);
  //   if (_bn_ctx) BN_CTX_free(_bn_ctx);
  //   if (_order) BN_free(_order);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~botan_curve free");
};
std::unique_ptr<bigint> botan_curve::gen_rand_bn() {
  auto bn = make_unique<botan_bn>();
  //   int fg = BN_rand_range(ptr(bn->_n), _order);
  //   if (fg) return bn;
  //   return nullptr;
  if (!bn) return bn;
  bn->_bn = _ec_group.random_scalar(*_rng);
  return bn;
};
bool botan_curve::gen_rand_bn(bigint* bn) {
  // return BN_rand_range(ptr(bn->_n), _order);
  botan_bn* bn_ = (botan_bn*)bn;
  if (!bn_) return false;
  bn_->_bn = _ec_group.random_scalar(*_rng);
  return true;
}
std::unique_ptr<bigint> botan_curve::new_bn() {
  return make_unique<botan_bn>();
};
std::unique_ptr<point> botan_curve::new_point() {
  auto ret = make_unique<botan_point>(this);
  if (!ret) return ret;
  //   ret->_p = _ec_group.zero_point();
  return ret;
};
bool botan_curve::is_on_curve(const point* p) {
  auto pt = (botan_point*)p;
  return pt->_p.on_the_curve();
  //   return EC_POINT_is_on_curve(_ec_group, pt->_p, _bn_ctx);
};
bool botan_curve::add(const point* p1, const point* p2, point* ret) {
  auto p_a = (botan_point*)p1;
  auto p_b = (botan_point*)p2;
  auto p_ret = (botan_point*)ret;
  p_ret->_p = p_a->_p + p_b->_p;
  return true;
};
bool botan_curve::add(const point* p1, point* p2) {
  auto p_a = (botan_point*)p1;
  auto p_b = (botan_point*)p2;
  //   return EC_POINT_add(_ec_group, p_b->_p, p_a->_p, p_b->_p, _bn_ctx);
  p_b->_p = p_a->_p + p_b->_p;
  return true;
};

bool botan_curve::scalar_mul(const bigint* bn, point* p1) {
  auto p_a = (botan_point*)p1;
  auto bn_ = (botan_bn*)bn;
  //   int res =
  //       EC_POINT_mul(_ec_group, p_a->_p, NULL, p_a->_p, ptr(bn->_n),
  //       _bn_ctx);
  //   return res;
  p_a->_p = bn_->_bn * p_a->_p;
  //   BigInt zero("0");
  //   p_a->_p = _ec_group.point_multiply(zero, p_a->_p, bn_->_bn);
  return true;
};
bool botan_curve::scalar_mul(const bigint* bn, const point* p1, point* p2) {
  auto p_a = (botan_point*)p1;
  auto p_b = (botan_point*)p2;
  auto bn_ = (botan_bn*)bn;
  p_b->_p = bn_->_bn * p_a->_p;
  return true;
}
bool botan_curve::scalar_base_mul(const bigint* bn, point* ret) {
  auto p_ret = (botan_point*)ret;
  auto G = _ec_group.get_base_point();
  auto bn_ = (botan_bn*)bn;
  p_ret->_p = bn_->_bn * G;
  return true;
};
std::unique_ptr<point> botan_curve::get_generator() {
  auto ret = make_unique<botan_point>(this);
  if (!ret) return ret;
  ret->_p = _ec_group.get_base_point();
  return ret;
};
bool botan_curve::inv(const point* p, point* ret) {
  auto p_a = (botan_point*)p;
  auto p_ret = (botan_point*)ret;
  p_ret->_p = -p_a->_p;
  return true;
};
bool botan_curve::inv(point* p) {
  auto p_a = (botan_point*)p;
  p_a->_p = -p_a->_p;
  return true;
}
std::unique_ptr<point> botan_curve::copy(const point* p) {
  auto p_a = (botan_point*)p;
  auto ret = make_unique<botan_point>(this);
  if (!ret) return ret;
  ret->_p = p_a->_p;
  return ret;
}
bool botan_curve::copy(const point* p, point* dst) {
  auto p_a = (botan_point*)p;
  auto p_d = (botan_point*)dst;
  p_d->_p = p_a->_p;
  return true;
}

bool botan_curve::equal(const point* p, const point* q) {
  botan_point *pa = (botan_point*)p, *pb = (botan_point*)q;
  return pa->_p == pb->_p;
}
bool botan_curve::is_at_infinity(const point* p) {
  botan_point* pa = (botan_point*)p;
  return pa->_p.is_zero();
};
bool botan_curve::set_to_infinity(point* p) {
  botan_point* pa = (botan_point*)p;
  pa->_p = pa->_p.zero();
  return true;
};
/****************** botan_ecc_curve end *******************/
}  // namespace fucrypto