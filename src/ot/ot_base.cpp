#include "crypto-protocol/ot_base.h"
#include "crypto-protocol/fuecc.h"
#include "crypto-protocol/fulog.h"
// #include <cereal/types/unordered_map.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/array.hpp>
#include <cereal/archives/binary.hpp>
#include <bits/stdc++.h>
namespace fucrypto {
using namespace std;
// 使用 cereal 可以直接支持标准库类型，可以不需要单独定义结构体
struct np99_msg_AC {
  string A, C;
  template <class Archive>
  void save(Archive& ar) const {
    ar(A, C);
  }
  template <class Archive>
  void load(Archive& ar) {
    ar(A, C);
  }
};
struct np99_msg_PKs {
  vector<string> pks;
  template <class Archive>
  void save(Archive& ar) const {
    ar(pks);
  }
  template <class Archive>
  void load(Archive& ar) {
    ar(pks);
  }
};
np99sender::np99sender() : otsender() {
  _ecc = move((*ecc_lib_map)["openssl"]->new_curve("secp256k1"));
  _hash = move(make_unique<sha256>());
};
np99sender::np99sender(const config_param& param) : otsender() {
  _ecc = move((*ecc_lib_map)[param.ecc_lib_name]->new_curve(param.curve_name));
  _hash = move(make_unique<sha256>());
  //   auto x = _ecc->new_bn();
  //   x->from_dec("12345");
  //   x->print();
};
np99sender::~np99sender() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~np99sender free");
};
int np99sender::send(std::vector<std::array<oc::block, 2>>& pair_keys,
                     conn* sock) {
  int ot_num = pair_keys.size();
  if (ot_num <= 0) return 0;
  //   生成随机点 C
  auto alpha = _ecc->gen_rand_bn();
  if (!alpha) return -1;
  auto C = _ecc->new_point();
  bool fg = _ecc->scalar_base_mul(alpha.get(), C.get());
  if (!fg) return -2;
  //   alpha
  fg = _ecc->gen_rand_bn(alpha.get());
  if (!fg) return -3;
  //   A=alpha*G
  auto A = _ecc->new_point();
  fg = _ecc->scalar_base_mul(alpha.get(), A.get());
  if (!fg) return -4;
  //   cereal 序列化
  //   np99_msg_AC ac;
  array<string, 2> ac;
  ac[0] = A->to_bin();
  ac[1] = C->to_bin();
  if (ac[0].empty() || ac[1].empty()) return -5;
  stringstream ss1;
  cereal::BinaryOutputArchive bin_out_ar(ss1);
  bin_out_ar(ac);
  //   send A C
  sock->send(ss1.str());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "np99 sender send AC ok");
  //   receive pk_i0
  ss1.clear(), ss1.str("");
  vector<string> recv_pks_str;
  string pks_i0 = sock->recv();
  ss1.str(pks_i0);
  cereal::BinaryInputArchive bin_in_ar(ss1);
  bin_in_ar(recv_pks_str);
  if (ot_num != recv_pks_str.size()) return -6;
  //   vector<unique_ptr<point>> recv_pks_str(ot_num);
  //   使用A变量作为pk_i0,不用再创建新的变量了
  auto& pk_i0 = A;
  auto tmp_pk = _ecc->new_point();
  char out_buf[32];
  for (size_t i = 0; i < ot_num; i++) {
    string tmp = recv_pks_str[i];
    // 使用
    pk_i0->from_bin(tmp.data(), tmp.size());
    // alpha*pk_i0
    bool fg = _ecc->scalar_mul(alpha.get(), pk_i0.get(), tmp_pk.get());
    if (!fg) return -10;
    string bin = tmp_pk->to_bin();
    _hash->hasher_reset();
    _hash->hasher_update(bin.data(), bin.size());
    _hash->hasher_final(out_buf, 32);
    pair_keys[i][0] = *(oc::block*)out_buf;
    //
    fg = _ecc->inv(pk_i0.get());
    if (!fg) return -7;
    fg = _ecc->add(C.get(), pk_i0.get());  // C-pk_i0
    if (!fg) return -8;
    fg = _ecc->scalar_mul(alpha.get(), pk_i0.get());
    if (!fg) return -9;
    string bin2 = pk_i0->to_bin();
    _hash->hasher_reset();
    _hash->hasher_update(bin2.data(), bin2.size());
    _hash->hasher_final(out_buf, 32);
    pair_keys[i][1] = *(oc::block*)out_buf;
  }

  return 0;
};
/************* np99receiver **************/
np99receiver::np99receiver() : otreceiver() {
  _ecc = move((*ecc_lib_map)["openssl"]->new_curve("secp256k1"));
  _hash = move(make_unique<sha256>());
};
np99receiver::np99receiver(const config_param& param) : otreceiver() {
  _ecc = move((*ecc_lib_map)[param.ecc_lib_name]->new_curve(param.curve_name));
  _hash = move(make_unique<sha256>());
};
np99receiver::~np99receiver() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~np99receiver free");
};
int np99receiver::receive(const oc::BitVector& choices,
                          std::vector<oc::block>& single_keys, conn* sock) {
  int ot_num = choices.size();
  if (single_keys.size() < ot_num) return -1;
  //   recv A C
  string a_c_str = sock->recv();
  array<string, 2> ac;
  stringstream ss(a_c_str);
  //   反序列化 A C
  cereal::BinaryInputArchive bin_in_ar(ss);
  bin_in_ar(ac);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "np99 receiver recv AC ok");
  auto C = _ecc->new_point();
  int fg = C->from_bin(ac[1].data(), ac[1].size());
  if (fg) return -2;
  // A point
  auto A = _ecc->new_point();
  fg = A->from_bin(ac[0].data(), ac[0].size());
  if (fg) return -13;
  //
  vector<string> pk_i0(ot_num);
  vector<string> k_i_A(ot_num);
  //   vector<unique_ptr<bigint>> sk_i(ot_num);
  auto sk_i = _ecc->new_bn();
  auto k_G = _ecc->new_point();
  for (size_t i = 0; i < ot_num; i++) {
    // ?? move()
    bool fg = _ecc->gen_rand_bn(sk_i.get());
    if (!fg) return -10;
    // int ch = choices[i];
    fg = _ecc->scalar_base_mul(sk_i.get(), k_G.get());
    if (!fg) return -11;
    if (choices[i]) {
      // C-kG
      fg = _ecc->inv(k_G.get());
      if (!fg) return -3;
      fg = _ecc->add(C.get(), k_G.get());
      if (!fg) return -12;
    } else {
      // kG
    }
    string tmp = k_G->to_bin();
    if (tmp.empty()) return -4;
    pk_i0[i] = tmp;
    // ki*A
    auto& k_A = k_G;
    _ecc->scalar_mul(sk_i.get(), A.get(), k_A.get());
    string tmp2 = k_A->to_bin();
    if (tmp2.empty()) return -14;
    k_i_A[i] = tmp2;
  }
  ss.clear(), ss.str("");
  cereal::BinaryOutputArchive bin_out_ar(ss);
  bin_out_ar(pk_i0);
  //   send pk_i0
  sock->send(ss.str());
  // 生成解密密钥

  char out_buf[32];
  for (size_t i = 0; i < ot_num; i++) {
    // bool fg = _ecc->scalar_mul(sk_i[i].get(), a_point.get(), c_point.get());
    // if (!fg) return -5;
    // string bin = c_point->to_bin();
    // if (bin.empty()) return -6;
    _hash->hasher_reset();
    _hash->hasher_update(k_i_A[i].data(), k_i_A[i].size());
    _hash->hasher_final(out_buf, 32);
    single_keys[i] = *(oc::block*)out_buf;
  }
  return 0;
};

}  // namespace fucrypto