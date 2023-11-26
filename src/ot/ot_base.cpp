#include "crypto-protocol/ot_base.h"
#include "crypto-protocol/fuecc.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/utils.h"
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
np99sender::np99sender() : ot_sender() {
  //   _ecc = move((*ecc_lib_map)["openssl"]->new_curve("secp256k1"));
  //   _hash = move(make_unique<sha256>());
  config_param param;
  _np99sender(param);
};
np99sender::np99sender(const config_param& param) : ot_sender() {
  _np99sender(param);
};
void np99sender::_np99sender(const config_param& param) {
  string ecc_lib_name = param.ecc_lib_name;
  string hasher_name = param.hasher_name;
  string curve_name = param.curve_name;
  //   auto isok = ecc_lib_map->find(ecc_lib_name);
  //   if (isok == ecc_lib_map->end())
  //     ecc_lib_name = default_config_param.ecc_lib_name;
  //   auto isok2 = (*hasher_map_ptr).find(hasher_name);
  //   if (isok2 == hasher_map_ptr->end())
  //     hasher_name = default_config_param.hasher_name;
  //   _ecc = move((*ecc_lib_map)[ecc_lib_name]->new_curve(curve_name));
  _ecc = new_lib_curve(param);
  _hash = new_hasher(param);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     ">> np99sender hasher:{},ecclib:{},curve_name:{}",
                     hasher_name, ecc_lib_name, curve_name);
};
np99sender::~np99sender() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~np99sender free");
};
int np99sender::send(std::vector<std::array<oc::block, 2>>& pair_keys,
                     conn* sock) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "np99 sender start ...");
  string err_info = "";
  //   出现错误时退出，要处理的逻辑，关闭 sock
  scope_guard on_error_exit([&]() {
    sock->close();
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(),
                        "np99 sender error exit,err_info:{} ...", err_info);
  });
  if (_ecc == nullptr || _hash == nullptr || sock == nullptr) return -1000;
  int ot_num = pair_keys.size();
  if (ot_num <= 0) return err_code_np99;
  //   生成随机点 C
  auto alpha = _ecc->gen_rand_bn();
  if (!alpha) return err_code_np99;
  auto C = _ecc->new_point();
  bool fg = _ecc->scalar_base_mul(alpha.get(), C.get());
  if (!fg) return err_code_np99;
  //   alpha
  fg = _ecc->gen_rand_bn(alpha.get());
  if (!fg) return err_code_np99;
  //   A=alpha*G
  auto A = _ecc->new_point();
  fg = _ecc->scalar_base_mul(alpha.get(), A.get());
  if (!fg) return err_code_np99;
  //   cereal 序列化
  //   np99_msg_AC ac;
  array<string, 2> ac;
  ac[0] = A->to_bin();
  ac[1] = C->to_bin();
  if (ac[0].empty() || ac[1].empty()) return err_code_np99;
  stringstream ss1;
  try {
    cereal::BinaryOutputArchive bin_out_ar(ss1);
    bin_out_ar(ac);
  } catch (const std::exception& e) {
    err_info = e.what();
    return err_code_np99;
  }

  //   send A C
  sock->send(ss1.str());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "np99 sender send AC");
  //   receive pk_i0
  ss1.clear(), ss1.str("");
  vector<string> recv_pks_str;
  string pks_i0 = sock->recv();
  if (pks_i0.empty()) {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(),
                        "np99 sender recv pk_i0 not ok");
    return err_code_np99;
  }
  ss1.str(pks_i0);
  try {
    cereal::BinaryInputArchive bin_in_ar(ss1);
    bin_in_ar(recv_pks_str);
  } catch (const cereal::Exception& e) {
    err_info = e.what();
    return err_code_np99;
  }

  if (ot_num != recv_pks_str.size()) return err_code_np99;
  //   vector<unique_ptr<point>> recv_pks_str(ot_num);
  //   使用A变量作为pk_i0,不用再创建新的变量了
  auto& pk_i0 = A;
  auto tmp_pk = _ecc->new_point();
  if (!tmp_pk) return err_code_np99;
  char out_buf[32];
  for (size_t i = 0; i < ot_num; i++) {
    string tmp = recv_pks_str[i];
    // 使用
    if (pk_i0->from_bin(tmp.data(), tmp.size()) == 0) return err_code_np99;
    // alpha*pk_i0
    bool fg = _ecc->scalar_mul(alpha.get(), pk_i0.get(), tmp_pk.get());
    if (!fg) return err_code_np99;
    string bin = tmp_pk->to_bin();
    if (bin.empty()) return err_code_np99;
    _hash->hasher_reset();
    _hash->hasher_update(bin.data(), bin.size());
    _hash->hasher_final(out_buf, 32);
    pair_keys[i][0] = *(oc::block*)out_buf;
    //
    fg = _ecc->inv(pk_i0.get());
    if (!fg) return err_code_np99;
    fg = _ecc->add(C.get(), pk_i0.get());  // C-pk_i0
    if (!fg) return err_code_np99;
    fg = _ecc->scalar_mul(alpha.get(), pk_i0.get());
    if (!fg) return err_code_np99;
    string bin2 = pk_i0->to_bin();
    if (bin2.empty()) return err_code_np99;
    _hash->hasher_reset();
    _hash->hasher_update(bin2.data(), bin2.size());
    _hash->hasher_final(out_buf, 32);
    pair_keys[i][1] = *(oc::block*)out_buf;
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "np99 sender end ...");
  on_error_exit.dismiss();
  return 0;
};
/************* np99receiver **************/
np99receiver::np99receiver() : ot_receiver() {
  //   _ecc = move((*ecc_lib_map)["openssl"]->new_curve("secp256k1"));
  //   _hash = move(make_unique<sha256>());
  config_param param;
  _np99receiver(param);
};
np99receiver::np99receiver(const config_param& param) : ot_receiver() {
  _np99receiver(param);
};
void np99receiver::_np99receiver(const config_param& param) {
  string ecc_lib_name = param.ecc_lib_name;
  string hasher_name = param.hasher_name;
  string curve_name = param.curve_name;
  //   auto isok = ecc_lib_map->find(ecc_lib_name);
  //   if (isok == ecc_lib_map->end())
  //     ecc_lib_name = default_config_param.ecc_lib_name;
  //   auto isok2 = (*hasher_map_ptr).find(hasher_name);
  //   if (isok2 == hasher_map_ptr->end())
  //     hasher_name = default_config_param.hasher_name;
  //   _ecc = move((*ecc_lib_map)[ecc_lib_name]->new_curve(curve_name));
  _ecc = new_lib_curve(param);
  _hash = new_hasher(param);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     ">> np99receiver hasher:{},ecclib:{},curve_name:{}",
                     hasher_name, ecc_lib_name, curve_name);
};
np99receiver::~np99receiver() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~np99receiver free");
};
int np99receiver::receive(const oc::BitVector& choices,
                          std::vector<oc::block>& single_keys, conn* sock) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "np99 receiver start ...");
  string err_info = "";
  //   出现错误时退出，要处理的逻辑，关闭 sock
  scope_guard on_error_exit([&]() {
    sock->close();
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(),
                        "np99 receiver error exit,err_info:{} ...", err_info);
  });
  if (!_ecc || !_hash || !sock) return err_code_np99;
  int ot_num = choices.size();
  if (single_keys.size() < ot_num) return err_code_np99;
  //   recv A C
  string a_c_str = sock->recv();
  if (a_c_str.empty()) return err_code_np99;
  array<string, 2> ac;
  stringstream ss(a_c_str);
  //   反序列化 A C
  try {
    cereal::BinaryInputArchive bin_in_ar(ss);
    bin_in_ar(ac);
  } catch (const cereal::Exception& e) {
    err_info = e.what();
    return err_code_np99;
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "np99 receiver recv AC");
  auto C = _ecc->new_point();
  int fg = C->from_bin(ac[1].data(), ac[1].size());
  if (!fg) return err_code_np99;
  // A point
  auto A = _ecc->new_point();
  fg = A->from_bin(ac[0].data(), ac[0].size());
  if (!fg) return err_code_np99;
  //
  vector<string> pk_i0(ot_num);
  vector<string> k_i_A(ot_num);
  //   vector<unique_ptr<bigint>> sk_i(ot_num);
  auto sk_i = _ecc->new_bn();
  auto k_G = _ecc->new_point();
  if (!sk_i || !k_G) return err_code_np99;
  for (size_t i = 0; i < ot_num; i++) {
    // ?? move()
    bool fg = _ecc->gen_rand_bn(sk_i.get());
    if (!fg) return err_code_np99;
    // int ch = choices[i];
    fg = _ecc->scalar_base_mul(sk_i.get(), k_G.get());
    if (!fg) return err_code_np99;
    if (choices[i]) {
      // C-kG
      fg = _ecc->inv(k_G.get());
      if (!fg) return err_code_np99;
      fg = _ecc->add(C.get(), k_G.get());
      if (!fg) return err_code_np99;
    } else {
      // kG
    }
    string tmp = k_G->to_bin();
    if (tmp.empty()) return err_code_np99;
    pk_i0[i] = tmp;
    // ki*A
    auto& k_A = k_G;
    fg = _ecc->scalar_mul(sk_i.get(), A.get(), k_A.get());
    if (!fg) return err_code_np99;
    string tmp2 = k_A->to_bin();
    if (tmp2.empty()) return err_code_np99;
    k_i_A[i] = tmp2;
  }
  ss.clear(), ss.str("");
  try {
    cereal::BinaryOutputArchive bin_out_ar(ss);
    bin_out_ar(pk_i0);
  } catch (const cereal::Exception& e) {
    err_info = e.what();
    return err_code_np99;
  }
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
  //   no error occur
  on_error_exit.dismiss();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "np99 receiver end ...");
  return 0;
};

}  // namespace fucrypto