#include "crypto-protocol/short_enc.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/utils.h"
#include <bits/stdc++.h>
using namespace std;
namespace fucrypto {
/// @brief
/// @param c
/// @param max_msg_n
/// @return
int short_elgamal::init_short_cipher(curve* c, uint32_t max_msg_n) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "init_short_cipher begin ...");
  string err_info = "";
  scope_guard on_err_exit([&]() {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "error_info:{}...", err_info);
  });
  if (!c) return err_code_short_enc;
  _max_msg_n = max_msg_n;
  _cipher_list.resize(_max_msg_n);
  auto bn = c->new_bn();
  auto m_g = c->new_point();
  if (!bn || !m_g) return err_code_short_enc;
  for (size_t i = 0; i < _max_msg_n; i++) {
    int fg = 0;
    fg = bn->from_dec(to_string(i));
    fg += c->scalar_base_mul(bn.get(), m_g.get());  // m*G
    if (fg != 2) {
      err_info = "compute m*G error";
      return err_code_short_enc;
    }
    string cipher_bin = m_g->to_bin();
    if (cipher_bin.empty()) return err_code_short_enc;
    _cipher_list[i] = cipher_bin;
    uint64_t key = 0;
    if (cipher_bin.size() >= 8)
      key = *(uint64_t*)cipher_bin.data();
    else
      memcpy(&key, cipher_bin.data(), cipher_bin.size());
    _cipher_map[key].push_back(make_pair(cipher_bin, i));
    if (i < 5 && i < _max_msg_n) {
      //   cout << "i:" << i << "," << m_g->to_hex() << ",key:" << key
      //        << ",bin.size:" << cipher_bin.size() << endl;
      SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                         "i:{},map_key:{},cipher_bin.size:{}", i, key,
                         cipher_bin.size());
    }
  }
  //   for (auto it = _cipher_map.begin(); it != _cipher_map.end(); it++) {
  //     cout << "key:" << it->first << ",vec_size:" << it->second.size() <<
  //     endl;
  //   }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "_cipher_map.size:{}",
                     _cipher_map.size());
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "init_short_cipher end ...");
  on_err_exit.dismiss();
  return 0;
};
/// @brief
/// @param mG_to_m
/// @return
uint32_t short_elgamal::_mg_to_short_msg(const std::string& mG_to_m) {
  //   返回 -1 表示转化出错
  if (mG_to_m.empty()) return -1;
  uint64_t key = 0;
  if (mG_to_m.size() >= 8)
    key = *(uint64_t*)mG_to_m.data();
  else
    memcpy(&key, mG_to_m.data(), mG_to_m.size());
  auto res = _cipher_map[key];
  int res_n = res.size();
  if (res_n == 0) return -1;
  if (res_n == 1) {
    if (mG_to_m == res[0].first)
      return res[0].second;
    else
      return -1;
  }
  for (size_t i = 0; i < res.size(); i++)
    if (mG_to_m == res[i].first) return res[i].second;
  return -1;
}
/// @brief static
std::unordered_map<uint64_t, std::vector<std::pair<std::string, uint32_t>>>
    short_elgamal::_cipher_map = {};
/// @brief static
uint32_t short_elgamal::_max_msg_n = 256;
std::vector<std::string> short_elgamal::_cipher_list = {};

short_elgamal::short_elgamal(){};
short_elgamal::~short_elgamal() { cout << "~short_elgamal free" << endl; };
/// @brief
/// @param plains
/// @param cipher_0
/// @param ciphers_1
/// @param pk
/// @param c
/// @return
int short_elgamal::enc_list_fast(const std::vector<uint32_t>& plains,
                                 std::string& cipher_0,
                                 std::vector<std::string>& ciphers_1,
                                 const point* pk, curve* c) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "enc_list_fast begin ...");
  string err_info = "";
  scope_guard on_err_exit([&]() {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "error_info:{}...", err_info);
  });
  if (!pk || !c) return err_code_short_enc;
  int plains_num = plains.size();
  ciphers_1.resize(plains_num);
  //   随机值 t
  auto t = c->gen_rand_bn();
  //   t->from_dec("1000");
  //   auto m = c->new_bn();
  //   c0=tG,c1=tY+mG
  auto c0 = c->new_point();
  auto t_y = c->new_point();
  if (!t || !c0 || !t_y) return err_code_short_enc;
  int fg = 0;
  // c0=tG
  fg = c->scalar_base_mul(t.get(), c0.get());
  // tY
  fg += c->scalar_mul(t.get(), pk, t_y.get());
  cipher_0 = c0->to_bin();
  if (fg != 2 || cipher_0.empty()) {
    err_info = "compute tG tY error";
    return err_code_short_enc;
  }
  auto& m_g = c0;
  for (size_t i = 0; i < plains_num; i++) {
    // c1=tY+mG
    // m->from_dec(to_string(i));                    // m
    // fg = c->scalar_base_mul(m.get(), m_g.get());  // mG
    // if (!fg) return err_code_short_enc;
    if (plains[i] < _max_msg_n) {
      int fg = 0;
      string bin = _cipher_list[plains[i]];
      fg = m_g->from_bin(bin.data(), bin.size());
      fg += c->add(t_y.get(), m_g.get());
      if (fg != 2) {
        err_info = "compute tY+mG error";
        return err_code_short_enc;
      }
      ciphers_1[i] = m_g->to_bin();
    } else {
      return err_code_short_enc;
    }
  }
  on_err_exit.dismiss();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "enc_list_fast end ...");
  return 0;
}
/// @brief
/// @param cipher_0
/// @param ciphers_1
/// @param plains
/// @param sk
/// @param c
/// @return
int short_elgamal::dec_list_fast(const std::string& cipher_0,
                                 const std::vector<std::string>& ciphers_1,
                                 vector<uint32_t>& plains, const bigint* sk,
                                 curve* c) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "start dec_list_fast begin ...");
  string error_info = "";
  scope_guard on_err_exit([&]() {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "error_info:{}...",
                        error_info);
  });
  if (!sk || !c) return err_code_short_enc;
  int num = ciphers_1.size();
  plains.resize(num);
  memset(plains.data(), -1, plains.size() * sizeof(uint32_t));
  auto c0 = c->new_point();
  auto c1 = c->new_point();
  //   auto tmp = c->new_point();
  //   auto sk_c0_inv = c->new_point();
  auto& sk_c0_inv = c0;
  if (!c0 || !c1) return err_code_short_enc;
  int fg = 0;
  fg = (bool)c0->from_bin(cipher_0.data(), cipher_0.size());  // C0
  fg += c->scalar_mul(sk, sk_c0_inv.get());                   // sk*C0
  fg += c->inv(sk_c0_inv.get());                              //-sk*C0
  if (fg != 3) {
    error_info = "compute -sk*C0 error";
    return err_code_short_enc;
  }
  //   mG=C1-sk*C0
  for (size_t i = 0; i < num; i++) {
    int fg = 0;
    fg = c1->from_bin(ciphers_1[i].data(), ciphers_1[i].size());
    fg += c->add(sk_c0_inv.get(), c1.get());  // C1-sk*C0
    if (fg != 2) {
      error_info = "mG=C1-sk*C0 error i:" + to_string(i);
      return err_code_short_enc;
    }
    string m_g = c1->to_bin();
    plains[i] = _mg_to_short_msg(m_g);
  }
  on_err_exit.dismiss();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "start dec_list_fast end ...");
  return 0;
}
/// @brief
/// @param cipher_0
/// @param ciphers_1
/// @param pk
/// @param c
/// @return
int short_elgamal::enc_list_cipher_add(const std::vector<std::string>& cipher_0,
                                       std::vector<std::string>* ciphers_1,
                                       const point* pk, curve* c) {
  //   密文向量个数
  int cipher_vector_num = cipher_0.size();
  if (cipher_vector_num <= 1) return 0;
  int vector_size = ciphers_1[0].size();
  //   check vector_size
  for (size_t i = 1; i < cipher_vector_num; i++) {
    if (vector_size != ciphers_1[i].size()) return err_code_short_enc;
  }
  //
  auto p0 = c->new_point();
  auto p1 = c->new_point();
  for (size_t i = 0; i < vector_size; i++) {
    string& tmp = ciphers_1[0][i];
    p0->from_bin(tmp.data(), tmp.size());
    for (size_t j = 1; j < cipher_vector_num; j++) {
      p1->from_bin(ciphers_1[j][i].data(), ciphers_1[j][i].size());
      c->add(p1.get(), p0.get());
    }
    tmp = p0->to_bin();
  }

  return 0;
}
//
int short_elgamal::gen_key(point* pk, bigint* sk, curve* c) {
  //   c->new_bn();
  return 0;
}
}  // namespace fucrypto
