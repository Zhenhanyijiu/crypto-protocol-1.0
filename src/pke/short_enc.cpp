#include "crypto-protocol/short_enc.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/utils.h"
#include <bits/stdc++.h>
using namespace std;
namespace fucrypto {
int short_elgamal::init_short_cipher(curve* c, uint32_t msg_n) {
  string err_info = "";
  scope_guard on_err_exit([&]() {});
  if (!c) return err_code_short_enc;
  _msg_n = msg_n;
  _cipher_list.resize(msg_n);
  auto bn = c->new_bn();
  auto g1 = c->new_point();
  if (!bn || !g1) return err_code_short_enc;
  for (size_t i = 0; i < _msg_n; i++) {
    bn->from_dec(to_string(i));
    bool fg = c->scalar_base_mul(bn.get(), g1.get());
    if (!fg) return err_code_short_enc;
    string cipher_bin = g1->to_bin();
    if (cipher_bin.empty()) return err_code_short_enc;
    _cipher_list[i] = cipher_bin;
    uint64_t key = 0;
    if (cipher_bin.size() >= 8)
      key = *(uint64_t*)cipher_bin.data();
    else
      memcpy(&key, cipher_bin.data(), cipher_bin.size());

    _cipher_map[key].push_back(make_pair(cipher_bin, i));
    // _cipher_map[];
    cout << "i:" << i << "," << g1->to_hex() << ",key:" << key
         << ",bin.size:" << cipher_bin.size() << endl;
  }
  for (auto it = _cipher_map.begin(); it != _cipher_map.end(); it++) {
    cout << "key:" << it->first << ",vec_size:" << it->second.size() << endl;
  }
  on_err_exit.dismiss();
  return 0;
};
//
uint32_t short_elgamal::_get_short_msg(const std::string& m_g) {
  if (m_g.empty()) return -1;
  uint64_t key = 0;
  if (m_g.size() >= 8)
    key = *(uint64_t*)m_g.data();
  else
    memcpy(&key, m_g.data(), m_g.size());
  auto res = _cipher_map[key];
  int res_n = res.size();
  if (res_n == 0) return -1;
  if (res_n == 1) {
    if (m_g == res[0].first)
      return res[0].second;
    else
      return -1;
  }
  for (size_t i = 0; i < res.size(); i++)
    if (m_g == res[i].first) return res[i].second;
  return -1;
}
//
std::unordered_map<uint64_t, std::vector<std::pair<std::string, uint32_t>>>
    short_elgamal::_cipher_map = {};
uint32_t short_elgamal::_msg_n = 256;
std::vector<std::string> short_elgamal::_cipher_list = {};

short_elgamal::short_elgamal(){};
short_elgamal::~short_elgamal() { cout << ">> ~short_elgamal free" << endl; };
// enc
int short_elgamal::enc_list(const std::vector<uint32_t>& plains,
                            std::vector<std::array<std::string, 2>>& ciphers,
                            const point* pk, curve* c) {
  if (!pk || !c) return err_code_short_enc;
  int plains_num = plains.size();
  ciphers.resize(plains_num);
  //   随机值 t
  auto t = c->gen_rand_bn();
  //   t->from_dec("1000");
  auto m = c->new_bn();
  //   c0=tG,c1=tY+mG
  auto c0 = c->new_point();
  auto t_y = c->new_point();
  auto m_g = c->new_point();
  if (!t || !m || !c0 || !t_y || !m_g) return err_code_short_enc;
  bool fg;
  // c0=tG
  fg = c->scalar_base_mul(t.get(), c0.get());
  if (!fg) return err_code_short_enc;
  // tY
  fg = c->scalar_mul(t.get(), pk, t_y.get());
  if (!fg) return err_code_short_enc;
  //
  for (size_t i = 0; i < plains_num; i++) {
    ciphers[i][0] = c0->to_bin();
    // c1=tY+mG
    // m->from_dec(to_string(i));                    // m
    // fg = c->scalar_base_mul(m.get(), m_g.get());  // mG
    // if (!fg) return err_code_short_enc;
    string bin = _cipher_list[i];
    m_g->from_bin(bin.data(), bin.size());
    c->add(t_y.get(), m_g.get());
    ciphers[i][1] = m_g->to_bin();
  }
  return 0;
}
int short_elgamal::dec_list(const vector<array<string, 2>>& ciphers,
                            vector<uint32_t>& plains, const bigint* sk,
                            curve* c) {
  string error_info = "";
  scope_guard on_err_exit([&]() {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "error_info:{}...",
                        error_info);
  });
  if (!sk || !c) return err_code_short_enc;
  int num = ciphers.size();
  plains.resize(num);
  memset(plains.data(), -1, plains.size() * sizeof(uint32_t));
  auto c0 = c->new_point();
  auto c1 = c->new_point();
  if (!c0 || !c1) return err_code_short_enc;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "start dec ...");
  //   mG=C1-sk*C0
  for (size_t i = 0; i < num; i++) {
    int fg = 0;
    fg = (bool)c0->from_bin(ciphers[i][0].data(), ciphers[i][0].size());
    fg += (bool)c1->from_bin(ciphers[i][1].data(), ciphers[i][1].size());
    fg += c->scalar_mul(sk, c0.get());  // sk*C0
    fg += c->inv(c0.get());             //-sk*C0
    fg += c->add(c1.get(), c0.get());   // c0==mG
    if (fg != 5) {
      error_info = "mG=C1-sk*C0 error i:" + to_string(i);
      return err_code_short_enc;
    }
    string m_g = c0->to_bin();
    plains[i] = _get_short_msg(m_g);
  }
  on_err_exit.dismiss();
  return 0;
}

//
int short_elgamal::gen_key(point* pk, bigint* sk, curve* c) {
  //   c->new_bn();
  return 0;
}
}  // namespace fucrypto
