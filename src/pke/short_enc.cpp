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
  auto bn = c->new_bn();
  auto g1 = c->new_point();
  if (!bn || !g1) return err_code_short_enc;
  for (size_t i = 0; i < _msg_n; i++) {
    bn->from_dec(to_string(i));
    bool fg = c->scalar_base_mul(bn.get(), g1.get());
    if (!fg) return err_code_short_enc;
    string cipher_bin = g1->to_bin();
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
std::unordered_map<uint64_t, std::vector<std::pair<std::string, uint32_t>>>
    short_elgamal::_cipher_map = {};
uint32_t short_elgamal::_msg_n = 256;
short_elgamal::short_elgamal(){};
short_elgamal::~short_elgamal() { cout << "::~short_elgamal free" << endl; };
// enc
int enc_list(const std::vector<uint32_t>& plains,
             std::vector<std::array<std::string, 2>>& ciphers, const point* pk,
             curve* c) {
  if (!pk || !c) return err_code_short_enc;
  int plains_num = plains.size();
  ciphers.resize(plains_num);
  //   随机值 t
  auto t = c->gen_rand_bn();
  //   c0=tG,c1=tY+mG
  auto c0 = c->new_point();
  auto c1 = c->new_point();
  if (!t || !c0 || !c1) return err_code_short_enc;
  bool fg;
  for (size_t i = 0; i < plains_num; i++) {
    // c0
    fg = c->scalar_base_mul(t.get(), c0.get());
    if (!fg) return err_code_short_enc;
    ciphers[i][0] = c0->to_bin();
    // c1=tY+mG
    fg = c->scalar_mul(t.get(), pk, c0.get());
    if (!fg) return err_code_short_enc;
    t->from_dec(to_string(i));                   // m
    fg = c->scalar_base_mul(t.get(), c1.get());  // mG
    if (!fg) return err_code_short_enc;
    ciphers[i][1] = c0->to_bin();
  }
  return 0;
}
int dec_list(const std::vector<std::array<std::string, 2>>& ciphers,
             std::vector<uint32_t>& plains, const bigint* sk, curve* c) {
  if (!sk || !c) return err_code_short_enc;
  int num = ciphers.size();
  plains.resize(num);
  for (size_t i = 0; i < num; i++) {
  }

  return 0;
}

}  // namespace fucrypto
