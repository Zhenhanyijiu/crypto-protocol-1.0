#ifndef __FU_SHORT_ENC_H__
#define __FU_SHORT_ENC_H__
#include "crypto-protocol/fuecc_open.h"
#include <bits/stdc++.h>
namespace fucrypto {
#define err_code_short_enc 2000;
class short_elgamal {
 private:
  //   curve* _c;

 public:
  static std::unordered_map<uint64_t,
                            std::vector<std::pair<std::string, uint32_t>>>
      _cipher_map;
  static uint32_t _msg_n;

 public:
  static int init_short_cipher(curve* c, uint32_t msg_n = 256);

  short_elgamal();
  ~short_elgamal();
  int gen_key(point* pk, bigint* sk);
  //   int set_key();
  int enc_list(const std::vector<uint32_t>& plains,
               std::vector<std::array<std::string, 2>>& ciphers,
               const point* pk, curve* c);
  int dec_list(const std::vector<std::array<std::string, 2>>& ciphers,
               std::vector<uint32_t>& plains, const bigint* sk, curve* c);
};
}  // namespace fucrypto
#endif