#ifndef __FU_SHORT_ENC_H__
#define __FU_SHORT_ENC_H__
#include "crypto-protocol/fuecc_open.h"
#include <bits/stdc++.h>
namespace fucrypto {
#define err_code_short_enc 2000;
class short_elgamal {
 private:
  //   curve* _c;
  uint32_t _mg_to_short_msg(const std::string& mG_to_m);

 public:
  static std::unordered_map<uint64_t,
                            std::vector<std::pair<std::string, uint32_t>>>
      _cipher_map;
  static std::vector<std::string> _cipher_list;
  static uint32_t _max_msg_n;

 public:
  static int init_short_cipher(curve* c, uint32_t max_msg_n = 256);

  short_elgamal();
  ~short_elgamal();

  int enc_batch(const std::vector<uint32_t>& plains,
                std::vector<std::array<std::string, 2>>& ciphers,
                const point* pk, curve* c);
  int dec_batch(const std::vector<std::array<std::string, 2>>& ciphers,
                std::vector<uint32_t>& plains, const bigint* sk, curve* c);
  int enc_batch_by_map(const std::vector<uint32_t>& plains,
                       std::vector<std::array<std::string, 2>>& ciphers,
                       const point* pk, curve* c);
  int dec_batch_by_map(const std::vector<std::array<std::string, 2>>& ciphers,
                       std::vector<uint32_t>& plains, const bigint* sk,
                       curve* c);
  // c0 预计算放到 ciphers[i][0]
  int enc_batch_pre_c0(const std::vector<uint32_t>& plains,
                       const std::vector<std::string>& t_list,
                       std::vector<std::array<std::string, 2>>& ciphers,
                       const point* pk, curve* c);
  int dec_batch_pre_c0(const std::vector<std::array<std::string, 2>>& ciphers,
                       std::vector<uint32_t>& plains, const bigint* sk,
                       curve* c);
  int batch_cipher_add(
      std::vector<std::vector<std::array<std::string, 2>>>& ciphers,
      const point* pk, curve* c);
  //
  int gen_key(point* pk, bigint* sk, curve* c);
  //   int set_key();
  int enc_list_fast(const std::vector<uint32_t>& plains, std::string& cipher_0,
                    std::vector<std::string>& ciphers_1, const point* pk,
                    curve* c);
  int dec_list_fast(const std::string& cipher_0,
                    const std::vector<std::string>& ciphers_1,
                    std::vector<uint32_t>& plains, const bigint* sk, curve* c);
  int enc_list_cipher_add(std::vector<std::string>& cipher_0,
                          std::vector<std::string>* ciphers_1, const point* pk,
                          curve* c);
};
}  // namespace fucrypto
#endif