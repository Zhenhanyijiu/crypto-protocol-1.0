#ifndef __FU_CONFIG_H__
#define __FU_CONFIG_H__
#include <bits/stdc++.h>
namespace fucrypto {
struct config_param {
  std::string ecc_lib_name = "openssl";
  std::string curve_name = "secp256k1";
  std::string ot_name = "np99";
  std::string ote_name = "iknp";
  std::string ot_n_1_name = "kkrt";
  std::string hasher_name = "sha256";
  //   int N = 16;
};
// extern config_param default_config_param;
;
;
}  // namespace fucrypto
#endif