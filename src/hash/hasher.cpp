// #include "crypto-protocol/hasher.h"
#include "crypto-protocol/hasherimpl.h"
#include <bits/stdc++.h>
namespace fucrypto {
// std::unordered_map<std::string, NewFuncType> hasher_map{
//     {"sha256", new_sha256},
//     {"blake3", new_blake3},
// };
// std::unordered_map<std::string, NewFuncType> *hasher_map_ptr = &hasher_map;
std::unique_ptr<hasher> new_hasher(const config_param& param) {
  if (param.hasher_name == "sha256") return new_sha256();
  if (param.hasher_name == "blake3") return new_blake3();
  return new_sha256();
}
}  // namespace fucrypto