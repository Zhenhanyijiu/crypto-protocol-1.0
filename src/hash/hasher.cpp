// #include "crypto-protocol/hasher.h"
#include "crypto-protocol/hasherimpl.h"
#include <bits/stdc++.h>
namespace fucrypto {
std::unordered_map<std::string, NewFuncType> hasher_map{
    {"sha256", new_sha256},
    {"blake3", new_blake3},
};
std::unordered_map<std::string, NewFuncType> *hasher_map_ptr = &hasher_map;
}  // namespace fucrypto