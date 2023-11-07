#ifndef __FU_HASHER_INTERFACE_H__
#define __FU_HASHER_INTERFACE_H__
#include <bits/stdc++.h>
// #if defined(__cplusplus) || defined(c_plusplus)
// extern "C" {
// #endif
namespace fucrypto {
class hasher {
 private:
 public:
  virtual ~hasher(){};
  virtual void hasher_reset() = 0;
  virtual void hasher_update(const char *input, int input_len) = 0;
  virtual void hasher_final(char *out, int out_len) = 0;
};
typedef std::unique_ptr<hasher> (*NewFuncType)();
// {"sha256","blake3"}
extern std::unordered_map<std::string, NewFuncType> *hasher_map_ptr;
}  // namespace fucrypto

// #if defined(__cplusplus) || defined(c_plusplus)
// }
// #endif
#endif
