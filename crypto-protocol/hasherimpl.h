#ifndef __FU_HASHER_IMPL_H__
#define __FU_HASHER_IMPL_H__

#include <openssl/sha.h>
#include <BLAKE3/c/blake3.h>
#include "crypto-protocol/hasher.h"
// #if defined(__cplusplus) || defined(c_plusplus)
// extern "C" {
// #endif
namespace fucrypto {
class sha256 : public hasher {
 private:
  SHA256_CTX c;

 public:
  sha256();
  ~sha256();
  void hasher_reset();
  void hasher_update(const char *input, int input_len);
  void hasher_final(char *out, int out_len);
};

class blake3 : public hasher {
 private:
  blake3_hasher hasher;

 public:
  blake3();
  ~blake3();
  void hasher_reset();
  void hasher_update(const char *input, int input_len);
  void hasher_final(char *out, int out_len);
};
}  // namespace fucrypto

// #if defined(__cplusplus) || defined(c_plusplus)
// }
// #endif
#endif
