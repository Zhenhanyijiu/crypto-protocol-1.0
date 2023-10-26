#include "crypto-protocol/hasherimpl.h"
namespace fucrypto {
// openssl sha256
sha256::sha256() { SHA256_Init(&this->c); }
sha256::~sha256() {}
void sha256::hasher_reset() { SHA256_Init(&this->c); }
void sha256::hasher_update(const char *input, int input_len) {
  SHA256_Update(&this->c, input, input_len);
}
void sha256::hasher_final(char *out, int out_len) {
  SHA256_Final((unsigned char *)out, &c);
}
// blake3
blake3::blake3() { blake3_hasher_init(&this->hasher); }
blake3::~blake3() {}
void blake3::hasher_reset() { blake3_hasher_reset(&this->hasher); }
void blake3::hasher_update(const char *input, int input_len) {
  blake3_hasher_update(&this->hasher, input, input_len);
}
void blake3::hasher_final(char *out, int out_len) {
  blake3_hasher_finalize(&this->hasher, (uint8_t *)out, out_len);
}
}  // namespace fucrypto

