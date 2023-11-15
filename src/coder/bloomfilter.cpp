#include "crypto-protocol/bloomfilter.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/AES.h"
using namespace std;
using namespace oc;
namespace fucrypto {
bloom_filter::bloom_filter(int num_hash_func, std::string bits)
    : _num_hash_func(num_hash_func),
      _num_bits(bits.size() * 8),
      _bits(move(bits)) {}
bloom_filter::~bloom_filter() { cout << "~bloom_filter" << endl; };
/// @brief
/// @param fpr
/// @param max_elements
/// @return
std::unique_ptr<bloom_filter> bloom_filter::new_bloom_filter(
    double fpr, uint32_t max_elements) {
  //   m = -1.44 log2(e) * n
  //   k = -log2(e)
  if (fpr <= 0 || fpr >= 1 || max_elements <= 0) return nullptr;
  int num_hash_functions = static_cast<int>(std::ceil(-std::log2(fpr)));
  int64_t num_bytes = static_cast<int64_t>(
      std::ceil(-max_elements * std::log2(fpr) / std::log(2) / 8));
  std::string bits(num_bytes, '\0');
  //   return make_unique<bloom_filter>(num_hash_functions, std::move(bits));
  return unique_ptr<bloom_filter>(
      new bloom_filter(num_hash_functions, std::move(bits)));
}
/// @brief
/// @param input
/// @return
vector<uint32_t> bloom_filter::_hash(const std::string &input) {
  int num = input.size();
  if (num == 0) return vector<uint32_t>();
  int cipher_num = (num + 15) / 16;
  block cipher[cipher_num];
  cipher[cipher_num - 1] = ZeroBlock;
  memcpy(cipher, input.data(), input.size());
  mAesFixedKey.ecbEncBlocks((block *)input.data(), cipher_num, cipher);
  for (size_t i = 1; i < cipher_num; i++) {
    cipher[0] ^= cipher[i];
  }
  block blk2 = mAesFixedKey.getKey() ^ cipher[0];
  uint32_t h1 = *(uint32_t *)cipher;
  uint32_t h2 = *(uint32_t *)&blk2;
  vector<uint32_t> result(_num_hash_func);

  for (int i = 0; i < _num_hash_func; i++) {
    result[i] = (h1 + i * h2) % _num_bits;
  }
  return result;
}
/// @brief
/// @param inputs
void bloom_filter::add(const std::vector<std::string> &inputs) {
  for (const std::string &input : inputs) {
    for (int64_t index : _hash(input)) {
      _bits[index / 8] |= (1 << (index % 8));
    }
  }
}
/// @brief
/// @param input
void bloom_filter::add(const std::string &input) {
  add(std::vector<std::string>{input});
}
/// @brief
/// @return
std::string bloom_filter::get_bits_string() { return _bits; }
int bloom_filter::get_hash_num() { return _num_hash_func; }
int bloom_filter::get_bits_num() { return _num_bits; }
}  // namespace fucrypto