#ifndef __FU_BLOOM_FILTER_H__
#define __FU_BLOOM_FILTER_H__
#include <bits/stdc++.h>
namespace fucrypto {
class bloom_filter {
 private:
  int _num_hash_func;
  int _num_bits;
  std::string _bits;
  std::vector<uint32_t> _hash(const std::string& input);
  bloom_filter(int num_hash_func, std::string bits);

 public:
  bloom_filter() = delete;
  ~bloom_filter();
  //   bloom_filter(int num_hash_func, std::string bits);

  static std::unique_ptr<bloom_filter> new_bloom_filter(double fpr,
                                                        uint32_t max_elements);
  void add(const std::vector<std::string>& inputs);
  void add(const std::string& input);
  std::string get_bits_string();
  int get_hash_num();
  int get_bits_num();
};

}  // namespace fucrypto
#endif