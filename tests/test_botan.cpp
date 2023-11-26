#include <bits/stdc++.h>
#include <botan/bigint.h>
#include "crypto-protocol/utils.h"
#include "crypto-protocol/fulog.h"

using namespace std;
using namespace Botan;
void test_bigint() {
  BigInt s;
  //   s.set_bit(10);
  string ret = s.to_dec_string();
  cout << "ret:" << ret << ",size:" << ret.size() << endl;
  ret = s.to_hex_string();
  cout << "ret:" << ret << ",size:" << ret.size() << endl;
}
int main(int argc, char** argv) {
  spdlog_set_level("info");
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "=== test botan ===");
  test_bigint();
  return 0;
}