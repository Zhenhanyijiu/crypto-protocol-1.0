#include "crypto-protocol/base.h"
#include "crypto-protocol/fulog.h"
#include <bits/stdc++.h>
using namespace std;
using namespace fucrypto;
vector<string> curve_list = {
    "secp256k1",
    "prime256v1",
    "secp384r1",
};
void test_npsender() {
  config_param param, param2;
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ecc_lib_name:{},curve_name:{}",
                     param.ecc_lib_name, param.curve_name);
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "ecc_lib_name:{},curve_name:{}",
                     param2.ecc_lib_name, param2.curve_name);
  for (auto& name : curve_list) {
    param.curve_name = name;
    np99sender np_sender(param);
    // np99sender np_sender2;
  }
}
int main(int argc, char** argv) {
  spdlog_set_level("info");
  test_npsender();
  return 0;
}