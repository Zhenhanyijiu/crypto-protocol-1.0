#include <crypto-protocol/fuecc.h>
#include <crypto-protocol/fuecc_open.h>
#include <crypto-protocol/fuecc_botan.h>
using namespace std;
namespace fucrypto {
// unordered_map<string, EccLibFactory*> lib_map{
//     {"openssl", openssl_factory_ptr},
// };
// unordered_map<string, EccLibFactory*>* ecc_lib_map = &lib_map;
std::unique_ptr<curve> new_openssl_curve(std::string curve_name) {
  return make_unique<open_curve>(curve_name);
};
std::unique_ptr<curve> new_botan_curve(std::string curve_name) {
  return make_unique<botan_curve>(curve_name);
};
std::unique_ptr<curve> new_lib_curve(const config_param& param) {
  if (param.ecc_lib_name == "openssl") {
    return new_openssl_curve(param.curve_name);
  }
  if (param.ecc_lib_name == "botan") {
    return new_botan_curve(param.curve_name);
  }
  //   default
  config_param defau;
  return new_openssl_curve(defau.curve_name);
}

}  // namespace fucrypto
