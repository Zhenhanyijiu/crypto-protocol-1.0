#include "crypto-protocol/ot_interface.h"
#include "crypto-protocol/ot_base.h"
#include "crypto-protocol/ote_iknp.h"
#include "crypto-protocol/kkrt.h"
using namespace oc;
using namespace std;
namespace fucrypto {
config_param default_config_param;
// OTFactory::OTFactory() {}
// OTFactory::~OTFactory() { cout << "~OTFactory free" << endl; }
// template <typename T, typename T1>
// unique_ptr<T> new_ot_sender(const config_param& param) {
//   return make_unique<T1>(param);
// }
// template <typename T, typename T1>
// unique_ptr<T> new_ot_receiver(const config_param& param) {
//   return make_unique<T1>(param);
// }
// OTFactory ot_factory;
// OTFactory* ot_factory_ptr = &ot_factory;

// new object
std::unique_ptr<ot_sender> new_base_ot_sender(const config_param& param) {
  if (param.ot_name == "np99") return make_unique<np99sender>(param);
  //   可以继续添加

  return nullptr;
}
std::unique_ptr<ot_receiver> new_base_ot_receiver(const config_param& param) {
  if (param.ot_name == "np99") return make_unique<np99receiver>(param);
  //   可以继续添加
  return nullptr;
}
std::unique_ptr<ote_sender> new_ote_sender(const config_param& param) {
  if (param.ote_name == "iknp") return make_unique<iknp_sender>(param);
  //   可以继续添加
  return nullptr;
};
std::unique_ptr<ote_receiver> new_ote_receiver(const config_param& param) {
  if (param.ote_name == "iknp") return make_unique<iknp_receiver>(param);
  //   可以继续添加
  return nullptr;
};
}  // namespace fucrypto