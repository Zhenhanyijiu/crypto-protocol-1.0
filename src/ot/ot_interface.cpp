#include "crypto-protocol/ot_interface.h"
// #include "crypto-protocol/ot_base.h"
// #include "crypto-protocol/ote_iknp.h"
// #include "crypto-protocol/kkrt.h"
using namespace oc;
using namespace std;
namespace fucrypto {
config_param default_config_param;
OTFactory::OTFactory() {}
OTFactory::~OTFactory() { cout << "~OTFactory free" << endl; }
// template <typename T, typename T1>
// unique_ptr<T> new_ot_sender(const config_param& param) {
//   return make_unique<T1>(param);
// }
// template <typename T, typename T1>
// unique_ptr<T> new_ot_receiver(const config_param& param) {
//   return make_unique<T1>(param);
// }
OTFactory ot_factory;
OTFactory* ot_factory_ptr = &ot_factory;
}  // namespace fucrypto