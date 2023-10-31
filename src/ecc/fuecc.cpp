#include <crypto-protocol/fuecc.h>
#include <crypto-protocol/fuecc_open.h>
using namespace std;
namespace fucrypto {
unordered_map<string, EccLibFactory*> lib_map{
    {"openssl", openssl_factory_ptr},
};
unordered_map<string, EccLibFactory*>* ecc_lib_map = &lib_map;

}  // namespace fucrypto
