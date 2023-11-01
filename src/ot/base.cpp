#include "crypto-protocol/base.h"
#include "crypto-protocol/fuecc.h"
#include "crypto-protocol/fulog.h"
namespace fucrypto {
np99sender::np99sender() : otsender() {
  _ecc = move((*ecc_lib_map)["openssl"]->new_curve("secp256k1"));
};
np99sender::np99sender(const config_param& param) : otsender() {
  _ecc = move((*ecc_lib_map)[param.ecc_lib_name]->new_curve(param.curve_name));
  auto x = _ecc->new_bn();
  x->from_dec("12345");
  x->print();
};
np99sender::~np99sender() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~np99sender free");
};
void np99sender::send(std::vector<std::array<oc::block, 2>>& pair_keys,
                      const conn* sock) {
  auto bn_c = _ecc->gen_rand_bn();
  //   随机点 C
  auto C = _ecc->scalar_base_mul(bn_c.get());
  //   alpha
  auto alpha = _ecc->gen_rand_bn();
  //   A=alpha*G
  auto A = _ecc->scalar_base_mul(alpha.get());
  ;
};
np99receiver::np99receiver(/* args */){};
np99receiver::~np99receiver(){};
void np99receiver::receive(const oc::BitVector& choices,
                           std::vector<oc::block>& single_keys,
                           const conn* sock){};

}  // namespace fucrypto