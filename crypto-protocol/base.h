#ifndef __BASE_OT_H__
#define __BASE_OT_H__
#include "crypto-protocol/ot_interface.h"
#include "crypto-protocol/fuecc.h"

namespace fucrypto {
class np99sender : public otsender {
 private:
  std::unique_ptr<curve> _ecc;

 public:
  np99sender();
  np99sender(const config_param& param);
  ~np99sender();
  void send(std::vector<std::array<oc::block, 2>>& pair_keys, const conn* sock);
};
class np99receiver : public otreceiver {
 private:
  /* data */
 public:
  np99receiver(/* args */);
  ~np99receiver();
  void receive(const oc::BitVector& choices,
               std::vector<oc::block>& single_keys, const conn* sock);
};

;
}  // namespace fucrypto
#endif