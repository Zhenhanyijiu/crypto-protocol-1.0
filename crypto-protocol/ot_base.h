#ifndef __BASE_OT_H__
#define __BASE_OT_H__
#include "crypto-protocol/ot_interface.h"
#include "crypto-protocol/fuecc.h"
#include "crypto-protocol/hasher.h"
#include "crypto-protocol/hasherimpl.h"

namespace fucrypto {
#define err_code_np99 1000
class np99sender : public ot_sender {
 private:
  std::unique_ptr<curve> _ecc;
  std::unique_ptr<hasher> _hash;
  void _np99sender(const config_param& param);

 public:
  np99sender();
  np99sender(const config_param& param);
  ~np99sender();
  int send(std::vector<std::array<oc::block, 2>>& pair_keys, conn* sock);
};
class np99receiver : public ot_receiver {
 private:
  std::unique_ptr<curve> _ecc;
  std::unique_ptr<hasher> _hash;
  void _np99receiver(const config_param& param);

 public:
  np99receiver();
  np99receiver(const config_param& param);
  ~np99receiver();
  int receive(const oc::BitVector& choices, std::vector<oc::block>& single_keys,
              conn* sock);
};

;
}  // namespace fucrypto
#endif