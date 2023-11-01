#ifndef __FU_OT_INTER_FACE_H__
#define __FU_OT_INTER_FACE_H__
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/BitVector.h>
#include <bits/stdc++.h>
#include "crypto-protocol/fusocket.h"
// using namespace oc;
// using namespace std;
namespace fucrypto {
//   "secp256k1",
//   "prime256v1",
//   "secp384r1",
struct config_param {
  std::string ecc_lib_name = "openssl";
  std::string curve_name = "secp256k1";
};

class otsender {
 public:
  otsender(){};
  //   otsender(const config_param& param){};
  virtual ~otsender(){};
  virtual void send(std::vector<std::array<oc::block, 2>>& pair_keys,
                    const conn* sock) = 0;
};
class otreceiver {
 private:
  /* data */
 public:
  //   otreceiver(/* args */);
  virtual ~otreceiver(){};
  virtual void receive(const oc::BitVector& choices,
                       std::vector<oc::block>& single_keys,
                       const conn* sock) = 0;
};

;
}  // namespace fucrypto
#endif