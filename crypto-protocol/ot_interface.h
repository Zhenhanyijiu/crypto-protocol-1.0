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
  std::string ot_name = "np99";
  std::string ote_name = "iknp";
  std::string ot_n_1_name = "kkrt";
  std::string hasher_name = "sha256";
};
extern config_param default_config_param;
class otsender {
 public:
  otsender(){};
  //   otsender(const config_param& param){};
  virtual ~otsender(){};
  virtual int send(std::vector<std::array<oc::block, 2>>& pair_keys,
                   conn* sock) = 0;
};
class otreceiver {
 private:
 public:
  otreceiver(){};
  virtual ~otreceiver(){};
  virtual int receive(const oc::BitVector& choices,
                      std::vector<oc::block>& single_keys, conn* sock) = 0;
};

// ote
class ote_sender {
 public:
  ote_sender(){};
  //   otsender(const config_param& param){};
  virtual ~ote_sender(){};
  virtual int set_base_ot(const oc::BitVector& base_choices,
                          const std::vector<oc::block>& base_single_keys) = 0;
  virtual int send(std::vector<std::array<oc::block, 2>>& pair_keys,
                   conn* sock) = 0;
};
class ote_receiver {
 private:
 public:
  ote_receiver(){};
  virtual ~ote_receiver(){};
  virtual int set_base_ot(
      std::vector<std::array<oc::block, 2>>& base_pair_keys) = 0;
  virtual int receive(const oc::BitVector& choices,
                      std::vector<oc::block>& single_keys, conn* sock) = 0;
};
// enum OT_ROLE { SENDER, RECEIVER };

class OTFactory {
 private:
 public:
  OTFactory();
  ~OTFactory();
  template <typename T, typename T1>
  std::unique_ptr<T> new_ot_sender(const config_param& param) {
    return std::make_unique<T1>(param);
  }
  template <typename T, typename T1>
  std::unique_ptr<T> new_ot_receiver(const config_param& param) {
    return std::make_unique<T1>(param);
  }
};

extern OTFactory* ot_factory_ptr;
// typedef std::unique_ptr<otsender> (*NewBaseOtSenderFunc)();
// typedef std::unique_ptr<otreceiver> (*NewBaseOtReceiverFunc)();
// typedef std::unique_ptr<ote_sender> (*NewOTeSenderFunc)();
// typedef std::unique_ptr<ote_receiver> (*NewOTeReceiverFunc)();
// extern std::unordered_map<std::string, NewBaseOtSenderFunc>*
// base_ot_sender_map; extern std::unordered_map<std::string,
// NewBaseOtReceiverFunc>*
//     base_ot_receiver_map;
// extern std::unordered_map<std::string, NewBaseOtSenderFunc>*
//     base_ote_sender_map;
// extern std::unordered_map<std::string, NewBaseOtSenderFunc>*
//     base_ote_receiver_map;
}  // namespace fucrypto
#endif