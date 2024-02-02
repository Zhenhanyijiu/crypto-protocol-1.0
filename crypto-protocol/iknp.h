#ifndef __FU_IKNP_H__
#define __FU_IKNP_H__
#include "crypto-protocol/ot_interface.h"
#include <bits/stdc++.h>
namespace fucrypto {
#define err_code_iknp 1001

const oc::u32 BaseOtCount(128);
class iknp_sender : public ote_sender {
 private:
  config_param _param;
  std::array<oc::PRNG, BaseOtCount> mGens;
  oc::BitVector mBaseChoiceBits;
  bool _has_base_ot = false;

 public:
  iknp_sender();
  iknp_sender(const config_param &param);
  ~iknp_sender();
  int set_base_ot(const oc::BitVector &base_choices,
                  const std::vector<oc::block> &base_single_keys);
  int send(std::vector<std::array<oc::block, 2>> &pair_keys, conn *sock);
};

///////////// iknp_receiver //////////
class iknp_receiver : public ote_receiver {
 private:
  config_param _param;
  std::array<std::array<oc::PRNG, 2>, BaseOtCount> mGens;
  bool _has_base_ot = false;

 public:
  iknp_receiver();
  iknp_receiver(const config_param &param);
  ~iknp_receiver();
  int set_base_ot(std::vector<std::array<oc::block, 2>> &base_pair_keys);
  int receive(const oc::BitVector &choices, std::vector<oc::block> &single_keys,
              conn *sock);
};

}  // namespace fucrypto
#endif