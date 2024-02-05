#ifndef __FU_N_CHOICE_ONE_KKRT_H_
#define __FU_N_CHOICE_ONE_KKRT_H_
#include "crypto-protocol/ot_interface.h"
#include "cryptoTools/Common/Matrix.h"
#include "crypto-protocol/hasher.h"
#define KKRT_WIDTH_X 2  // 设置为2,通信变少
namespace fucrypto {
#define err_code_kkrt 1002
class kkrt_sender {
 private:
  config_param _param;
  std::unique_ptr<hasher> _hash = nullptr;
  std::vector<oc::AES> mGens;
  oc::u64 mCorrectionIdx;
  oc::BitVector mBaseChoiceBits;
  std::vector<oc::u64> mGensBlkIdx;
  std::vector<oc::block> mChoiceBlks;
  oc::MultiKeyAES<KKRT_WIDTH_X> mMultiKeyAES;
  oc::Matrix<oc::block> mT, mCorrectionVals;
  bool _has_base_ot = false;
  int _init(int numOTExt);
  int _encode(int otIdx, const oc::block* input, oc::block* dest);

 public:
  kkrt_sender();
  kkrt_sender(const config_param& param);
  ~kkrt_sender();
  int get_base_ot_count();
  int set_base_ot(const oc::BitVector& base_choices,
                  const std::vector<oc::block>& base_single_keys);
  int recv_correction(conn* sock, int num_otext);
  int encode_all(int num_otext,
                 const std::vector<std::vector<oc::block>>& inputs,
                 std::vector<std::vector<oc::block>>& out_mask);
};
/////////////////
class kkrt_receiver {
 private:
  config_param _param;
  std::unique_ptr<hasher> _hash = nullptr;
  std::vector<std::array<oc::AES, 2>> mGens;
  std::vector<oc::u64> mGensBlkIdx;
  oc::MultiKeyAES<KKRT_WIDTH_X> mMultiKeyAES;
  oc::Matrix<oc::block> mT0, mT1;
  oc::u64 mCorrectionIdx;
  bool _has_base_ot = false;
  int _init(int numOTExt);
  int _encode(int otIdx, const oc::block* input, oc::block* dest);

 public:
  kkrt_receiver();
  kkrt_receiver(const config_param& param);
  ~kkrt_receiver();
  int get_base_ot_count();
  int set_base_ot(const std::vector<std::array<oc::block, 2>>& base_pair_keys);
  int encode_all(int numOTExt, const std::vector<oc::block>& inputs,
                 std::vector<oc::block>& out_mask, conn* sock);
  int send_correction(conn* sock, int sendCount);
};
}  // namespace fucrypto
#endif