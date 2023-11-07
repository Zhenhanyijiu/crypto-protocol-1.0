#ifndef __FU_N_CHOICE_ONE_KKRT_H_
#define __FU_N_CHOICE_ONE_KKRT_H_
#include "crypto-protocol/ot_interface.h"
#include "cryptoTools/Common/Matrix.h"
#include "crypto-protocol/hasher.h"
namespace fucrypto {

class kkrt_sender {
 private:
  config_param _param;
  std::unique_ptr<hasher> _hash = nullptr;
  std::vector<oc::AES> mGens;
  oc::u64 mCorrectionIdx, mInputByteCount;
  oc::BitVector mBaseChoiceBits;
  std::vector<oc::u64> mGensBlkIdx;
  std::vector<oc::block> mChoiceBlks;
  oc::MultiKeyAES<4> mMultiKeyAES;
  oc::Matrix<oc::block> mT, mCorrectionVals;
  bool _has_base_ot = false;
  int _init(int numOTExt);
  int _encode(int otIdx, const void* input, void* dest, int destSize);

 public:
  kkrt_sender();
  kkrt_sender(const config_param& param);
  ~kkrt_sender();
  int get_base_ot_count();
  int set_base_ot(const oc::BitVector& base_choices,
                  const std::vector<oc::block>& base_single_keys);
  int recv_correction(conn* sock, int num_otext);
  int encode_all(int num_otext,
                 const std::vector<std::vector<uint32_t>>& inputs,
                 std::vector<std::vector<oc::block>>& out_mask);
};
/////////////////
class kkrt_receiver {
 private:
  config_param _param;
  std::unique_ptr<hasher> _hash = nullptr;
  std::vector<std::array<oc::AES, 2>> mGens;
  std::vector<oc::u64> mGensBlkIdx;
  oc::u64 mInputByteCount;
  oc::MultiKeyAES<4> mMultiKeyAES;
  oc::Matrix<oc::block> mT0, mT1;
  oc::u64 mCorrectionIdx;
  bool _has_base_ot = false;
  int _init(int numOTExt);
  int _encode(int otIdx, const void* input, void* dest, int destSize);

 public:
  kkrt_receiver();
  kkrt_receiver(const config_param& param);
  ~kkrt_receiver();
  int get_base_ot_count();
  int set_base_ot(const std::vector<std::array<oc::block, 2>>& base_pair_keys);
  int encode_all(int numOTExt, const std::vector<uint32_t>& inputs,
                 std::vector<oc::block>& out_mask, conn* sock);
  int send_correction(conn* sock, int sendCount);
};
}  // namespace fucrypto
#endif