#ifndef __FU_N_CHOICE_ONE_KKRT_H_
#define __FU_N_CHOICE_ONE_KKRT_H_
#include "crypto-protocol/ot_interface.h"
#include "cryptoTools/Common/Matrix.h"
#include "crypto-protocol/hasher.h"
namespace fucrypto {

class kkrt_sender {
 private:
  std::unique_ptr<hasher> _hash = nullptr;
  std::vector<oc::AES> mGens;
  oc::u64 mCorrectionIdx, mInputByteCount;
  oc::BitVector mBaseChoiceBits;
  std::vector<oc::u64> mGensBlkIdx;
  std::vector<oc::block> mChoiceBlks;
  oc::MultiKeyAES<4> mMultiKeyAES;
  oc::Matrix<oc::block> mT, mCorrectionVals;

 public:
  kkrt_sender();
  kkrt_sender(const config_param& param);
  ~kkrt_sender();
  int get_base_ot_count();
  int set_base_ot(const oc::BitVector& base_choices,
                  const std::vector<oc::block>& base_single_keys);
  int init(int numOTExt);
  int recvCorrection(conn* sock, oc::u64 recvCount);
  int encode(oc::u64 otIdx, const void* input, void* dest, oc::u64 destSize);
  int encode_all(int numOTExt, const std::vector<std::vector<oc::u32>>& inputs,
                 std::vector<std::vector<oc::block>>& out_mask);
};
/////////////////
class kkrt_receiver {
 private:
  std::unique_ptr<hasher> _hash = nullptr;
  std::vector<std::array<oc::AES, 2>> mGens;
  std::vector<oc::u64> mGensBlkIdx;
  oc::u64 mInputByteCount;
  oc::MultiKeyAES<4> mMultiKeyAES;
  oc::Matrix<oc::block> mT0, mT1;
  oc::u64 mCorrectionIdx;

 public:
  kkrt_receiver();
  kkrt_receiver(const config_param& param);
  ~kkrt_receiver();
  int get_base_ot_count();
  int set_base_ot(const std::vector<std::array<oc::block, 2>>& base_pair_keys);
  int init(int numOTExt);
  int encode(oc::u64 otIdx, const void* input, void* dest, oc::u64 destSize);
  int encode_all(int numOTExt, const std::vector<oc::u32>& inputs,
                 std::vector<oc::block>& out_mask);
  int sendCorrection(conn* sock, oc::u64 sendCount);
};
}  // namespace fucrypto
#endif