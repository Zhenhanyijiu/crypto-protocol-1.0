#include "crypto-protocol/iknp.h"
#include "crypto-protocol/ot_base.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/utils.h"
#include "cryptoTools/Common/tools.h"
#include <cereal/types/memory.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/array.hpp>
#include <cereal/archives/binary.hpp>
namespace fucrypto {
using namespace std;
using namespace oc;
static const u32 commStepSize(512);
static const u32 superBlkSize(8);
iknp_sender::iknp_sender() : ote_sender() {}
iknp_sender::iknp_sender(const config_param &param) : ote_sender() {
  _param = param;
}

iknp_sender::~iknp_sender() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~iknp_sender free");
}
int iknp_sender::set_base_ot(const oc::BitVector &base_choices,
                             const std::vector<oc::block> &base_single_keys) {
  int base_num = base_choices.size();
  if (base_num < BaseOtCount) return err_code_iknp;
  for (size_t i = 0; i < BaseOtCount; i++) {
    mGens[i].SetSeed(base_single_keys[i]);
    mBaseChoiceBits = base_choices;
  }
  _has_base_ot = true;
  return 0;
}
int iknp_sender::send(std::vector<std::array<oc::block, 2>> &encMsgOutput,
                      conn *sock) {
  if (_has_base_ot == false) {
    // np99receiver otbase;
    // otreceiver *ot = &otbase;
    // 需要一个 base ot receiver
    unique_ptr<ot_receiver> ot = new_base_ot_receiver(_param);
    oc::PRNG rng(oc::sysRandomSeed());
    oc::BitVector chs(BaseOtCount);
    chs.randomize(rng);
    vector<block> single_keys(BaseOtCount);
    int fg = ot->receive(chs, single_keys, sock);
    if (fg) return fg;
    //
    for (size_t i = 0; i < BaseOtCount; i++) {
      mGens[i].SetSeed(single_keys[i]);
      mBaseChoiceBits = chs;
    }
    _has_base_ot = true;
  }
  // const vector<block> &uBuffInputAll,
  //    vector<array<block, 2>> &encMsgOutput
  // round up
  u64 numOtExt = roundUpTo(encMsgOutput.size(), 128);
  u64 numSuperBlocks = (numOtExt / 128 + superBlkSize - 1) / superBlkSize;
  // u64 numSuperBlocks = (numOtExt / 128 + superBlkSize - 1) / superBlkSize;
  u64 step = std::min<u64>(numSuperBlocks, (u64)commStepSize);
  // u64 numBlocks = numSuperBlocks * superBlkSize;
  //  a temp that will be used to transpose the sender's matrix
  std::array<std::array<block, superBlkSize>, 128> t;
  // std::vector<std::array<block, superBlkSize>> u(128 * commStepSize);

  std::array<block, 128> choiceMask;
  block delta = *(block *)this->mBaseChoiceBits.data();
  for (u64 i = 0; i < BaseOtCount; ++i) {
    if (this->mBaseChoiceBits[i])
      choiceMask[i] = AllOneBlock;
    else
      choiceMask[i] = ZeroBlock;
  }

  auto mIter = encMsgOutput.begin();

  // block *uIter = (block *)u.data() + superBlkSize * 128 * commStepSize;
  int offset = 0;
  vector<block> uBuffInput(commStepSize * 128 * superBlkSize);
  u64 uBuffInputSize = uBuffInput.size();
  // memcpy(uBuffInput.data(), uBuffInputAll.data() + offset, uBuffInput.size()
  // * 16); check ok if (uBuffInputSize != step * 128 * superBlkSize)
  // {
  //     return -121;
  // }
  block *uIter = (block *)uBuffInput.data() + uBuffInputSize;
  block *uEnd = uIter;
  // 接收 T^R^U
  //   vector<char> uBuffOut(numSuperBlocks * 128 * superBlkSize * 16);
  string T_R_U = sock->recv();
  //   然后反序列化成 uBuffInputAll
  vector<char> uBuffOut;
  stringstream ss(T_R_U);
  cereal::BinaryInputArchive bin_in_ar(ss);
  bin_in_ar(uBuffOut);
  if (uBuffOut.size() != numSuperBlocks * 128 * superBlkSize * 16) return -100;
  block *uBuffInputAll = (block *)uBuffOut.data();
  for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx) {
    block *tIter = (block *)t.data();
    block *cIter = choiceMask.data();
    if (uIter == uEnd) {
      u64 step = std::min<u64>(numSuperBlocks - superBlkIdx, (u64)commStepSize);
      // chl.recv((u8 *)u.data(), step * superBlkSize * 128 * sizeof(block));
      memcpy(uBuffInput.data(), uBuffInputAll + offset,
             step * superBlkSize * 128 * sizeof(block));
      offset += step * superBlkSize * 128;
      uIter = (block *)uBuffInput.data();
    }
    // transpose 128 columns at at time. Each column will be 128 * superBlkSize
    // = 1024 bits long.
    for (u64 colIdx = 0; colIdx < 128; ++colIdx) {
      // generate the columns using AES-NI in counter mode.
      // 生成t
      this->mGens[colIdx].mAes.ecbEncCounterMode(this->mGens[colIdx].mBlockIdx,
                                                 superBlkSize, tIter);
      this->mGens[colIdx].mBlockIdx += superBlkSize;

      uIter[0] = uIter[0] & *cIter;
      uIter[1] = uIter[1] & *cIter;
      uIter[2] = uIter[2] & *cIter;
      uIter[3] = uIter[3] & *cIter;
      uIter[4] = uIter[4] & *cIter;
      uIter[5] = uIter[5] & *cIter;
      uIter[6] = uIter[6] & *cIter;
      uIter[7] = uIter[7] & *cIter;

      tIter[0] = tIter[0] ^ uIter[0];
      tIter[1] = tIter[1] ^ uIter[1];
      tIter[2] = tIter[2] ^ uIter[2];
      tIter[3] = tIter[3] ^ uIter[3];
      tIter[4] = tIter[4] ^ uIter[4];
      tIter[5] = tIter[5] ^ uIter[5];
      tIter[6] = tIter[6] ^ uIter[6];
      tIter[7] = tIter[7] ^ uIter[7];

      ++cIter;
      uIter += 8;
      tIter += 8;
    }

    // transpose our 128 columns of 1024 bits. We will have 1024 rows,
    // each 128 bits wide.
    sse_transpose128x1024(t);

    auto mEnd =
        mIter + std::min<u64>(128 * superBlkSize, encMsgOutput.end() - mIter);
    tIter = (block *)t.data();
    block *tEnd = (block *)t.data() + 128 * superBlkSize;
    while (mIter != mEnd) {
      while (mIter != mEnd && tIter < tEnd) {
        (*mIter)[0] = *tIter;          // qi
        (*mIter)[1] = *tIter ^ delta;  // qi^s

        tIter += superBlkSize;
        mIter += 1;
      }
      tIter = tIter - 128 * superBlkSize + 1;
    }
  }

  std::array<block, 8> aesHashTemp;

  u64 doneIdx = 0;
  u64 bb = (encMsgOutput.size() + 127) / 128;
  for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx) {
    u64 stop = std::min<u64>(encMsgOutput.size(), doneIdx + 128);

    auto length = 2 * (stop - doneIdx);
    auto steps = length / 8;
    block *mIter = encMsgOutput[doneIdx].data();
    for (u64 i = 0; i < steps; ++i) {
      mAesFixedKey.ecbEncBlocks(mIter, 8, aesHashTemp.data());
      mIter[0] = mIter[0] ^ aesHashTemp[0];
      mIter[1] = mIter[1] ^ aesHashTemp[1];
      mIter[2] = mIter[2] ^ aesHashTemp[2];
      mIter[3] = mIter[3] ^ aesHashTemp[3];
      mIter[4] = mIter[4] ^ aesHashTemp[4];
      mIter[5] = mIter[5] ^ aesHashTemp[5];
      mIter[6] = mIter[6] ^ aesHashTemp[6];
      mIter[7] = mIter[7] ^ aesHashTemp[7];

      mIter += 8;
    }

    auto rem = length - steps * 8;
    mAesFixedKey.ecbEncBlocks(mIter, rem, aesHashTemp.data());
    for (u64 i = 0; i < rem; ++i) {
      mIter[i] = mIter[i] ^ aesHashTemp[i];
    }
    doneIdx = stop;
  }
  return 0;
}

////////////////////////////////////////////////
iknp_receiver::iknp_receiver() : ote_receiver() {}
iknp_receiver::iknp_receiver(const config_param &param) : ote_receiver() {
  _param = param;
};
iknp_receiver::~iknp_receiver() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~iknp_receiver free");
}
int iknp_receiver::set_base_ot(
    std::vector<std::array<oc::block, 2>> &base_pair_keys) {
  int base_num = base_pair_keys.size();
  if (base_num < BaseOtCount) return err_code_iknp;
  for (size_t i = 0; i < BaseOtCount; i++) {
    mGens[i][0].SetSeed(base_pair_keys[i][0]);
    mGens[i][1].SetSeed(base_pair_keys[i][1]);
  }
  _has_base_ot = true;
  return 0;
}
int iknp_receiver::receive(const oc::BitVector &choicesWidthInput,
                           std::vector<oc::block> &recoverMsgWidthOutput,
                           conn *sock) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "iknp_receiver::receive start ...");
  string err_info = "";
  scope_guard on_error_exit([&]() {
    sock->close();
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(),
                        "iknp_receiver::receive,err_info:{}", err_info);
  });
  if (_has_base_ot == false) {
    // np99sender otbase;
    // otsender *ot = &otbase;
    // oc::PRNG rng(oc::sysRandomSeed());
    // oc::BitVector chs(base_ot_count);
    // chs.randomize(rng);
    unique_ptr<ot_sender> ot = new_base_ot_sender(_param);
    vector<array<block, 2>> pair_keys(BaseOtCount);
    int fg = ot->send(pair_keys, sock);
    if (fg) return fg;
    //
    for (size_t i = 0; i < BaseOtCount; i++) {
      mGens[i][0].SetSeed(pair_keys[i][0]);
      mGens[i][1].SetSeed(pair_keys[i][1]);
    }
    _has_base_ot = true;
  }
  //   const BitVector &choicesWidthInput,
  //   vector<block> &recoverMsgWidthOutput,
  //   vector<block> &uBuffOutputAll
  // iknp接收方实际输入的iknpote的个数
  u64 rChoicesSize = choicesWidthInput.size();
  if (rChoicesSize < 0) {
    return err_code_iknp;
  }
  //((60+128-1)/128)*128
  u64 numOtExt = roundUpTo(choicesWidthInput.size(), 128);
  // numSuperBlocks与numOtExt有一定的对应关系
  u64 numSuperBlocks = (numOtExt / 128 + superBlkSize - 1) / superBlkSize;
  // numBlocks==8,16,24,...
  u64 numBlocks = numSuperBlocks * superBlkSize;
  BitVector choices2(numBlocks * 128);
  choices2 = choicesWidthInput;
  // 8*128为一个单位，不小于实际的输入长度rChoicesSize
  choices2.resize(numBlocks * 128);
  // 转化为block类型
  auto choiceBlocks = choices2.getSpan<block>();
#if 0  // debug
        for (int i = 0; i < choiceBlocks.size(); i++)
        {
            cout << "===>>choiceBlock i:" << i << "," << choiceBlocks[i] << endl;
        }
#endif
  // 定义t0矩阵
  std::array<std::array<block, superBlkSize>, 128> t0;
  // the index of the OT that has been completed.
  // 初始化recoverMsgWidthOutput大小
  recoverMsgWidthOutput.resize(rChoicesSize);
  auto mIter = recoverMsgWidthOutput.begin();
  u64 step = std::min<u64>(numSuperBlocks, (u64)commStepSize);
  // 初始化uBuffOutput大小 T_R_U
  vector<char> uBuffOut(numSuperBlocks * 128 * superBlkSize * 16);
  block *uBuffOutputAll = (block *)uBuffOut.data();
  //   uBuffOutputAll.resize(numSuperBlocks * 128 * superBlkSize);
  vector<block> uBuffOutput;
  uBuffOutput.resize(step * 128 * superBlkSize);
  // get an array of blocks that we will fill.
  auto uIter = (block *)uBuffOutput.data();
  auto uEnd = uIter + uBuffOutput.size();
  int offset = 0;
  for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx) {
    // this will store the next 128 rows of the matrix u
    block *tIter = (block *)t0.data();
    block *cIter = choiceBlocks.data() + superBlkSize * superBlkIdx;
    for (u64 colIdx = 0; colIdx < 128; ++colIdx) {
      // generate the column indexed by colIdx. This is done with
      // AES in counter mode acting as a PRNG. We don'tIter use the normal
      // PRNG interface because that would result in a data copy when
      // we move it into the T0,T1 matrices. Instead we do it directly.
      // 生成矩阵t0
      this->mGens[colIdx][0].mAes.ecbEncCounterMode(
          this->mGens[colIdx][0].mBlockIdx, superBlkSize, tIter);
      // 生成矩阵u,并将u^r^t发送给对方
      this->mGens[colIdx][1].mAes.ecbEncCounterMode(
          this->mGens[colIdx][1].mBlockIdx, superBlkSize, uIter);
      // increment the counter mode idx.
      this->mGens[colIdx][0].mBlockIdx += superBlkSize;
      this->mGens[colIdx][1].mBlockIdx += superBlkSize;
      // u^c
      uIter[0] = uIter[0] ^ cIter[0];
      uIter[1] = uIter[1] ^ cIter[1];
      uIter[2] = uIter[2] ^ cIter[2];
      uIter[3] = uIter[3] ^ cIter[3];
      uIter[4] = uIter[4] ^ cIter[4];
      uIter[5] = uIter[5] ^ cIter[5];
      uIter[6] = uIter[6] ^ cIter[6];
      uIter[7] = uIter[7] ^ cIter[7];
      // u=u^c^t
      uIter[0] = uIter[0] ^ tIter[0];
      uIter[1] = uIter[1] ^ tIter[1];
      uIter[2] = uIter[2] ^ tIter[2];
      uIter[3] = uIter[3] ^ tIter[3];
      uIter[4] = uIter[4] ^ tIter[4];
      uIter[5] = uIter[5] ^ tIter[5];
      uIter[6] = uIter[6] ^ tIter[6];
      uIter[7] = uIter[7] ^ tIter[7];

      uIter += 8;
      tIter += 8;
    }
    // 如果 numSuperBlocks >512时，这里需要优化，不过一般512就足够了
    if (uIter == uEnd) {
      // send over u buffer
      // chl.asyncSend(std::move(uBuff));
      memcpy(uBuffOutputAll + offset, uBuffOutput.data(),
             uBuffOutput.size() * 16);
      // uBuffOutput.data();
      offset += uBuffOutput.size();
      // 512是一个大块
      u64 step =
          std::min<u64>(numSuperBlocks - superBlkIdx - 1, (u64)commStepSize);
      if (step) {
        uBuffOutput.resize(step * 128 * superBlkSize);
        uIter = (block *)uBuffOutput.data();
        uEnd = uIter + uBuffOutput.size();
      }
    }

    // transpose our 128 columns of 1024 bits. We will have 1024 rows,
    // each 128 bits wide.
    sse_transpose128x1024(t0);

    // block* mStart = mIter;
    // block* mEnd = std::min<block*>(mIter + 128 * superBlkSize,
    // &*messages.end());
    auto mEnd = mIter + std::min<u64>(128 * superBlkSize,
                                      recoverMsgWidthOutput.end() - mIter);
    tIter = (block *)t0.data();
    block *tEnd = (block *)t0.data() + 128 * superBlkSize;
    while (mIter != mEnd) {
      while (mIter != mEnd && tIter < tEnd) {
        (*mIter) = *tIter;
        tIter += superBlkSize;
        mIter += 1;
      }
      tIter = tIter - 128 * superBlkSize + 1;
    }
  }
  // 发送 T_R_U
  stringstream ss;
  cereal::BinaryOutputArchive bin_out_ar(ss);
  bin_out_ar(uBuffOut);
  sock->send(ss.str());

  std::array<block, 8> aesHashTemp;

  u64 doneIdx = (0);
  u64 bb = (recoverMsgWidthOutput.size() + 127) / 128;
  for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx) {
    u64 stop = std::min<u64>(recoverMsgWidthOutput.size(), doneIdx + 128);

    auto length = stop - doneIdx;
    auto steps = length / 8;
    block *mIter = recoverMsgWidthOutput.data() + doneIdx;
    for (u64 i = 0; i < steps; ++i) {
      mAesFixedKey.ecbEncBlocks(mIter, 8, aesHashTemp.data());
      mIter[0] = mIter[0] ^ aesHashTemp[0];
      mIter[1] = mIter[1] ^ aesHashTemp[1];
      mIter[2] = mIter[2] ^ aesHashTemp[2];
      mIter[3] = mIter[3] ^ aesHashTemp[3];
      mIter[4] = mIter[4] ^ aesHashTemp[4];
      mIter[5] = mIter[5] ^ aesHashTemp[5];
      mIter[6] = mIter[6] ^ aesHashTemp[6];
      mIter[7] = mIter[7] ^ aesHashTemp[7];
      mIter += 8;
    }
    auto rem = length - steps * 8;
    mAesFixedKey.ecbEncBlocks(mIter, rem, aesHashTemp.data());
    for (u64 i = 0; i < rem; ++i) {
      mIter[i] = mIter[i] ^ aesHashTemp[i];
    }
    doneIdx = stop;
  }
  on_error_exit.dismiss();
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "iknp_receiver::receive end ...");
  return 0;
}

////////////////////////////////////////////////

}  // namespace fucrypto