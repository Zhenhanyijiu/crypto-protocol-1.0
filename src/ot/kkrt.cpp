#include "crypto-protocol/kkrt.h"
#include "crypto-protocol/fulog.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/tools.h"
#include <bits/stdc++.h>
using namespace std;
using namespace oc;
namespace fucrypto {
kkrt_sender::kkrt_sender() {
  u64 statSecParam = 40;
  u64 inputBitCount = 128;
  mInputByteCount = (inputBitCount + 7) / 8;
  mGens.resize(128 * 4);
}
kkrt_sender::kkrt_sender(const config_param& param) {
  // hash 先不配置
  u64 statSecParam = 40;
  u64 inputBitCount = 128;
  mInputByteCount = (inputBitCount + 7) / 8;
  mGens.resize(128 * 4);
}
kkrt_sender::~kkrt_sender() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~kkrt_sender");
}
int kkrt_sender::get_base_ot_count() { return mGens.size(); }
int kkrt_sender::set_base_ot(const oc::BitVector& base_choices,
                             const std::vector<oc::block>& base_single_keys) {
  if (base_choices.size() != u64(base_single_keys.size())) return -1;

  if (base_choices.size() != u64(mGens.size())) return -2;
  mBaseChoiceBits = base_choices;  // 512个 0-1
  //   mGens.resize(choices.size());
  mGensBlkIdx.resize(base_choices.size(), 0);

  for (u64 i = 0; i < u64(base_single_keys.size()); i++) {
    mGens[i].setKey(base_single_keys[i]);
  }

  mChoiceBlks.resize(base_choices.size() / (sizeof(block) * 8));  // 4
  for (u64 i = 0; i < mChoiceBlks.size(); ++i) {
    mChoiceBlks[i] = toBlock(mBaseChoiceBits.data() + (i * sizeof(block)));
  }
}

//
int kkrt_sender::init(int numOTExt) {
  block common_key = toBlock(0xaa, 0xff);
  std::array<block, 4> keys;
  PRNG(common_key).get(keys.data(), keys.size());
  mMultiKeyAES.setKeys(keys);
  //
  static const u8 superBlkSize(8);

  // round up
  numOTExt = ((numOTExt + 127) / 128) * 128;

  // We need two matrices, one for the senders matrix T^i_{b_i} and
  // one to hold the the correction values. This is sometimes called
  // the u = T0 + T1 + C matrix in the papers.
  mT.resize(numOTExt, mGens.size() / 128);
  // char c;
  // chl.recv(&c, 1);

  mCorrectionVals.resize(numOTExt, mGens.size() / 128);

  // The receiver will send us correction values, this is the index of
  // the next one they will send.
  mCorrectionIdx = 0;

  // we are going to process OTs in blocks of 128 * superblkSize messages.
  u64 numSuperBlocks = (numOTExt / 128 + superBlkSize - 1) / superBlkSize;

  // the index of the last OT that we have completed.
  u64 doneIdx = 0;

  // a temp that will be used to transpose the sender's matrix
  std::array<std::array<block, superBlkSize>, 128> t;

  u64 numCols = mGens.size();

  for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx) {
    // compute at what row does the user want use to stop.
    // the code will still compute the transpose for these
    // extra rows, but it is thrown away.
    u64 stopIdx = doneIdx + std::min<u64>(u64(128) * superBlkSize,
                                          mT.bounds()[0] - doneIdx);

    // transpose 128 columns at at time. Each column will be 128 * superBlkSize
    // = 1024 bits long.
    for (u64 i = 0; i < numCols / 128; ++i) {
      // generate the columns using AES-NI in counter mode.
      for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx) {
        mGens[colIdx].ecbEncCounterMode(
            mGensBlkIdx[colIdx], superBlkSize,
            ((block*)t.data() + superBlkSize * tIdx));
        mGensBlkIdx[colIdx] += superBlkSize;
      }

      // transpose our 128 columns of 1024 bits. We will have 1024 rows,
      // each 128 bits wide.
      sse_transpose128x1024(t);

      // This is the index of where we will store the matrix long term.
      // doneIdx is the starting row. i is the offset into the blocks of 128
      // bits.
      // __restrict isn't crucial, it just tells the compiler that this pointer
      // is unique and it shouldn't worry about pointer aliasing.
      block* __restrict mTIter = mT.data() + doneIdx * mT.stride() + i;

      for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++j) {
        // because we transposed 1024 rows, the indexing gets a bit weird. But
        // this is the location of the next row that we want. Keep in mind that
        // we had long
        // **contiguous** columns.
        block* __restrict tIter = (((block*)t.data()) + j);

        // do the copy!
        for (u64 k = 0; rowIdx < stopIdx && k < 128; ++rowIdx, ++k) {
          *mTIter = *tIter;

          tIter += superBlkSize;
          mTIter += mT.stride();
        }
      }
    }
    doneIdx = stopIdx;
  }
  return 0;
}

//
int kkrt_sender::recvCorrection(conn* sock, u64 recvCount) {
#ifndef NDEBUG
  if (recvCount > mCorrectionVals.bounds()[0] - mCorrectionIdx) return -1;
#endif  // !NDEBUG

  // receive the next OT correction values. This will be several rows of the
  // form u = T0 + T1 + C(w) there c(w) is a pseudo-random code.
  auto dest =
      mCorrectionVals.begin() + (mCorrectionIdx * mCorrectionVals.stride());
  //   大小固定
  string ot_data = sock->recv();
  assert(ot_data.size() ==
         recvCount * sizeof(block) * mCorrectionVals.stride());
  memcpy((u8*)&*dest, ot_data.data(),
         recvCount * sizeof(block) * mCorrectionVals.stride());
  //   chl.recv((u8*)&*dest, recvCount * sizeof(block) *
  //   mCorrectionVals.stride());

  // update the index of there we should store the next set of correction
  // values.
  mCorrectionIdx += recvCount;
  return 0;
}
int kkrt_sender::encode(u64 otIdx, const void* input, void* dest,
                        u64 destSize) {
#ifndef NDEBUG
  if (eq(mCorrectionVals[otIdx][0], ZeroBlock))
    throw std::invalid_argument(
        "appears that we haven't received the receiver's choice "
        "yet. " LOCATION);
#endif  // !NDEBUG
#define KKRT_WIDTH 4
  // static const int width(4);

  block word = ZeroBlock;
  memcpy(&word, input, mInputByteCount);

  std::array<block, KKRT_WIDTH> choice{word, word, word, word}, code;
  mMultiKeyAES.ecbEncNBlocks(choice.data(), code.data());

  auto* corVal = mCorrectionVals.data() + otIdx * mCorrectionVals.stride();
  auto* tVal = mT.data() + otIdx * mT.stride();

  // This is the hashing phase. Here we are using pseudo-random codewords.
  // That means we assume inputword is a hash of some sort.
#if KKRT_WIDTH == 4
  code[0] = code[0] ^ word;
  code[1] = code[1] ^ word;
  code[2] = code[2] ^ word;
  code[3] = code[3] ^ word;

  block t00 = corVal[0] ^ code[0];
  block t01 = corVal[1] ^ code[1];
  block t02 = corVal[2] ^ code[2];
  block t03 = corVal[3] ^ code[3];
  block t10 = t00 & mChoiceBlks[0];
  block t11 = t01 & mChoiceBlks[1];
  block t12 = t02 & mChoiceBlks[2];
  block t13 = t03 & mChoiceBlks[3];

  code[0] = tVal[0] ^ t10;
  code[1] = tVal[1] ^ t11;
  code[2] = tVal[2] ^ t12;
  code[3] = tVal[3] ^ t13;
#else

  for (u64 i = 0; i < KKRT_WIDTH; ++i) {
    code[i] = code[i] ^ word;

    block t0 = corVal[i] ^ code[i];
    block t1 = t0 & mChoiceBlks[i];

    code[i] = tVal[i] ^ t1;
  }
#endif

  if (_hash) {
    _hash->hasher_reset();
    _hash->hasher_update((char*)code.data(), sizeof(block) * mT.stride());
    _hash->hasher_final((char*)dest, 16);
    // RandomOracle sha1(destSize);
    // // hash it all to get rid of the correlation.
    // sha1.Update((u8*)code.data(), sizeof(block) * mT.stride());
    // sha1.Final((u8*)dest);
    return 0;
  }
  // 使用 aes
  std::array<block, 4> aesBuff;
  mAesFixedKey.ecbEncBlocks(code.data(), mT.stride(), aesBuff.data());
  auto val = ZeroBlock;
  for (u64 i = 0; i < mT.stride(); ++i) val = val ^ code[i] ^ aesBuff[i];
  //   memcpy(dest, (char*)&val, std::min(destSize, sizeof(block)));
  memcpy(dest, (char*)&val, sizeof(block));
  return 0;
  ;
}

int kkrt_sender::encode_all(int numOTExt,
                            const std::vector<std::vector<oc::u32>>& inputs,
                            std::vector<std::vector<block>>& out_mask) {
  out_mask.resize(numOTExt);
  for (auto i = 0ull; i < numOTExt; ++i) {
    int input_num_i = inputs[i].size();
    out_mask[i].resize(input_num_i);
    oc::block* begin = (oc::block*)out_mask[i].data();
    for (auto j = 0ull; j < input_num_i; ++j) {
      *(begin + j) = oc::toBlock(inputs[i][j]);
      encode(i, begin + j, begin + j, 16);
    }
  }
  return 0;
}

//////////////////////////////////
kkrt_receiver::kkrt_receiver() {
  u64 statSecParam = 40;
  u64 inputBitCount = 128;
  mInputByteCount = (inputBitCount + 7) / 8;
  auto count = 128 * 4;
  mGens.resize(count);
}

kkrt_receiver::kkrt_receiver(const config_param& param) {
  u64 statSecParam = 40;
  u64 inputBitCount = 128;
  mInputByteCount = (inputBitCount + 7) / 8;
  auto count = 128 * 4;
  mGens.resize(count);
}
kkrt_receiver::~kkrt_receiver() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~kkrt_receiver");
}
int kkrt_receiver::get_base_ot_count() { return mGens.size(); };
int kkrt_receiver::set_base_ot(
    const std::vector<std::array<oc::block, 2>>& base_pair_keys) {
  if (base_pair_keys.size() != mGens.size()) return -1;
  // mGens.resize(baseRecvOts.size());
  mGensBlkIdx.resize(base_pair_keys.size(), 0);
  for (u64 i = 0; i < mGens.size(); i++) {
    mGens[i][0].setKey(base_pair_keys[i][0]);
    mGens[i][1].setKey(base_pair_keys[i][1]);
  }
  return 0;
};
int kkrt_receiver::init(int numOtExt) {
  //   if (hasBaseOts() == false) throw std::runtime_error("rt error at "
  //   LOCATION);
  block common_key = toBlock(0xaa, 0xff);
  std::array<block, 4> keys;
  PRNG(common_key).get(keys.data(), keys.size());
  mMultiKeyAES.setKeys(keys);
  ///////
  static const u64 superBlkSize(8);

  // this will be used as temporary buffers of 128 columns,
  // each containing 1024 bits. Once transposed, they will be copied
  // into the T1, T0 buffers for long term storage.
  std::array<std::array<block, superBlkSize>, 128> t0;
  std::array<std::array<block, superBlkSize>, 128> t1;

  // we are going to process OTs in blocks of 128 * superblkSize messages.
  u64 numSuperBlocks =
      ((numOtExt + 127) / 128 + superBlkSize - 1) / superBlkSize;
  u64 numCols = mGens.size();

  // We need two matrices, T0 and T1. These will hold the expanded and
  // transposed rows that we got the using the base OTs as PRNG seed.
  mT0.resize(numOtExt, numCols / 128);
  mT1.resize(numOtExt, numCols / 128);

  // The is the index of the last correction value u = T0 ^ T1 ^ c(w)
  // that was sent to the sender.
  mCorrectionIdx = 0;

  // the index of the OT that has been completed.
  u64 doneIdx = 0;

  // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
  //   Instead we break it down into smaller chunks. We do 128 columns
  //   times 8 * 128 rows at a time, where 8 = superBlkSize. This is done for
  //   performance reasons. The reason for 8 is that most CPUs have 8 AES vector
  //   lanes, and so its more efficient to encrypt (aka prng) 8 blocks at a
  //   time. So that's what we do.
  for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx) {
    // compute at what row does the user want us to stop.
    // The code will still compute the transpose for these
    // extra rows, but it is thrown away.
    u64 stopIdx =
        doneIdx + std::min<u64>(u64(128) * superBlkSize, numOtExt - doneIdx);

    for (u64 i = 0; i < numCols / 128; ++i) {
      for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx) {
        // generate the column indexed by colIdx. This is done with
        // AES in counter mode acting as a PRNG. We don't use the normal
        // PRNG interface because that would result in a data copy when
        // we move it into the T0,T1 matrices. Instead we do it directly.
        mGens[colIdx][0].ecbEncCounterMode(
            mGensBlkIdx[colIdx], superBlkSize,
            ((block*)t0.data() + superBlkSize * tIdx));
        mGens[colIdx][1].ecbEncCounterMode(
            mGensBlkIdx[colIdx], superBlkSize,
            ((block*)t1.data() + superBlkSize * tIdx));

        // increment the counter mode idx.
        mGensBlkIdx[colIdx] += superBlkSize;
      }

      // transpose our 128 columns of 1024 bits. We will have 1024 rows,
      // each 128 bits wide.
      sse_transpose128x1024(t0);
      sse_transpose128x1024(t1);

      // This is the index of where we will store the matrix long term.
      // doneIdx is the starting row. i is the offset into the blocks of 128
      // bits.
      // __restrict isn't crucial, it just tells the compiler that this pointer
      // is unique and it shouldn't worry about pointer aliasing.
      block* __restrict mT0Iter = mT0.data() + mT0.stride() * doneIdx + i;
      block* __restrict mT1Iter = mT1.data() + mT1.stride() * doneIdx + i;

      for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++j) {
        // because we transposed 1024 rows, the indexing gets a bit weird. But
        // this is the location of the next row that we want. Keep in mind that
        // we had long
        // **contiguous** columns.
        block* __restrict t0Iter = ((block*)t0.data()) + j;
        block* __restrict t1Iter = ((block*)t1.data()) + j;

        // do the copy!
        for (u64 k = 0; rowIdx < stopIdx && k < 128; ++rowIdx, ++k) {
          *mT0Iter = *(t0Iter);
          *mT1Iter = *(t1Iter);

          t0Iter += superBlkSize;
          t1Iter += superBlkSize;

          mT0Iter += mT0.stride();
          mT1Iter += mT0.stride();
        }
      }
    }

    doneIdx = stopIdx;
  }
  return 0;
}

int kkrt_receiver::encode(u64 otIdx, const void* input, void* dest,
                          u64 destSize) {
  static const int width(4);
#ifndef NDEBUG
  if (mT0.stride() != width) return -1002;
  // if (choice.size() != mT0.stride())
  //     throw std::invalid_argument("");
  if (eq(mT0[otIdx][0], ZeroBlock)) return -1000;
  if (eq(mT0[otIdx][0], AllOneBlock)) return -1001;
#endif  // !NDEBUG

  block* t0Val = mT0.data() + mT0.stride() * otIdx;
  block* t1Val = mT1.data() + mT0.stride() * otIdx;

  // 128 bit input restriction
  block word = ZeroBlock;
  memcpy(&word, input, mInputByteCount);

  // run the input word through AES to get a psuedo-random codeword. Then
  // XOR the input with the AES output.
  std::array<block, width> choice{word, word, word, word}, code;
  mMultiKeyAES.ecbEncNBlocks(choice.data(), code.data());

  // encode the correction value as u = T0 + T1 + c(w), there c(w) is a
  // pseudo-random codeword.

  for (u64 i = 0; i < width; ++i) {
    // final code is the output of AES plus the input
    code[i] = code[i] ^ choice[i];

    // reuse mT1 as the place we store the correlated value.
    // this will later get sent to the sender.
    t1Val[i] = code[i] ^ t0Val[i] ^ t1Val[i];
  }
  if (_hash) {
    _hash->hasher_reset();
    _hash->hasher_update((char*)mT0[otIdx].data(),
                         mT0[otIdx].size() * sizeof(block));
    _hash->hasher_final((char*)dest, 16);
  } else {
    std::array<block, 4> aesBuff;
    mAesFixedKey.ecbEncBlocks(t0Val, mT0.stride(), aesBuff.data());
    oc::block val = ZeroBlock;
    for (u64 i = 0; i < mT0.stride(); ++i) val = val ^ aesBuff[i] ^ t0Val[i];
    memcpy(dest, &val, 16);
  }
// #ifdef KKRT_SHA_HASH

//   // now hash it to remove the correlation.
//   RandomOracle sha1(destSize);
//   sha1.Update((u8*)mT0[otIdx].data(), mT0[otIdx].size() * sizeof(block));
//   sha1.Final((u8*)dest);
// #else
//   std::array<block, 10> aesBuff;
//   mAesFixedKey.ecbEncBlocks(t0Val, mT0.stride(), aesBuff.data());

//   val = ZeroBlock;
//   for (u64 i = 0; i < mT0.stride(); ++i) val = val ^ aesBuff[i] ^ t0Val[i];
// #endif
#ifndef NDEBUG
  // a debug check to mark this OT as used and ready to send.
  mT0[otIdx][0] = AllOneBlock;
#endif
  return 0;
}

int kkrt_receiver::sendCorrection(conn* sock, oc::u64 sendCount) {
#ifndef NDEBUG
  // make sure these OTs all contain valid correction values, aka encode has
  // been called.
  for (u64 i = mCorrectionIdx; i < mCorrectionIdx + sendCount; ++i)
    if (neq(mT0[i][0], AllOneBlock)) return -2000;
#endif

  // this is potentially dangerous. We dont have a guarantee that mT1 will still
  // exist when the network gets around to sending this. Oh well.
  sock->send(string((char*)(mT1.data() + (mCorrectionIdx * mT1.stride())),
                    mT1.stride() * sendCount * sizeof(block)));
  //   mHasPendingSendFuture = true;
  //   mPendingSendFuture =
  //       chl.asyncSendFuture((u8*)(mT1.data() + (mCorrectionIdx *
  //       mT1.stride())),
  //                           mT1.stride() * sendCount * sizeof(block));

  mCorrectionIdx += sendCount;
  return 0;
}

int kkrt_receiver::encode_all(int numOTExt, const std::vector<oc::u32>& inputs,
                              std::vector<block>& out_mask) {
  out_mask.resize(numOTExt);
  auto begin = out_mask.data();
  for (auto k = 0ull; k < numOTExt; ++k) {
    *(begin + k) = oc::toBlock(inputs[k]);
    encode(k, begin + k, begin + k, 16);
  }
  return 0;
}
}  // namespace fucrypto