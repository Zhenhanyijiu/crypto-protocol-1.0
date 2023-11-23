#include "crypto-protocol/cm20.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/ot_interface.h"
#include "crypto-protocol/hasher.h"
#include <bits/stdc++.h>
using namespace std;
using namespace oc;
namespace fucrypto {
// cm20_sender::cm20_sender(){};
cm20_sender::cm20_sender(conn *sock, u8 *commonSeedIn, u64 senderSizeIn,
                         u64 matrixWidthIn, u64 logHeightIn, int threadNum,
                         u64 hash2LengthInBytesIn, u64 bucket2ForComputeH2Out) {
  this->threadNumOmp = threadNum;
  this->matrixWidth = matrixWidthIn;
  this->matrixWidthInBytes = (this->matrixWidth + 7) >> 3;
  this->commonSeed = toBlock(commonSeedIn);
  this->logHeight = logHeightIn;
  this->height = 1 << this->logHeight;
  this->heightInBytes = (this->height + 7) >> 3;  // 除以8
  this->senderSize = senderSizeIn;
  this->senderSizeInBytes = (this->senderSize + 7) >> 3;
  this->bucket1 = 256;
  this->bucket2ForComputeH2Output = bucket2ForComputeH2Out;  // default 256
  // this->h1LengthInBytes = 32;
  // todo
  this->hash2LengthInBytes = hash2LengthInBytesIn;
  srand(time(NULL));
  int rn[4];
  for (int i = 0; i < 4; i++) {
    rn[i] = rand();
  }
  block localSeed = _mm_set_epi32(rn[0], rn[1], rn[2], rn[3]);
  // block localSeed = _mm_set_epi32(100, 100, 100, 100);
  PRNG localRng(localSeed);
  // 初始化一个向量r，长度为width
  this->choicesWidthInput.resize(this->matrixWidth);
  this->choicesWidthInput.randomize(localRng);
  this->hashOutputBuff.resize(this->hash2LengthInBytes *
                              this->bucket2ForComputeH2Output);
  this->hashInputs.resize(this->bucket2ForComputeH2Output);
  for (u64 i = 0; i < this->bucket2ForComputeH2Output; i++) {
    this->hashInputs[i].resize(this->matrixWidthInBytes);
  }
  this->transHashInputs.resize(this->matrixWidth);
  for (u64 i = 0; i < this->matrixWidth; i++) {
    this->transHashInputs[i].resize(this->senderSizeInBytes);
    memset(this->transHashInputs[i].data(), 0, this->senderSizeInBytes);
  }
  this->lowL = (u64)0;
  // PRNG comPrng(rhis->commonSeed);
  // this->commonPrng = new PRNG(this->commonSeed);
  // this->sendSet = new block[this->senderSize];
  printf("[cm20.cpp] hash2LengthInBytes:%ld,bucket2ForComputeH2Output:%ld\n",
         this->hash2LengthInBytes, this->bucket2ForComputeH2Output);
  config_param param;
  auto ote = new_ote_receiver(param);
  ote->receive(this->choicesWidthInput, this->recoverMsgWidthOutput, sock);
  //   return this->iknpOteReceiver.init(localRng);
};
cm20_sender::~cm20_sender() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~cm20_sender free");
};
typedef struct RecoverMatrixCInfo {
  int threadId;
  // 1
  u64 shift;
  // 2
  u64 wLeftBegin;
  // 3
  u64 processNum;
  // 4
  u64 aesKeyNum;
  // 5
  u64 aesComkeysBegin;
  // 6
  block *aesComKeys;
  // AES *currThreadAesFkey;
  // 7
  u64 senderSize;
  // 8
  u64 heightInBytes;
  // 9
  u64 locationInBytes;
  // 10
  u64 bucket1;
  // 11
  u64 widthBucket1;
  // 12
  block *sendset;
  // 13
  block *recoverMsgWidthOutputPtr;
  // 14
  int *choicesWidthInputPtr;
  // 15
  const u8 *recvMatrixADBuffBegin;
  // 16
  vector<u8> *transHashInputsPtr;
  // 17
  u8 *recoverMatCBuffBegin;
  // 18
  const u8 *encMatrixABuffBegin;
} RecoverMatrixCInfo;
void process_recover_matrix_C(RecoverMatrixCInfo *infoArg) {
  printf("[cm20.cpp] (process_recover_matrix_C) thread id:%d\n",
         infoArg->threadId);
  int cycTimes = 0;
  u64 widthBucket1 = infoArg->widthBucket1;
  u64 bucket1 = infoArg->bucket1;
  u64 senderSize = infoArg->senderSize;
  u64 heightInBytes = infoArg->heightInBytes;
  u64 locationInBytes = infoArg->locationInBytes;
  // block randomLocations[bucket1]; // 256个block
  vector<block> randomLocations(bucket1);
  // u8 *matrixC[widthBucket1]; // 16
  vector<u8 *> matrixC(widthBucket1);
  vector<vector<u8>> matC(widthBucket1);
  // u8 *transLocations[widthBucket1];
  // vector<u8 *> transLocations(widthBucket1);
  // vector<vector<u8>> trans(widthBucket1);
  for (u64 i = 0; i < widthBucket1; ++i) {
    // 256*1+4，每个元素为u8*，下面语句为创建一个u8*,260个u8
    // transLocations[i] = new u8[senderSize * locationInBytes + sizeof(u32)];
    // matrixC[i] = new u8[heightInBytes]; // 32
    // trans[i].resize(senderSize * locationInBytes + sizeof(u32));
    // transLocations[i] = trans[i].data();
    matC[i].resize(heightInBytes);
    matrixC[i] = matC[i].data();
  }

  for (u64 wLeft = 0; wLeft < infoArg->processNum;
       wLeft += widthBucket1, cycTimes++) {
    u64 wRight = wLeft + widthBucket1 < infoArg->processNum
                     ? wLeft + widthBucket1
                     : infoArg->processNum;
    u64 w = wRight - wLeft;

    // Extend OTs and compute matrix C
    // u8 *recvMatrix;
    u64 offset1 = wLeft * heightInBytes;
    u64 offset2 = 0;
    for (u64 i = 0; i < w; ++i) {
      PRNG prng(infoArg->recoverMsgWidthOutputPtr[i + wLeft]);
      prng.get(matrixC[i], heightInBytes);
      if (infoArg->choicesWidthInputPtr[i + wLeft]) {
        for (u64 j = 0; j < heightInBytes; ++j) {
          matrixC[i][j] ^=
              (infoArg->recvMatrixADBuffBegin + offset1 + offset2)[j];
        }
      }
      offset2 += heightInBytes;
    }
    // Compute random locations transposed
    AES commonAesFkey;
    commonAesFkey.setKey(infoArg->aesComKeys[cycTimes]);
    for (u64 low = 0; low < senderSize; low += bucket1) {
      u64 up = low + bucket1 < senderSize ? low + bucket1 : senderSize;
      commonAesFkey.ecbEncBlocks(infoArg->sendset + low, up - low,
                                 randomLocations.data());
      for (u64 i = 0; i < w; ++i) {
        for (u64 j = low; j < up; ++j) {
          // memcpy(transLocations[i] + j * locationInBytes,
          //        (u8 *)(randomLocations.data() + (j - low)) + i *
          //        locationInBytes, locationInBytes);
          //
          // auto location = (*(u32 *)(transLocations[i] + j * locationInBytes))
          // & (infoArg->shift);
          auto location = (*(u32 *)((u8 *)(randomLocations.data() + (j - low)) +
                                    i * locationInBytes)) &
                          (infoArg->shift);
          infoArg->transHashInputsPtr[i + wLeft][j >> 3] |=
              (u8)((bool)(matrixC[i][location >> 3] & (1 << (location & 7))))
              << (j & 7);
        }
      }
    }
    // // Extend OTs and compute matrix C
    // // u8 *recvMatrix;
    // u64 offset1 = wLeft * heightInBytes;
    // u64 offset2 = 0;
    // for (u64 i = 0; i < w; ++i)
    // {
    //   PRNG prng(infoArg->recoverMsgWidthOutputPtr[i + wLeft]);
    //   prng.get(matrixC[i], heightInBytes);
    //   if (infoArg->choicesWidthInputPtr[i + wLeft])
    //   {
    //     for (u64 j = 0; j < heightInBytes; ++j)
    //     {
    //       matrixC[i][j] ^= (infoArg->recvMatrixADBuffBegin + offset1 +
    //       offset2)[j];
    //     }
    //   }
    //   offset2 += heightInBytes;
    // }
    // Compute hash inputs (transposed)
    // for (u64 i = 0; i < w; ++i)
    // {
    //   for (u64 j = 0; j < senderSize; ++j)
    //   {
    //     auto location = (*(u32 *)(transLocations[i] + j * locationInBytes)) &
    //     (infoArg->shift); infoArg->transHashInputsPtr[i + wLeft][j >> 3] |=
    //         (u8)((bool)(matrixC[i][location >> 3] & (1 << (location & 7))))
    //         << (j & 7);
    //   }
    // }
  }
  //**************释放内存*************//
  // for (u64 i = 0; i < widthBucket1; ++i)
  // {
  //   delete[] transLocations[i];
  //   transLocations[i] = nullptr;
  //   delete[] matrixC[i];
  //   matrixC[i] = nullptr;
  // }
}

int cm20_sender::recoverMatrixC(conn *sock, vector<block> &senderSet) {
  string matrix_a_d_recv = sock->recv();
  u8 *recvMatrixADBuff = (u8 *)matrix_a_d_recv.data();
  u64 recvMatixADBuffSize = matrix_a_d_recv.size();
  auto locationInBytes = (this->logHeight + 7) / 8;     // logHeight==1
  auto widthBucket1 = sizeof(block) / locationInBytes;  // 16/1
  u64 shift = (1 << this->logHeight) - 1;               // 全1
  printf(
      "[cm20.cpp] recover matrix "
      "C,widthBucket1:%ld(16/loc),locationInBytes:%ld\n",
      widthBucket1, locationInBytes);
  if (recvMatixADBuffSize != this->matrixWidth * this->heightInBytes) {
    return -111;
  }
  // u8 *transHashInputs[this->matrixWidth]; // width==60，矩阵宽度
  printf("[cm20.cpp] ****** before cycle in recover MatrixC ******\n");
  //   long start1 = start_time();
  int threadNum = this->threadNumOmp;
  u64 sumCount = 0;
  int isExit = 0;
  printf("[cm20.cpp] ====== 参数准备开始 ======\n");
  // RecoverMatrixCInfo infoArgs[threadNum];
  vector<RecoverMatrixCInfo> infoArgs(threadNum);
  // block *senderSet = new block[senderSet1.size()];
  // memcpy(senderSet, senderSet1.data(), senderSet1.size() * sizeof(block));
  // 内存初始化为0
  memset(infoArgs.data(), 0, threadNum * sizeof(RecoverMatrixCInfo));
  // 对每个线程进行分配处理的矩阵的列数
  for (;;) {
    for (int k = 0; k < threadNum; k++) {
      u64 wRight = sumCount + widthBucket1;
      if (wRight <= this->matrixWidth) {
        // 3
        infoArgs[k].processNum += widthBucket1;
        // 4
        infoArgs[k].aesKeyNum++;
      } else {
        isExit = 1;
        break;
      }
      sumCount += widthBucket1;
    }
    if (isExit) {
      break;
    }
  }
  printf("[cm20.cpp] omp 处理,sumCount:=%ld\n", sumCount);
  // 不要漏掉余数
  if ((this->matrixWidth - sumCount) != 0) {
    infoArgs[threadNum - 1].processNum += this->matrixWidth - sumCount;
    infoArgs[threadNum - 1].aesKeyNum += 1;
  }
  for (int i = 0; i < threadNum; i++) {
    printf("[cm20.cpp] procesNum[%2d]=:%2ld,", i, infoArgs[i].processNum);
  }
  printf("\n");
  for (int i = 0; i < threadNum; i++) {
    printf("[cm20.cpp] aesKeyNum[%2d]=:%2ld,", i, infoArgs[i].aesKeyNum);
  }
  // 分配处理的矩阵的列数结束
  // 最重要的一步，生成Fk函数的keys
  PRNG commonPrng(this->commonSeed);
  vector<block> commonKeys;
  for (u64 wLeft = 0; wLeft < this->matrixWidth; wLeft += widthBucket1) {
    block comKey;
    commonPrng.get((u8 *)&comKey, sizeof(block));
    // commonKeys.push_back(comKey);
    commonKeys.emplace_back(comKey);
  }
  printf("\n[cm20.cpp] commonKeys size:%ld\n", commonKeys.size());
  // 最重要的一步，取出 choicesWidthInput
  u64 choiceSize = this->choicesWidthInput.size();
  vector<int> choiceVector;
  for (u64 i = 0; i < choiceSize; i++) {
    // choiceVector.push_back(this->choicesWidthInput[i]);
    choiceVector.emplace_back(this->choicesWidthInput[i]);
  }
  // 给参数赋值
  for (int k = 0; k < threadNum; k++) {
    infoArgs[k].threadId = k;
    // 1
    infoArgs[k].shift = shift;
    if (k == 0) {
      // 2
      infoArgs[k].wLeftBegin = 0;
      // 5
      infoArgs[k].aesComkeysBegin = 0;
    } else {
      infoArgs[k].wLeftBegin =
          infoArgs[k - 1].wLeftBegin + infoArgs[k - 1].processNum;
      infoArgs[k].aesComkeysBegin =
          infoArgs[k - 1].aesComkeysBegin + infoArgs[k - 1].aesKeyNum;
    }
    // 7
    infoArgs[k].senderSize = this->senderSize;
    // 8
    infoArgs[k].heightInBytes = this->heightInBytes;
    // 9
    infoArgs[k].locationInBytes = locationInBytes;
    // 10
    infoArgs[k].bucket1 = this->bucket1;
    // 11
    infoArgs[k].widthBucket1 = widthBucket1;
    // 6
    infoArgs[k].aesComKeys =
        (block *)(commonKeys.data()) + infoArgs[k].aesComkeysBegin;
    // 12
    infoArgs[k].sendset = senderSet.data();
    // infoArgs[k].sendset = senderSet;
    // 13
    infoArgs[k].recoverMsgWidthOutputPtr =
        this->recoverMsgWidthOutput.data() + infoArgs[k].wLeftBegin;
    // 14
    infoArgs[k].choicesWidthInputPtr =
        choiceVector.data() + infoArgs[k].wLeftBegin;  // todo
    // 15
    infoArgs[k].recvMatrixADBuffBegin =
        recvMatrixADBuff + infoArgs[k].wLeftBegin * this->heightInBytes;
    // 16
    infoArgs[k].transHashInputsPtr =
        (vector<u8> *)(this->transHashInputs.data()) + infoArgs[k].wLeftBegin;
  }

  for (int i = 0; i < threadNum; i++) {
    printf("[cm20.cpp] aesBegin[%2d]:%2ld,", i, infoArgs[i].aesComkeysBegin);
  }
  printf("\n");
  for (int j = 0; j < threadNum; j++) {
    printf("[cm20.cpp] wlfBegin[%2d]:%2ld,", j, infoArgs[j].wLeftBegin);
  }
  printf("\n[cm20.cpp] ====== 参数准备结束 ======\n");
  printf("[cm20.cpp] ====== 并行处理恢复矩阵 C 开始,threadNum(%d) ======\n",
         threadNum);

#pragma omp parallel for num_threads(threadNum)
  for (int i = 0; i < threadNum; i++) {
    process_recover_matrix_C(infoArgs.data() + i);
  }
  printf("[cm20.cpp] ====== 并行处理恢复矩阵 C 结束,threadNum(%d) ======\n",
         threadNum);
  printf("[cm20.cpp] ****** end cycle in recover MatrixC ******\n");
  //   printf("[cm20.cpp] cycle 用时：%ldms\n", get_use_time(start1));
  return 0;
}
int cm20_sender::computeHashOutputToReceiverOnce(conn *sock) {
  //  this->lowL < this->senderSize
  for (;;) {
    if (this->lowL >= this->senderSize) break;
    auto upR = this->lowL + this->bucket2ForComputeH2Output < this->senderSize
                   ? this->lowL + this->bucket2ForComputeH2Output
                   : this->senderSize;

    //   ROracle ro;
    auto ro = (*hasher_map_ptr)["sha256"]();
    char hashOutput[32];
    for (auto j = this->lowL; j < upR; ++j) {
      memset(this->hashInputs[j - this->lowL].data(), 0,
             this->matrixWidthInBytes);
    }
    for (u64 i = 0; i < this->matrixWidth; ++i) {
      for (u64 j = this->lowL; j < upR; ++j) {
        this->hashInputs[j - this->lowL][i >> 3] |=
            (u8)((bool)(this->transHashInputs[i][j >> 3] & (1 << (j & 7))))
            << (i & 7);
      }
    }
    u64 offset = 0;
    for (u64 j = this->lowL; j < upR; ++j, offset += this->hash2LengthInBytes) {
      // if (j == this->lowL)
      // {
      //   cout << "    最后计算:" << j << "," << *(block *)(this->hashInputs[j
      //   - this->lowL].data()) << endl;
      // }

      ro->hasher_reset();
      ro->hasher_update((char *)this->hashInputs[j - this->lowL].data(),
                        this->matrixWidthInBytes);
      ro->hasher_final(hashOutput, 32);
      memcpy(this->hashOutputBuff.data() + offset, hashOutput,
             this->hash2LengthInBytes);
    }
    // *sendBuffSize = (upR - this->lowL) * this->hash2LengthInBytes;
    // *sendBuff = this->hashOutputBuff.data();

    sock->send(string((char *)this->hashOutputBuff.data(),
                      (upR - this->lowL) * this->hash2LengthInBytes));
    this->lowL += this->bucket2ForComputeH2Output;
  }

  return 0;
}
///////////////////////////////////////////////////////////////

cm20_receiver::~cm20_receiver() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~cm20_receiver free");
}
// cm20_receiver::cm20_receiver() {}
cm20_receiver::cm20_receiver(conn *sock, u8 *commonSeedIn, u64 receiverSizeIn,
                             u64 senderSizeIn, u64 matrixWidthIn,
                             u64 logHeightIn, int threadNum,
                             u64 hash2LengthInBytesIn,
                             u64 bucket2ForComputeH2Out) {
  this->threadNumOmp = threadNum;
  this->matrixWidth = matrixWidthIn;
  this->matrixWidthInBytes = (matrixWidthIn + 7) >> 3;
  this->receiverSize = receiverSizeIn;
  this->senderSize = senderSizeIn;
  this->receiverSizeInBytes = (receiverSizeIn + 7) >> 3;
  this->logHeight = logHeightIn;
  this->height = 1 << this->logHeight;
  this->heightInBytes = (this->height + 7) >> 3;  // 除以8
  this->bucket1 = 256;
  this->bucket2ForComputeH2Output = bucket2ForComputeH2Out;  // default 256
  // this->h1LengthInBytes = 32;
  this->hash2LengthInBytes = hash2LengthInBytesIn;
  this->sendMatrixADBuff.resize(this->heightInBytes * this->matrixWidth);
  this->transHashInputs.resize(this->matrixWidth);
  for (u64 i = 0; i < this->matrixWidth; ++i) {
    this->transHashInputs[i].resize(this->receiverSizeInBytes);
    memset(this->transHashInputs[i].data(), 0, this->receiverSizeInBytes);
  }
  this->encMsgOutput.resize(this->matrixWidth);
  this->commonSeed = toBlock(commonSeedIn);
  // block localSeedBlock = toBlock((u8 *)localSeed);
  srand(time(NULL));
  int rn[4];
  for (int i = 0; i < 4; i++) {
    rn[i] = rand();
  }
  // init local rng seed
  PRNG localRng(_mm_set_epi32(rn[0], rn[1], rn[2], rn[3]));
  // PRNG localRng(_mm_set_epi32(101, 103, 107, 100));
  this->lowL = (u64)0;
  this->indexId = 0;
  this->psiComputePool = new (std::nothrow) ThreadPool(this->threadNumOmp);
  if (this->psiComputePool == nullptr) {
    return;
  }

  this->psiResults.resize(this->senderSize / this->bucket2ForComputeH2Output +
                          2);
  this->psiResultPirQuery.resize(
      this->senderSize / this->bucket2ForComputeH2Output + 2);
  config_param param;
  auto ote = new_ote_sender(param);
  ote->send(this->encMsgOutput, sock);
  //   return this->iknpOteSender.init(localRng);
};

// 并行计算 MatrixAxorD,参数结构体
typedef struct ComputeMatrixAxorDInfo {
  int threadId;
  // 1
  u64 shift;
  // 2
  u64 wLeftBegin;
  // 3
  u64 processNum;
  // 4
  u64 aesKeyNum;
  // 5
  u64 aesComkeysBegin;
  // 6
  block *aesComKeys;
  // 7
  u64 receiverSize;
  // 8
  u64 heightInBytes;
  // 9
  u64 locationInBytes;
  // 10
  u64 bucket1;
  // 11
  u64 widthBucket1;
  // 12
  block *recvSet;
  // 13
  array<block, 2> *encMsgOutputPtr;
  // 15
  const u8 *recvMatrixADBuffBegin;
  // 16
  vector<u8> *transHashInputsPtr;
  // 17,存储发送给对方的数据
  u8 *sendMatrixADBuffPtr;
} ComputeMatrixAxorDInfo;
// 并行计算矩阵AxorD，处理函数
void process_compute_Matrix_AxorD(ComputeMatrixAxorDInfo *infoArg) {
  //   printf("[cm20.cpp] (process_compute_Matrix_AxorD) thread id:%d\n",
  //          infoArg->threadId);
  int cycTimes = 0;
  u64 bucket1 = infoArg->bucket1;
  u64 widthBucket1 = infoArg->widthBucket1;
  u64 heightInBytes = infoArg->heightInBytes;
  u64 locationInBytes = infoArg->locationInBytes;
  u64 receiverSize = infoArg->receiverSize;
  // block randomLocations[bucket1]; // 256block
  vector<block> randomLocations(bucket1);
  // 这种写法有问题
  //  u8 *transLocations[widthBucket1];
  //   printf("    widthBucket1:%d,locationInBytes:%d\n", widthBucket1,
  //          locationInBytes);
  // vector<u8 *> transLocations(widthBucket1);
  // vector<vector<u8>> trans(widthBucket1);
  // for (u64 i = 0; i < widthBucket1; ++i)
  // {
  //   transLocations[i] = new u8[receiverSize * locationInBytes + sizeof(u32)];
  //   trans[i].resize(receiverSize * locationInBytes + sizeof(u32));
  //   transLocations[i] = trans[i].data();
  // }
  // u8 *matrixA[widthBucket1];
  vector<u8 *> matrixA(widthBucket1);
  vector<vector<u8>> matA(widthBucket1);
  // u8 *matrixDelta[widthBucket1];
  vector<u8 *> matrixDelta(widthBucket1);
  vector<vector<u8>> matD(widthBucket1);
  for (u64 i = 0; i < widthBucket1; ++i) {
    // matrixA[i] = new u8[heightInBytes]; //要释放
    // matrixDelta[i] = new u8[heightInBytes];
    matA[i].resize(heightInBytes);
    matD[i].resize(heightInBytes);
    matrixA[i] = matA[i].data();
    matrixDelta[i] = matD[i].data();
  }

  for (u64 wLeft = 0; wLeft < infoArg->processNum;
       wLeft += widthBucket1, cycTimes++) {
    u64 wRight = wLeft + widthBucket1 < infoArg->processNum
                     ? wLeft + widthBucket1
                     : infoArg->processNum;
    u64 w = wRight - wLeft;
    //////////// Compute random locations (transposed) ////////////////
    // 对应论文中的P2(接收者)
    for (u64 i = 0; i < widthBucket1; ++i) {
      memset(matrixDelta[i], 255, heightInBytes);
      // heightInBytes，置为全1矩阵
    }
    // 先把 matrixA 生成
    for (u64 i = 0; i < w; ++i) {
      PRNG prng(infoArg->encMsgOutputPtr[i + wLeft][0]);
      prng.get(matrixA[i], heightInBytes);
    }

    AES commonAesFkey;
    commonAesFkey.setKey(infoArg->aesComKeys[cycTimes]);
    for (u64 low = 0; low < receiverSize; low += bucket1) {
      u64 up = low + bucket1 < receiverSize ? low + bucket1 : receiverSize;
      // 每256个输入处理一次，randomLocations==256blocks,Fk函数，Fk(H1(y))
      commonAesFkey.ecbEncBlocks(infoArg->recvSet + low, up - low,
                                 randomLocations.data());
      // 如果w比较宽，这里的计算会增加
      for (u64 i = 0; i < w; ++i) {
        // for (u64 j = low; j < up; ++j)
        // {
        //   // randomLocations,256个block
        //   memcpy(transLocations[i] + j * locationInBytes,
        //          (u8 *)(randomLocations.data() + (j - low)) + i *
        //          locationInBytes, locationInBytes);
        // }
        // D 置 0
        for (u64 j = low; j < up; ++j) {
          // auto location = (*(u32 *)(transLocations[i] + j * locationInBytes))
          // & (infoArg->shift);
          auto location = (*(u32 *)((u8 *)(randomLocations.data() + (j - low)) +
                                    i * locationInBytes)) &
                          (infoArg->shift);
          // shift全1
          // location >> 3(除以8)表示matrixDelta[i]的字节位置
          // location & 0b0111,取出低3位；(location & 7)==0,1,2,3,4,5,6,7
          matrixDelta[i][location >> 3] &= ~(1 << (location & 7));
        }
        ///////////////// Compute hash inputs (transposed) /////////////////////
        for (u64 j = low; j < up; ++j) {
          // auto location = (*(u32 *)(transLocations[i] + j * locationInBytes))
          // & (infoArg->shift);
          auto location = (*(u32 *)((u8 *)(randomLocations.data() + (j - low)) +
                                    i * locationInBytes)) &
                          (infoArg->shift);
          infoArg->transHashInputsPtr[i + wLeft][j >> 3] |=
              (u8)((bool)(matrixA[i][location >> 3] & (1 << (location & 7))))
              << (j & 7);
        }
      }
    }
    //////////// Compute matrix Delta /////////////////////////////////

    //////////////// Compute matrix A & sent matrix ///////////////////////
    u64 offset1 = wLeft * heightInBytes;
    u64 offset2 = 0;
    for (u64 i = 0; i < w; ++i) {
      // PRNG prng(infoArg->encMsgOutputPtr[i + wLeft][0]);
      // prng.get(matrixA[i], heightInBytes);
      PRNG prng(infoArg->encMsgOutputPtr[i + wLeft][1]);
      // prng.get(sentMatrix[i], this->heightInBytes);
      prng.get(infoArg->sendMatrixADBuffPtr + offset1 + offset2, heightInBytes);
      for (u64 j = 0; j < heightInBytes; ++j) {
        // sentMatrix[i][j] ^= matrixA[i][j] ^ matrixDelta[i][j];
        (infoArg->sendMatrixADBuffPtr + offset1 + offset2)[j] ^=
            matrixA[i][j] ^ matrixDelta[i][j];
      }
      // 发送sM^A^D
      // 发送数据U^A^D给对方，
      //  ch.asyncSend(sentMatrix[i], heightInBytes);
      // 偏移计算
      offset2 += heightInBytes;
    }
  }
}

int cm20_receiver::getSendMatrixADBuff(conn *sock, vector<block> &receiverSet) {
  // u32 locationInBytes = (this->logHeight + 7) / 8;
  u64 locationInBytes = (this->logHeight + 7) >> 3;
  u64 widthBucket1 = sizeof(block) / locationInBytes;
  u64 shift = (1 << this->logHeight) - 1;  // 全1
  //////////// Initialization ///////////////////
  PRNG commonPrng(this->commonSeed);
  // block commonKey;
  // AES commonAes;
  if (receiverSet.size() != this->receiverSize) {
    return -111;
  }
  /*********for cycle start*********/
  //   printf("[cm20.cpp] (AD)widthBucket1(16/loc):%ld,locationInBytes:%ld\n",
  //          widthBucket1, locationInBytes);
  //   printf("\n[cm20.cpp] ====== 并行计算 AxorD 参数准备开始 ======\n");
  // 并行计算矩阵AxorD
  int threadNum = this->threadNumOmp;
  int sumCount = 0;
  int isExit = 0;
  // ComputeMatrixAxorDInfo infoArgs[threadNum];
  vector<ComputeMatrixAxorDInfo> infoArgs(threadNum);
  // block *receiverSet = new block[receiverSet1.size()];
  // memcpy(receiverSet, receiverSet1.data(), receiverSet1.size() *
  // sizeof(block));
  // 将全部内存初始为0
  memset(infoArgs.data(), 0, sizeof(ComputeMatrixAxorDInfo) * threadNum);
  // 为每一个线程生成参数数据,主要是处理的矩阵的列数
  for (;;) {
    for (int k = 0; k < threadNum; k++) {
      u64 wRight = sumCount + widthBucket1;
      if (wRight <= this->matrixWidth) {
        // 3
        infoArgs[k].processNum += widthBucket1;
        // 4
        infoArgs[k].aesKeyNum++;
      } else {
        isExit = 1;
        break;
      }
      sumCount += widthBucket1;
    }
    if (isExit) {
      break;
    }
  }
  //   printf("[cm20.cpp] debug sumCount:=%d\n", sumCount);
  // 不要漏掉余数
  if ((this->matrixWidth - sumCount) != 0) {
    infoArgs[threadNum - 1].processNum += this->matrixWidth - sumCount;
    infoArgs[threadNum - 1].aesKeyNum += 1;
  }
  for (int i = 0; i < threadNum; i++) {
    // printf("[cm20.cpp] procesNum[%2d]:=%2ld,", i, infoArgs[i].processNum);
  }
  //   printf("\n");
  for (int i = 0; i < threadNum; i++) {
    // printf("[cm20.cpp] aesKeyNum[%2d]:=%2ld,", i, infoArgs[i].aesKeyNum);
  }
  // 分配处理的矩阵的列数结束
  // 最重要的一步，生成Fk函数的keys
  vector<block> commonKeys;
  for (u64 wLeft = 0; wLeft < this->matrixWidth; wLeft += widthBucket1) {
    block comKey;
    commonPrng.get((u8 *)&comKey, sizeof(block));
    // commonKeys.push_back(comKey);
    commonKeys.emplace_back(comKey);
  }
  // printf("\n[cm20.cpp] commonKeys size:%ld\n", commonKeys.size());
  //   printf("\n>>>>>> [cm20.cpp] commonKeys size:%ld\n", commonKeys.size());
  // for (int i = 0; i < commonKeys.size(); i++)
  // {
  //   cout << "i:" << i << "," << commonKeys[i] << endl;
  // }
  cout << endl;
  // 给参数赋值,重要
  for (int k = 0; k < threadNum; k++) {
    infoArgs[k].threadId = k;
    // 1
    infoArgs[k].shift = shift;
    if (k == 0) {
      // 2
      infoArgs[k].wLeftBegin = 0;
      // 5
      infoArgs[k].aesComkeysBegin = 0;
    } else {
      infoArgs[k].wLeftBegin =
          infoArgs[k - 1].wLeftBegin + infoArgs[k - 1].processNum;
      infoArgs[k].aesComkeysBegin =
          infoArgs[k - 1].aesComkeysBegin + infoArgs[k - 1].aesKeyNum;
    }
    // 7
    infoArgs[k].receiverSize = this->receiverSize;
    // 8
    infoArgs[k].heightInBytes = this->heightInBytes;
    // 9
    infoArgs[k].locationInBytes = locationInBytes;
    // 10
    infoArgs[k].bucket1 = this->bucket1;
    // 11
    infoArgs[k].widthBucket1 = widthBucket1;
    // 6
    infoArgs[k].aesComKeys =
        (block *)(commonKeys.data()) + infoArgs[k].aesComkeysBegin;
    // 12
    infoArgs[k].recvSet = receiverSet.data();
    // infoArgs[k].recvSet = receiverSet;
    // 13
    infoArgs[k].encMsgOutputPtr =
        (array<block, 2> *)(this->encMsgOutput.data()) + infoArgs[k].wLeftBegin;
    // 16
    infoArgs[k].transHashInputsPtr =
        (vector<u8> *)(this->transHashInputs.data()) + infoArgs[k].wLeftBegin;
    // 17
    infoArgs[k].sendMatrixADBuffPtr =
        (u8 *)(this->sendMatrixADBuff.data()) +
        (infoArgs[k].wLeftBegin) * (this->heightInBytes);
  }
  for (int i = 0; i < threadNum; i++) {
    // printf("[cm20.cpp] aesBegin[%2d]:%2ld,", i, infoArgs[i].aesComkeysBegin);
  }
  //   printf("\n");
  for (int j = 0; j < threadNum; j++) {
    // printf("[cm20.cpp] wlfBegin[%2d]:%2ld,", j, infoArgs[j].wLeftBegin);
  }
  //   printf("\n[cm20.cpp] ====== 并行计算 AxorD 参数准备结束 ======\n");
  //   printf("[cm20.cpp] ====== 开始并行计算矩阵 AxorD,threadNum(%d) ======\n",
  //          threadNum);
  // omp process
  // printf("*************** sleep 10s ************\n");
  // sleep(10);
  // printf("*************** sleep 10s end ************\n");

#pragma omp parallel for num_threads(threadNum)
  for (int i = 0; i < threadNum; i++) {
    process_compute_Matrix_AxorD(infoArgs.data() + i);
  }
  // printf("*************** sleep 10s ************\n");
  // sleep(10);
  // printf("*************** sleep 10s end ************\n");
  //   printf("[cm20.cpp] ====== 并行计算矩阵 AxorD 结束,threadNum(%d)
  //   ======\n",
  //          threadNum);
  //   printf("[cm20.cpp] 计算 Hash1 之后,并行生成矩阵 A,D 用时:%ldms\n",
  //          get_use_time(start0));
  /*********for cycle end*********/
  // 将uBuff输出并发送给对方
  //   *sendMatrixADBuff = this->sendMatrixADBuff.data();
  //   *sendMatixADBuffSize = this->heightInBytes * this->matrixWidth;
  sock->send(string((char *)this->sendMatrixADBuff.data(),
                    this->heightInBytes * this->matrixWidth));
  /****************************/
  return 0;
}

// 并行处理，并行生成hashMap,参数结构体类型
typedef struct HashMapParallelInfo {
  int threadId;
  u64 startIndex;
  u64 processNum;
  u64 receiverSize;
  u64 matrixWidth;
  u64 matrixWidthInBytes;
  u64 hash2LengthInBytes;
  u64 bucket2ForComputeH2Output;
  vector<u8> *transHashInputsPtr;
  unordered_map<u64, std::vector<std::pair<block, u32>>> *hashMap;
} HashMapParallelInfo;
// 并行生成hashmap 处理函数
void process_for_hash_map(HashMapParallelInfo *infoArg) {
  // printf("  tid:%d,startIndex:%ld\n", infoArg->threadId,
  // infoArg->startIndex); printf("  tid:%d,processNum:%ld\n",
  // infoArg->threadId, infoArg->processNum); printf("
  // tid:%d,receiverSize:%ld\n", infoArg->threadId, infoArg->receiverSize);
  // printf("  tid:%d,bucket2ForComputeH2Output:%ld\n", infoArg->threadId,
  // infoArg->bucket2ForComputeH2Output);
  //   printf("[cm20.cpp] (process_for_hash_map) thread id:%d\n",
  //   infoArg->threadId);
  // RandomOracle H(infoArg->hash2LengthInBytes);
  // u8 hashOutput[sizeof(block)];
  auto ro = (*hasher_map_ptr)["sha256"]();
  //   ROracle ro;
  char hashOutput[32];
  // 这种写法当 infoArg->bucket2ForComputeH2Output==5000000时coredump
  //  u8 *hashInputs[infoArg->bucket2ForComputeH2Output];
  vector<u8 *> hashInputs(infoArg->bucket2ForComputeH2Output);
  vector<vector<u8>> hashInputsV(infoArg->bucket2ForComputeH2Output);
  for (u64 i = 0; i < infoArg->bucket2ForComputeH2Output; ++i) {
    // hashInputs[i] = new u8[infoArg->matrixWidthInBytes];
    hashInputsV[i].resize(infoArg->matrixWidthInBytes);
    hashInputs[i] = hashInputsV[i].data();
  }
  // 接收集合中的每个元素
  u64 rightIndex = infoArg->startIndex + infoArg->processNum;
  for (u64 low = infoArg->startIndex; low < rightIndex;
       low += infoArg->bucket2ForComputeH2Output) {
    u64 up = low + infoArg->bucket2ForComputeH2Output < rightIndex
                 ? low + infoArg->bucket2ForComputeH2Output
                 : rightIndex;
    for (u64 j = low; j < up; ++j) {
      memset(hashInputs[j - low], 0, infoArg->matrixWidthInBytes);
    }
    for (u64 i = 0; i < infoArg->matrixWidth; ++i) {
      for (u64 j = low; j < up; ++j) {
        hashInputs[j - low][i >> 3] |=
            (u8)((bool)(infoArg->transHashInputsPtr[i][j >> 3] &
                        (1 << (j & 7))))
            << (i & 7);
      }
    }
    for (u64 j = low; j < up; ++j) {
      // if (j == low)
      // {
      //   cout << "   最后计算:" << j << "," << *(block *)hashInputs[j - low]
      //   << endl;
      // }

      ro->hasher_reset();
      ro->hasher_update((char *)hashInputs[j - low],
                        infoArg->matrixWidthInBytes);
      ro->hasher_final(hashOutput, 32);
      // 生成一个map并保存
      //  infoArg->hashMap[0][*(u64 *)hashOutput].push_back(
      //      std::make_pair(*(block *)hashOutput, j));
      infoArg->hashMap[0][*(u64 *)hashOutput].emplace_back(
          std::make_pair(*(block *)hashOutput, j));
    }
  }
}

int cm20_receiver::genenateAllHashesMap() {
  /////////////////// Compute hash outputs ///////////////////////////
  // H2
  // RandomOracle H(this->hash2LengthInBytes);
  // u8 hashOutput[sizeof(block)];
  // u8 *hashInputs[this->bucket2ForComputeH2Output];
  int threadNum = this->threadNumOmp;
  this->HashMapVector.resize(threadNum);
  u64 processLen = this->receiverSize / threadNum;
  u64 remain = this->receiverSize % threadNum;
  HashMapParallelInfo infoArgs[threadNum];
  // 内存初始化为0
  memset(infoArgs, 0, threadNum * sizeof(HashMapParallelInfo));
  // 给每个线程的参数赋值
  for (int i = 0; i < threadNum; i++) {
    infoArgs[i].threadId = i;
    infoArgs[i].startIndex = i * processLen;
    if (i == threadNum - 1) {
      infoArgs[i].processNum = processLen + remain;
    } else {
      infoArgs[i].processNum = processLen;
    }
    infoArgs[i].receiverSize = this->receiverSize;
    infoArgs[i].matrixWidth = this->matrixWidth;
    infoArgs[i].matrixWidthInBytes = this->matrixWidthInBytes;
    infoArgs[i].hash2LengthInBytes = this->hash2LengthInBytes;
    infoArgs[i].bucket2ForComputeH2Output = this->bucket2ForComputeH2Output;
    infoArgs[i].transHashInputsPtr =
        (vector<u8> *)(this->transHashInputs.data());
    infoArgs[i].hashMap =
        (unordered_map<u64, std::vector<std::pair<block, u32>>>
             *)(this->HashMapVector.data() + i);
  }
  // 给每个线程的参数赋值结束
//   printf("[cm20.cpp] 并行计算 hashmap 开始,threadNum(%d)\n", threadNum);
#pragma omp parallel for num_threads(threadNum)
  for (int i = 0; i < threadNum; i++) {
    process_for_hash_map(infoArgs + i);
  }
  return 0;
}

///////////////////////////////////////////////////////////////
// 并行逻辑
// 多线程处理，计算Hash1
typedef struct HashOneInfo {
  int threadId;
  // int h1LengthInBytes;
  u64 processNum;
  block *aesInputStart;
  block *dataSetOutputStart;
  string *dataSetInputStart;
} HashOneInfo;
// 用omp并行指令，加速Hash1的计算，在使用
void process_char_to_block_omp(HashOneInfo *info) {
  char h1Output[32];
  auto ro = (*hasher_map_ptr)["sha256"]();
  //   ROracle ro;
  for (u64 i = 0; i < info->processNum; ++i) {
    // 256个元素
    ro->hasher_reset();
    ro->hasher_update((char *)info->dataSetInputStart[i].data(),
                      info->dataSetInputStart[i].size());
    ro->hasher_final(h1Output, 32);
    info->dataSetOutputStart[i] = *(block *)h1Output;
  }
  // delete[] h1Output;
}

void transform_input_to_block(const vector<string> &dataSetInput,
                              vector<block> &dataSetOutput, int threadNum) {
  // u64 h1LengthInBytesTemp = 16;
  u64 dataSetInputSize = dataSetInput.size();
  // 初始化大小
  dataSetOutput.resize(dataSetInputSize);
  int numTh = threadNum;
  HashOneInfo infoArgs[numTh];
  memset(infoArgs, 0, sizeof(HashOneInfo) * numTh);
  u64 stepLength = dataSetInputSize / numTh;
  u64 remain = dataSetInputSize % numTh;
  for (int i = 0; i < numTh; i++) {
    infoArgs[i].threadId = i;
    if (i == numTh - 1) {
      infoArgs[i].processNum = stepLength + remain;
    } else {
      infoArgs[i].processNum = stepLength;
    }
    infoArgs[i].threadId = i;
    infoArgs[i].dataSetOutputStart = dataSetOutput.data() + i * stepLength;
    infoArgs[i].dataSetInputStart =
        (string *)(dataSetInput.data()) + i * stepLength;
  }
#pragma omp parallel for num_threads(numTh)
  for (int i = 0; i < numTh; i++) {
    process_char_to_block_omp(infoArgs + i);
  }
}
}  // namespace fucrypto