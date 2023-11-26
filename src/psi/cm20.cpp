#include "crypto-protocol/cm20.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/ot_interface.h"
#include "crypto-protocol/hasher.h"
#include "crypto-protocol/utils.h"
#include <bits/stdc++.h>
using namespace std;
using namespace oc;
namespace fucrypto {
// cm20_sender::cm20_sender(){};
cm20_sender::cm20_sender(const string &common_seed, u64 sender_size,
                         int mat_width, int log_height, int omp_num,
                         int h2_len_in_bytes, int bucket2_send_hash) {
  _omp_num = omp_num;
  this->_mat_width = mat_width;
  this->_mat_width_bytes = (this->_mat_width + 7) >> 3;
  this->_common_seed = toBlock((u8 *)common_seed.data());
  this->_log_height = log_height;
  this->_height = 1 << this->_log_height;
  this->_height_bytes = (this->_height + 7) >> 3;  // 除以8
  this->_sender_size = sender_size;
  this->_sender_size_in_bytes = (this->_sender_size + 7) >> 3;
  this->_bucket1 = 256;
  this->_bucket2_send_hash = bucket2_send_hash;  // default 256
  this->_h2_len_in_bytes = h2_len_in_bytes;
  this->_hash_inputs.resize(this->_bucket2_send_hash);
  for (u64 i = 0; i < this->_bucket2_send_hash; i++) {
    this->_hash_inputs[i].resize(this->_mat_width_bytes);
  }
  this->_trans_hash_inputs.resize(this->_mat_width);
  for (u64 i = 0; i < this->_mat_width; i++) {
    this->_trans_hash_inputs[i].resize(this->_sender_size_in_bytes);
    memset(this->_trans_hash_inputs[i].data(), 0, this->_sender_size_in_bytes);
  }
  this->_low_left = (u64)0;
  SPDLOG_LOGGER_INFO(
      spdlog::default_logger(),
      "cm20_sender,w:{},log_h:{},h2_length:{},_bucket2_send_hash:{}",
      _mat_width, _log_height, _h2_len_in_bytes, _bucket2_send_hash);
};
int cm20_sender::set_base_ot(const oc::BitVector &choice_ote,
                             const vector<oc::block> &m_gens) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "cm20_sender,set_base_ot");
  if (choice_ote.size() != _mat_width || m_gens.size() != _mat_width)
    return err_code_cm20;
  _choice_ote = choice_ote;
  _m_gens = m_gens;
  _has_base_ot = true;
  return 0;
}
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
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_sender,(process_recover_matrix_C) thread id:{}",
                     infoArg->threadId);
  int cycTimes = 0;
  u64 widthBucket1 = infoArg->widthBucket1;
  u64 bucket1 = infoArg->bucket1;
  u64 senderSize = infoArg->senderSize;
  u64 heightInBytes = infoArg->heightInBytes;
  u64 locationInBytes = infoArg->locationInBytes;
  vector<block> randomLocations(bucket1);
  vector<u8 *> matrixC(widthBucket1);
  vector<vector<u8>> matC(widthBucket1);
  for (u64 i = 0; i < widthBucket1; ++i) {
    // 256*1+4，每个元素为u8*，下面语句为创建一个u8*,260个u8
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
          auto location = (*(u32 *)((u8 *)(randomLocations.data() + (j - low)) +
                                    i * locationInBytes)) &
                          (infoArg->shift);
          infoArg->transHashInputsPtr[i + wLeft][j >> 3] |=
              (u8)((bool)(matrixC[i][location >> 3] & (1 << (location & 7))))
              << (j & 7);
        }
      }
    }
  }
}

int cm20_sender::recover_matrix_c(conn *sock, vector<block> &senderSet) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_sender,recover_matrix_c begin ...");
  string err_info = "error";
  scope_guard err_on_exit([&]() {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "cm20_sender,err_info:{}",
                        err_info);
    sock->close();
  });
  if (_has_base_ot == false) {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                       "cm20_sender,_has_base_ot == false");
    PRNG rng(oc::sysRandomSeed());
    this->_choice_ote.resize(this->_mat_width);
    this->_choice_ote.randomize(rng);
    config_param param;
    auto ote = new_ote_receiver(param);
    if (ote == nullptr) {
      err_info = "ote is nullptr error";
      return err_code_cm20;
    }
    int fg = ote->receive(this->_choice_ote, this->_m_gens, sock);
    if (fg) {
      err_info = "ote->receive error";
      return err_code_cm20;
    }
  } else {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                       "cm20_sender,_has_base_ot == true");
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_sender,receive matrix_a_d_recv before");
  string matrix_a_d_recv = sock->recv();
  if (matrix_a_d_recv.empty()) {
    err_info = "matrix_a_d_recv is null error";
    return err_code_cm20;
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_sender,receive matrix_a_d_recv end");
  u8 *recvMatrixADBuff = (u8 *)matrix_a_d_recv.data();
  u64 recvMatixADBuffSize = matrix_a_d_recv.size();
  auto locationInBytes = (this->_log_height + 7) / 8;   // logHeight==1
  auto widthBucket1 = sizeof(block) / locationInBytes;  // 16/1
  u64 shift = (1 << this->_log_height) - 1;             // 全1
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_sender,widthBucket1:{},:{}", widthBucket1,
                     locationInBytes);
  if (recvMatixADBuffSize != this->_mat_width * this->_height_bytes) {
    return err_code_cm20;
  }

  int omp_num = _omp_num;
  u64 sumCount = 0;
  int isExit = 0;

  vector<RecoverMatrixCInfo> infoArgs(omp_num);
  memset(infoArgs.data(), 0, omp_num * sizeof(RecoverMatrixCInfo));
  // 对每个线程进行分配处理的矩阵的列数
  for (;;) {
    for (int k = 0; k < omp_num; k++) {
      u64 wRight = sumCount + widthBucket1;
      if (wRight <= this->_mat_width) {
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
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_sender, omp 处理,sumCount:{}", sumCount);
  // 不要漏掉余数
  if ((this->_mat_width - sumCount) != 0) {
    infoArgs[omp_num - 1].processNum += this->_mat_width - sumCount;
    infoArgs[omp_num - 1].aesKeyNum += 1;
  }
  for (int i = 0; i < omp_num; i++) {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                       "cm20_sender, procesNum[{}]:{}", i,
                       infoArgs[i].processNum);
  }

  for (int i = 0; i < omp_num; i++) {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                       "cm20_sender, aesKeyNum[{}]:{}", i,
                       infoArgs[i].aesKeyNum);
  }
  // 分配处理的矩阵的列数结束
  // 最重要的一步，生成 Fk 函数的 keys
  PRNG commonPrng(this->_common_seed);
  vector<block> commonKeys;
  for (u64 wLeft = 0; wLeft < this->_mat_width; wLeft += widthBucket1) {
    block comKey = commonPrng.get<block>();
    commonKeys.emplace_back(comKey);
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "cm20_sender,commonKeys size:{}",
                     commonKeys.size());
  // 最重要的一步，取出 _choice_ote
  u64 choiceSize = this->_choice_ote.size();
  vector<int> choiceVector;
  for (u64 i = 0; i < choiceSize; i++) {
    choiceVector.emplace_back(this->_choice_ote[i]);
  }
  // 给参数赋值
  for (int k = 0; k < omp_num; k++) {
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
    infoArgs[k].senderSize = this->_sender_size;
    // 8
    infoArgs[k].heightInBytes = this->_height_bytes;
    // 9
    infoArgs[k].locationInBytes = locationInBytes;
    // 10
    infoArgs[k].bucket1 = this->_bucket1;
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
        this->_m_gens.data() + infoArgs[k].wLeftBegin;
    // 14
    infoArgs[k].choicesWidthInputPtr =
        choiceVector.data() + infoArgs[k].wLeftBegin;  // todo
    // 15
    infoArgs[k].recvMatrixADBuffBegin =
        recvMatrixADBuff + infoArgs[k].wLeftBegin * this->_height_bytes;
    // 16
    infoArgs[k].transHashInputsPtr =
        (vector<u8> *)(this->_trans_hash_inputs.data()) +
        infoArgs[k].wLeftBegin;
  }

  for (int i = 0; i < omp_num; i++) {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "cm20_sender,aesBegin[{}]:{}",
                       i, infoArgs[i].aesComkeysBegin);
  }
  for (int j = 0; j < omp_num; j++) {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "cm20_sender,wlfBegin[{}]:{}",
                       j, infoArgs[j].wLeftBegin);
  }

#pragma omp parallel for num_threads(threadNum)
  for (int i = 0; i < omp_num; i++) {
    process_recover_matrix_C(infoArgs.data() + i);
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_sender,并行处理恢复矩阵 C 结束 omp_num:{}", omp_num);
  err_on_exit.dismiss();
  return 0;
}
int cm20_sender::send_hash2_output(conn *sock) {
  string hashOutputBuff(_h2_len_in_bytes * _bucket2_send_hash, '\0');
  int count = 0;
  for (;;) {
    if (this->_low_left >= this->_sender_size) break;
    count++;
    auto upR = this->_low_left + this->_bucket2_send_hash < this->_sender_size
                   ? this->_low_left + this->_bucket2_send_hash
                   : this->_sender_size;
    //   ROracle ro;
    // auto ro = (*hasher_map_ptr)["sha256"]();
    auto ro = new_hasher(_conf);
    char hashOutput[32];
    for (auto j = this->_low_left; j < upR; ++j) {
      memset(this->_hash_inputs[j - this->_low_left].data(), 0,
             this->_mat_width_bytes);
    }
    for (u64 i = 0; i < this->_mat_width; ++i) {
      for (u64 j = this->_low_left; j < upR; ++j) {
        this->_hash_inputs[j - this->_low_left][i >> 3] |=
            (u8)((bool)(this->_trans_hash_inputs[i][j >> 3] & (1 << (j & 7))))
            << (i & 7);
      }
    }
    u64 offset = 0;
    for (u64 j = this->_low_left; j < upR;
         ++j, offset += this->_h2_len_in_bytes) {
      ro->hasher_reset();
      ro->hasher_update((char *)this->_hash_inputs[j - this->_low_left].data(),
                        this->_mat_width_bytes);
      ro->hasher_final(hashOutput, 32);
      memcpy((char *)(hashOutputBuff.data() + offset), hashOutput,
             this->_h2_len_in_bytes);
    }
    if (count != get_count()) {
      sock->send(hashOutputBuff);
    } else {
      sock->send(string((char *)hashOutputBuff.data(),
                        (upR - this->_low_left) * this->_h2_len_in_bytes));
    }
    this->_low_left += this->_bucket2_send_hash;
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     ">> cm20_sender send hash count:{}", count);
  return 0;
}
///////////////////////////////////////////////////////////////

cm20_receiver::~cm20_receiver() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "~cm20_receiver free");
}
// cm20_receiver::cm20_receiver() {}
cm20_receiver::cm20_receiver(const string &common_seed, u64 recver_size,
                             u64 sender_size, int mat_width, int log_height,
                             int omp_num, int h2_len_in_bytes,
                             int bucket2_send_hash) {
  this->_omp_num = omp_num;
  this->_mat_width = mat_width;
  this->_mat_width_bytes = (_mat_width + 7) >> 3;
  this->_recver_size = recver_size;
  this->_sender_size = sender_size;
  this->_recver_size_in_bytes = (_recver_size + 7) >> 3;
  this->_log_height = log_height;
  this->_height = 1 << this->_log_height;
  //   除以8
  this->_height_bytes = (this->_height + 7) >> 3;
  this->_bucket1 = 256;
  this->_bucket2_send_hash = bucket2_send_hash;  // default 256
  this->_h2_len_in_bytes = h2_len_in_bytes;
  this->_trans_hash_inputs.resize(this->_mat_width);
  for (u64 i = 0; i < this->_mat_width; ++i) {
    this->_trans_hash_inputs[i].resize(this->_recver_size_in_bytes);
    memset(this->_trans_hash_inputs[i].data(), 0, this->_recver_size_in_bytes);
  }
  this->_common_seed = toBlock((u8 *)common_seed.data());
  this->_low_left = (u64)0;
  this->_index_id = 0;
  this->_psi_compute_pool = new (std::nothrow) ThreadPool(this->_omp_num);
  if (this->_psi_compute_pool == nullptr) {
    return;
  }
  this->_psi_results.resize(this->_sender_size / this->_bucket2_send_hash + 2);
  this->_psi_result_pir.resize(this->_sender_size / this->_bucket2_send_hash +
                               2);
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
int cm20_receiver::set_base_ot(const vector<array<block, 2>> &m_gens_pair) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_receiver,set_base_ot start ...");
  if (m_gens_pair.size() != _mat_width) return err_code_cm20;
  _m_gens_pair = m_gens_pair;
  _has_base_ot = true;
  return 0;
}
int cm20_receiver::gen_matrix_u_a_d(conn *sock, vector<block> &receiverSet) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_receiver,gen_matrix_u_a_d start ...");
  string err_info = "error";
  scope_guard err_on_exit([&]() {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "cm20_receiver,err_info:{}",
                        err_info);
    sock->close();
  });
  if (_has_base_ot == false) {
    this->_m_gens_pair.resize(this->_mat_width);
    config_param param;
    auto ote = new_ote_sender(param);
    if (!ote) {
      err_info = "ote is null error";
      return err_code_cm20;
    }
    int fg = ote->send(this->_m_gens_pair, sock);
    if (fg) {
      err_info = "ote->send error";
      return err_code_cm20;
    }
    SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                       "cm20_receiver,_has_base_ot == false");
  } else {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                       "cm20_receiver,_has_base_ot == true");
  }
  u64 locationInBytes = (this->_log_height + 7) >> 3;
  u64 widthBucket1 = sizeof(block) / locationInBytes;
  u64 shift = (1 << this->_log_height) - 1;  // 全1

  if (receiverSet.size() != this->_recver_size) {
    return err_code_cm20;
  }

  // 并行计算矩阵AxorD
  int threadNum = this->_omp_num;
  int sumCount = 0;
  int isExit = 0;
  vector<ComputeMatrixAxorDInfo> infoArgs(threadNum);
  // 将全部内存初始为 0
  memset(infoArgs.data(), 0, sizeof(ComputeMatrixAxorDInfo) * threadNum);
  // 为每一个线程生成参数数据,主要是处理的矩阵的列数
  for (;;) {
    for (int k = 0; k < threadNum; k++) {
      u64 wRight = sumCount + widthBucket1;
      if (wRight <= this->_mat_width) {
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

  // 不要漏掉余数
  if ((this->_mat_width - sumCount) != 0) {
    infoArgs[threadNum - 1].processNum += this->_mat_width - sumCount;
    infoArgs[threadNum - 1].aesKeyNum += 1;
  }
  for (int i = 0; i < threadNum; i++) {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                       "cm20_receiver,procesNum[{}]:={}", i,
                       infoArgs[i].processNum);
  }

  for (int i = 0; i < threadNum; i++) {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                       "cm20_receiver,aesKeyNum[{}]:={}", i,
                       infoArgs[i].aesKeyNum);
  }
  // 分配处理的矩阵的列数结束
  // 最重要的一步，生成 Fk 函数的 keys
  vector<block> commonKeys;
  PRNG commonPrng(this->_common_seed);
  for (u64 wLeft = 0; wLeft < this->_mat_width; wLeft += widthBucket1) {
    block comKey = commonPrng.get<block>();
    commonKeys.emplace_back(comKey);
  }

  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_receiver,commonKeys size={}", commonKeys.size());
  string sendMatrixADBuff(this->_height_bytes * this->_mat_width, '\0');
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
    infoArgs[k].receiverSize = this->_recver_size;
    // 8
    infoArgs[k].heightInBytes = this->_height_bytes;
    // 9
    infoArgs[k].locationInBytes = locationInBytes;
    // 10
    infoArgs[k].bucket1 = this->_bucket1;
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
        (array<block, 2> *)(this->_m_gens_pair.data()) + infoArgs[k].wLeftBegin;
    // 16
    infoArgs[k].transHashInputsPtr =
        (vector<u8> *)(this->_trans_hash_inputs.data()) +
        infoArgs[k].wLeftBegin;
    // 17
    infoArgs[k].sendMatrixADBuffPtr =
        (u8 *)(sendMatrixADBuff.data()) +
        (infoArgs[k].wLeftBegin) * (this->_height_bytes);
  }
  for (int i = 0; i < threadNum; i++) {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                       "cm20_receiver,aesBegin[{}]:={}", i,
                       infoArgs[i].aesComkeysBegin);
  }

  for (int j = 0; j < threadNum; j++) {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                       "cm20_receiver,wlfBegin[{}]:={}", j,
                       infoArgs[j].wLeftBegin);
  }

#pragma omp parallel for num_threads(threadNum)
  for (int i = 0; i < threadNum; i++) {
    process_compute_Matrix_AxorD(infoArgs.data() + i);
  }
  sock->send(sendMatrixADBuff);
  int fg = gen_hash_map();
  if (fg) {
    err_info = "gen_hash_map error";
    return fg;
  }
  err_on_exit.dismiss();
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
  config_param param;
} HashMapParallelInfo;
// 并行生成hashmap 处理函数
void process_for_hash_map(HashMapParallelInfo *infoArg) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_receiver,process_for_hash_map");
  //   auto ro = (*hasher_map_ptr)["sha256"]();
  auto ro = new_hasher(infoArg->param);

  char hashOutput[32];

  vector<u8 *> hashInputs(infoArg->bucket2ForComputeH2Output);
  vector<vector<u8>> hashInputsV(infoArg->bucket2ForComputeH2Output);
  for (u64 i = 0; i < infoArg->bucket2ForComputeH2Output; ++i) {
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

int cm20_receiver::gen_hash_map() {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(), "cm20_receiver,gen_hash_map");
  int threadNum = this->_omp_num;
  this->_hash_map_vector.resize(threadNum);
  u64 processLen = this->_recver_size / threadNum;
  u64 remain = this->_recver_size % threadNum;
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
    infoArgs[i].receiverSize = this->_recver_size;
    infoArgs[i].matrixWidth = this->_mat_width;
    infoArgs[i].matrixWidthInBytes = this->_mat_width_bytes;
    infoArgs[i].hash2LengthInBytes = this->_h2_len_in_bytes;
    infoArgs[i].bucket2ForComputeH2Output = this->_bucket2_send_hash;
    infoArgs[i].transHashInputsPtr =
        (vector<u8> *)(this->_trans_hash_inputs.data());
    infoArgs[i].hashMap =
        (unordered_map<u64, std::vector<std::pair<block, u32>>>
             *)(this->_hash_map_vector.data() + i);
  }
  // 给每个线程的参数赋值结束
#pragma omp parallel for num_threads(threadNum)
  for (int i = 0; i < threadNum; i++) {
    process_for_hash_map(infoArgs + i);
  }
  return 0;
}
typedef struct ThreadPoolInfo {
  u8 *recvBuff;
  u64 recvBufSize;
  u64 hash2LengthInBytes;
  u64 lowL;
  u64 up;
  unordered_map<u64, std::vector<std::pair<block, u32>>> *HashMapVectorPtr;
  int hashMapSize;
  u32 psiResultId;
  vector<u32> *psiResult;
  vector<vector<u32>> *psiResultPirQuery;  // 匿踪查询用的结构
} ThreadPoolInfo;
u32 process_compute_psi_by_threadpool(ThreadPoolInfo *infoArg) {
  u64 offset = 0;
  for (u64 idx = 0; idx < infoArg->up - infoArg->lowL;
       ++idx, offset += infoArg->hash2LengthInBytes) {
    u64 mapIdx = *(u64 *)(infoArg->recvBuff + offset);
    // 这里加omp指令并不能提高性能，反而下降一倍多
    for (int i = 0; i < infoArg->hashMapSize; i++) {
      auto found = infoArg->HashMapVectorPtr[i].find(mapIdx);
      if (found == infoArg->HashMapVectorPtr[i].end()) continue;
      // 可能找到好几个
      for (size_t j = 0; j < found->second.size(); ++j) {
        if (memcmp(&(found->second[j].first), infoArg->recvBuff + offset,
                   infoArg->hash2LengthInBytes) == 0) {
          // psiMsgIndex->push_back(found->second[j].second);

          infoArg->psiResult[0].emplace_back(found->second[j].second);

          break;
        }
      }
    }
  }
  u32 psiResultId = infoArg->psiResultId;
  // free内存
  //  free(infoArg->recvBuff);
  delete[] infoArg->recvBuff;
  infoArg->recvBuff = nullptr;
  // free(infoArg);
  delete infoArg;
  infoArg = nullptr;
  return psiResultId;
}

u32 process_compute_psi_by_threadpool_pir(ThreadPoolInfo *infoArg) {
  // u64 recvBufSize = infoArg->recvBufSize;
  // vector<u32_t> *psiResult = infoArg->psiResult;
  u64 offset = 0;
  for (u64 idx = 0; idx < infoArg->up - infoArg->lowL;
       ++idx, offset += infoArg->hash2LengthInBytes) {
    // 记录对方的id的索引号
    u32 sender_id_index = infoArg->lowL + idx;
    // 记录对方的id的索引号

    u64 mapIdx = *(u64 *)(infoArg->recvBuff + offset);
    // 这里加omp指令并不能提高性能，反而下降一倍多
    for (int i = 0; i < infoArg->hashMapSize; i++) {
      auto found = infoArg->HashMapVectorPtr[i].find(mapIdx);
      if (found == infoArg->HashMapVectorPtr[i].end()) continue;
      // 可能找到好几个
      for (size_t j = 0; j < found->second.size(); ++j) {
        if (memcmp(&(found->second[j].first), infoArg->recvBuff + offset,
                   infoArg->hash2LengthInBytes) == 0) {
          // psiMsgIndex->push_back(found->second[j].second);

          vector<u32> recv_index_send_index;
          recv_index_send_index.emplace_back(found->second[j].second);
          recv_index_send_index.emplace_back(sender_id_index);
          // printf("   sender_id_index:%d\n", sender_id_index);
          // printf("   recv_index_send_index[0]:%d\n",
          // recv_index_send_index[0]); printf(" recv_index_send_index[1]:%d\n",
          // recv_index_send_index[1]);
          infoArg->psiResultPirQuery[0].emplace_back(recv_index_send_index);
          break;
        }
      }
    }
  }
  u32 psiResultId = infoArg->psiResultId;
  // free内存
  //  free(infoArg->recvBuff);
  delete[] infoArg->recvBuff;
  infoArg->recvBuff = nullptr;
  // free(infoArg);
  delete infoArg;
  infoArg = nullptr;
  return psiResultId;
}

int cm20_receiver::recv_hash2_output(conn *sock) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_receiver,recv_hash2_output start ...");
  string err_info = "error";
  scope_guard err_on_exit([&]() {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(),
                        "cm20_receiver,recv_hash2_output err_info:{}");
    sock->close();
  });
  int count = 0;
  for (;;) {
    if (this->_low_left >= this->_sender_size) break;
    string recvBuff = sock->recv();
    if (recvBuff.empty()) {
      err_info = "recv h2 data error";
      return err_code_cm20;
    }
    count++;
    auto up = this->_low_left + this->_bucket2_send_hash < this->_sender_size
                  ? this->_low_left + this->_bucket2_send_hash
                  : this->_sender_size;
    uint32_t recvBufSize = recvBuff.size();
    if (recvBufSize != (up - this->_low_left) * this->_h2_len_in_bytes) {
      return -122;
    }
    ThreadPoolInfo *infoArg = new (std::nothrow) ThreadPoolInfo;
    if (infoArg == nullptr) {
      return err_code_cm20;
    }

    memset(infoArg, 0, sizeof(ThreadPoolInfo));
    // 赋值
    //  infoArg->recvBuff = (u8_t *)malloc(recvBufSize);
    infoArg->recvBuff = new (std::nothrow) u8[recvBufSize];
    if (infoArg->recvBuff == nullptr) {
      return -8;
    }
    memcpy(infoArg->recvBuff, recvBuff.data(), recvBufSize);
    infoArg->recvBufSize = recvBufSize;
    infoArg->hash2LengthInBytes = this->_h2_len_in_bytes;
    infoArg->lowL = this->_low_left;
    infoArg->up = up;
    infoArg->HashMapVectorPtr = this->_hash_map_vector.data();
    infoArg->hashMapSize = this->_hash_map_vector.size();
    infoArg->psiResultId = this->_index_id;

    infoArg->psiResult =
        (vector<u32> *)(this->_psi_results.data()) + this->_index_id;

    // 赋值 end
    this->_psi_result_index.emplace_back(this->_psi_compute_pool->enqueue(
        process_compute_psi_by_threadpool, infoArg));
    this->_low_left += this->_bucket2_send_hash;
    this->_index_id++;
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     ">> cm20_receiver recv hash count:{}", count);
  err_on_exit.dismiss();
  return 0;
}

int cm20_receiver::recv_hash2_output_pir(conn *sock) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_receiver,recv_hash2_output_pir start ...");
  string err_info = "error";
  scope_guard err_on_exit([&]() {
    SPDLOG_LOGGER_ERROR(spdlog::default_logger(),
                        "cm20_receiver,recv_hash2_output_pir err_info:{}");
    sock->close();
  });
  int count = 0;
  for (;;) {
    if (this->_low_left >= this->_sender_size) break;
    string recvBuff = sock->recv();
    if (recvBuff.empty()) {
      err_info = "recv h2 data pir error";
      return err_code_cm20;
    }
    count++;
    auto up = this->_low_left + this->_bucket2_send_hash < this->_sender_size
                  ? this->_low_left + this->_bucket2_send_hash
                  : this->_sender_size;
    uint32_t recvBufSize = recvBuff.size();
    if (recvBufSize != (up - this->_low_left) * this->_h2_len_in_bytes) {
      return -122;
    }

    ThreadPoolInfo *infoArg = new (std::nothrow) ThreadPoolInfo;
    if (infoArg == nullptr) {
      return -8;
    }

    memset(infoArg, 0, sizeof(ThreadPoolInfo));
    // 赋值
    infoArg->recvBuff = new (std::nothrow) u8[recvBufSize];
    if (infoArg->recvBuff == nullptr) {
      return -8;
    }
    memcpy(infoArg->recvBuff, recvBuff.data(), recvBufSize);
    infoArg->recvBufSize = recvBufSize;
    infoArg->hash2LengthInBytes = this->_h2_len_in_bytes;
    infoArg->lowL = this->_low_left;
    infoArg->up = up;
    infoArg->HashMapVectorPtr = this->_hash_map_vector.data();
    infoArg->hashMapSize = this->_hash_map_vector.size();
    infoArg->psiResultId = this->_index_id;

    infoArg->psiResultPirQuery =
        (vector<vector<u32>> *)(this->_psi_result_pir.data()) + this->_index_id;

    // 赋值 end
    this->_psi_result_index.emplace_back(this->_psi_compute_pool->enqueue(
        process_compute_psi_by_threadpool_pir, infoArg));
    this->_low_left += this->_bucket2_send_hash;
    this->_index_id++;
  }
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     ">> cm20_receiver recv hash count:{}", count);
  err_on_exit.dismiss();
  return 0;
}

int cm20_receiver::get_psi_results(vector<u32> &psiResultsOutput) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_receiver,get_psi_results start ...");
  u64 psiResultsSize = this->_psi_result_index.size();
  for (u64 i = 0; i < psiResultsSize; i++) {
    u32 resultIndex = (this->_psi_result_index)[i].get();
    for (size_t j = 0; j < this->_psi_results[resultIndex].size(); j++) {
      psiResultsOutput.emplace_back(this->_psi_results[resultIndex][j]);
    }
  }
  return 0;
}

int cm20_receiver::get_psi_results_pir(vector<vector<u32>> &psiResultsOutput) {
  SPDLOG_LOGGER_INFO(spdlog::default_logger(),
                     "cm20_receiver,get_psi_results_pir start ...");
  u64 psiResultsSize = this->_psi_result_index.size();
  for (u64 i = 0; i < psiResultsSize; i++) {
    u32 resultIndex = (this->_psi_result_index)[i].get();
    for (int j = 0; j < this->_psi_result_pir[resultIndex].size(); j++) {
      psiResultsOutput.emplace_back(this->_psi_result_pir[resultIndex][j]);
    }
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
  config_param param;
} HashOneInfo;
// 用omp并行指令，加速Hash1的计算，在使用
void process_char_to_block_omp(HashOneInfo *info) {
  char h1Output[32];
  //   auto ro = (*hasher_map_ptr)["sha256"]();
  auto ro = new_hasher(info->param);
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