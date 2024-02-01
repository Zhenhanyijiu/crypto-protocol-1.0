#ifndef __FU_OT_INTER_FACE_H__
#define __FU_OT_INTER_FACE_H__
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/BitVector.h>
#include <bits/stdc++.h>
#include "crypto-protocol/fusocket.h"
#include "crypto-protocol/config.h"
// using namespace oc;
// using namespace std;
namespace fucrypto {
//   "secp256k1",
//   "prime256v1",
//   "secp384r1",
// struct config_param {
//   std::string ecc_lib_name = "openssl";
//   std::string curve_name = "secp256k1";
//   std::string ot_name = "np99";
//   std::string ote_name = "iknp";
//   std::string ot_n_1_name = "kkrt";
//   std::string hasher_name = "sha256";
// };
extern config_param default_config_param;
class ot_sender {
 public:
  ot_sender(){};
  //   otsender(const config_param& param){};
  virtual ~ot_sender(){};
  virtual int send(std::vector<std::array<oc::block, 2>>& pair_keys,
                   conn* sock) = 0;
};
class ot_receiver {
 private:
 public:
  ot_receiver(){};
  virtual ~ot_receiver(){};
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

// class OTFactory {
//  private:
//  public:
//   OTFactory();
//   ~OTFactory();
//   template <typename T, typename T1>
//   std::unique_ptr<T> new_ot_sender(const config_param& param) {
//     return std::make_unique<T1>(param);
//   }
//   template <typename T, typename T1>
//   std::unique_ptr<T> new_ot_receiver(const config_param& param) {
//     return std::make_unique<T1>(param);
//   }
// };

// extern OTFactory* ot_factory_ptr;
// BASE OT
extern std::unique_ptr<ot_sender> new_base_ot_sender(const config_param& param);
extern std::unique_ptr<ot_receiver> new_base_ot_receiver(
    const config_param& param);

// BASE OTE
extern std::unique_ptr<ote_sender> new_ote_sender(const config_param& param);
extern std::unique_ptr<ote_receiver> new_ote_receiver(
    const config_param& param);

// 1ooN KKRT
// extern std::unique_ptr<> new_ote_sender(const config_param& param);
// extern std::unique_ptr<ote_receiver> new_ote_receiver(
//     const config_param& param);

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
template <typename T>
T get_mask_l(int bit_l) {
  return bit_l == sizeof(T) * 8 ? -1 : (T(1) << bit_l) - 1;
}

/// @brief N选1 OT 包括1oo2-ot 发送真实数据的模板函数
/// @tparam T: 要发送的数据的存储类型
/// @param sock: 通信对象
/// @param data: 要发送的数据
/// @param N: N选1的 N
/// @param bit_l: 发送数据的有效bit长度
/// @param mask_keys: 可以认为是一次性教秘密钥数组
/// @return
template <typename T>
int ot_send(conn* sock, const std::vector<std::vector<T>>& data, int N,
            int bit_l, const std::vector<std::vector<oc::block>>& mask_keys) {
  assert(N > 1);
  assert(bit_l > 0);
  assert(bit_l <= sizeof(T) * 8);
  assert(data.size() == mask_keys.size());
  int num_otext = data.size();
  std::stringstream ssbuff;
  int min_num = (N * bit_l + 7) / 8;
  //   std::cout << "=== min_num:" << min_num << std::endl;
  uint8_t tmp[min_num];
  T mask = get_mask_l<T>(bit_l);
  for (size_t i = 0; i < num_otext; i++) {
    memset(tmp, 0, min_num);
    for (size_t j = 0; j < N; j++) {
      T key = (*(T*)&mask_keys[i][j]) & mask;
      T x = data[i][j] ^ key;
      int bit_pos = j * bit_l, shift = 0;
      for (size_t k = bit_pos; k < bit_pos + bit_l; k++, shift++) {
        int byte_index = k / 8, bit_index = k % 8;
        tmp[byte_index] |= ((x >> shift) & 0x1) << bit_index;
      }
    }
    ssbuff << std::string((char*)tmp, min_num);
  }
  sock->send(ssbuff.str());
  //   std::cout << "recv mask:" << (uint64_t)mask << std::endl;
  return 0;
}

/// @brief N选1 OT 包括1oo2-ot 接收真实数据的模板函数
/// @tparam T: 要接收的数据的存储类型
/// @param sock: 通信对象
/// @param r_i: 要选择的数据的在对方的索引
/// @param N: N选1的 N
/// @param bit_l: 要接收的数据的有效bit长度
/// @param mask_keys: 可以认为是一次性解密密钥
/// @param out_data: 要接收的数据
/// @return
template <typename T>
int ot_recv(conn* sock, const std::vector<int>& r_i, int N, int bit_l,
            const std::vector<oc::block>& mask_keys, std::vector<T>& out_data) {
  assert(N > 1);
  assert(bit_l > 0);
  assert(bit_l <= sizeof(T) * 8);
  assert(r_i.size() == mask_keys.size());
  int num_otext = r_i.size();
  out_data.resize(num_otext, 0ll);
  std::string buff = sock->recv();
  if (buff.empty()) return -1;
  int min_num = (N * bit_l + 7) / 8;
  uint8_t tmp[min_num];
  T mask = get_mask_l<T>(bit_l);
  int offset = 0;
  for (size_t i = 0; i < num_otext; i++, offset += min_num) {
    memcpy(tmp, buff.data() + offset, min_num);
    T key = (*(T*)&mask_keys[i]) & mask;
    int bit_pos = r_i[i] * bit_l, shift = 0;
    int byte_index = 0, bit_index = 0;
    for (size_t k = bit_pos; k < bit_pos + bit_l; k++, shift++) {
      byte_index = k / 8, bit_index = k % 8;
      out_data[i] |= T((tmp[byte_index] >> bit_index) & 0x1) << shift;
    }
    out_data[i] ^= key;
  }
  return 0;
}

}  // namespace fucrypto
#endif