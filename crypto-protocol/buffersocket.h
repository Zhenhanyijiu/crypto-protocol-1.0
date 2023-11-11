#ifndef __FU_BUFFER_SOCKET_H__
#define __FU_BUFFER_SOCKET_H__
#include "crypto-protocol/syncsave.h"
#include "crypto-protocol/fusocket.h"
namespace fucrypto {

class buffersocket : public conn {
 private:
  shared_queue<std::string> _send_buf;
  shared_queue<std::string> _recv_buf;
  int _role;

 public:
  buffersocket();
  buffersocket(const buffersocket& buffsock);
  ~buffersocket();
  int send(const std::string data);
  std::string recv();
  int close();
  std::string get_msg();
  void set_msg(std::string data);
  bool has_msg();
};

}  // namespace fucrypto
#endif