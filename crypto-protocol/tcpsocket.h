#ifndef __FU_TCP_SOCKET_H__
#define __FU_TCP_SOCKET_H__
#include "crypto-protocol/fusocket.h"
// #include <bits/stdc++.h>
// #if defined(__cplusplus) || defined(c_plusplus)
// extern "C" {
// #endif

namespace fucrypto {

typedef enum { CLIENT, SERVER } RoleType;

class connection : public conn {
 private:
  void *_conn = nullptr;

 public:
  connection() = delete;
  connection(int role, const std::string ip_addr, int port);
  ~connection();
  int send(const std::string data);
  std::string recv();
  int close();
};
void main_test_channel(int argc, char **argv);
}  // namespace fucrypto

// #if defined(__cplusplus) || defined(c_plusplus)
// }
// #endif
#endif