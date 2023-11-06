#ifndef __FU_SOCKET_INTERFACE_H__
#define __FU_SOCKET_INTERFACE_H__
#include <string>
// #if defined(__cplusplus) || defined(c_plusplus)
// extern "C" {
// #endif
namespace fucrypto {
class conn {
 public:
  uint64_t _recv_bytes_count = 0;
  uint64_t _send_bytes_count = 0;

 public:
  conn(){};
  virtual ~conn(){};
  virtual int send(const std::string data) = 0;
  virtual std::string recv() = 0;
  virtual int close() = 0;
  uint64_t recv_bytes_count() { return _recv_bytes_count; };
  uint64_t send_bytes_count() { return _send_bytes_count; };
};
// class Conn {
//  private:
//  public:
//   virtual ~Conn(){};
//   virtual int send(const std::string& data) = 0;
//   virtual int recv(std::string& data) = 0;
//   virtual int closeerr() = 0;
//   virtual int closenormal() = 0;
//   virtual std::string getuid() = 0;
// };
}  // namespace fucrypto

// #if defined(__cplusplus) || defined(c_plusplus)
// }
// #endif
#endif
