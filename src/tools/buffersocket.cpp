#include "crypto-protocol/buffersocket.h"
namespace fucrypto {
using namespace std;
buffersocket::buffersocket() {}
buffersocket::buffersocket(const buffersocket& buffsock) {}
buffersocket::~buffersocket() {
  cout << "buffersocket::~buffersocket 析构" << endl;
}
int buffersocket::send(string data) {
  _send_buf.push_back(data);
  return 0;
}
string buffersocket::recv() { return _recv_buf.pop(); }
string buffersocket::get_msg() { return _send_buf.pop(); }
void buffersocket::set_msg(string data) { _recv_buf.push_back(data); }
int buffersocket::close() {
  _send_buf.push_back("eof");
  return 0;
};
}  // namespace fucrypto
