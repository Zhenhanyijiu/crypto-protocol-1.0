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
string buffersocket::recv() {
  string ret;
  bool fg = _recv_buf.front_not_wait(ret);
  if (fg) return ret;
  return "";
}
string buffersocket::get_msg() {
  string ret;
  bool fg = _send_buf.front_not_wait(ret);
  if (fg) return ret;
  return "";
}
void buffersocket::set_msg(string data) { _recv_buf.push_back(data); }
bool buffersocket::has_msg() { return !_send_buf.empty(); }
int buffersocket::close() {
  //   _send_buf.push_back("eof");
  _send_buf.set_not_wait();
  _recv_buf.set_not_wait();
  return 0;
};
}  // namespace fucrypto
