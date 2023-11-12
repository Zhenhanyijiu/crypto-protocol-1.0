#include "crypto-protocol/short_enc.h"
using namespace fucrypto;
int main_test(int argc, char** argv) {
  cout << "====== test short elgamal enc ======\n";
  int msg_n = 3;
  if (argc > 1) msg_n = atoi(argv[1]);
  auto c = (*ecc_lib_map)["openssl"]->new_curve("secp256k1");
  if (!c) return 0;
  short_elgamal::init_short_cipher(msg_n, c.get());
  return 0;
}

int main(int argc, char** argv) {
  main_test(argc, argv);
  return 0;
}