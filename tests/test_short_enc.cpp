#include "crypto-protocol/short_enc.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/futime.h"
using namespace fucrypto;
int main_test(int argc, char** argv) {
  spdlog_set_level("info");
  cout << "====== test short elgamal enc ======\n";
  int msg_n = 3;
  if (argc > 1) msg_n = atoi(argv[1]);
  auto c = (*ecc_lib_map)["openssl"]->new_curve("secp256k1");
  if (!c) return 0;
  short_elgamal::init_short_cipher(c.get(), msg_n);
  short_elgamal sh_elg;
  //   sh_elg.init_short_cipher(c.get(), msg_n);
  vector<uint32_t> plain(msg_n);
  for (size_t i = 0; i < msg_n; i++) {
    plain[i] = i;
  }

  auto pk = c->new_point();
  auto sk = c->gen_rand_bn();
  c->scalar_base_mul(sk.get(), pk.get());
  std::vector<std::array<std::string, 2>> ciphers;
  //
  uint64_t start1 = get_time_now<uint64_t>();
  int fg = sh_elg.enc_list(plain, ciphers, pk.get(), c.get());
  if (fg) {
    cout << "enc_list error ";
    return 0;
  }
  for (size_t i = 0; i < ciphers.size(); i++) {
    cout << "cipher_i:" << i << ",c0:" << ciphers[i][0].size()
         << ",c1:" << ciphers[i][1].size() << endl;
  }
  auto use_t = get_use_time<uint64_t>(start1, MS);
  cout << "enc_list time:" << use_t << " ms" << endl;
  //
  vector<uint32_t> plain_dec;
  fg = sh_elg.dec_list(ciphers, plain_dec, sk.get(), c.get());
  if (fg) {
    cout << "dec_list error ";
    return 0;
  }
  //   check
  if (plain.size() != plain_dec.size()) {
    cout << "check error " << endl;
    return 0;
  }
  for (int i = 0; i < plain.size(); i++) {
    // cout << "dec i:" << i << ",plain_dec[i]:" << plain_dec[i]
    //      << ",plain[i]:" << plain[i] << endl;
    if (plain[i] != plain_dec[i]) {
      cout << "check val error i:" << i << endl;
      return 0;
    }
  }
  cout << "check ok " << endl;
  return 0;
}

int main(int argc, char** argv) {
  main_test(argc, argv);
  return 0;
}