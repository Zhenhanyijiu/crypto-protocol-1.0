#include "crypto-protocol/short_enc.h"
#include "crypto-protocol/fulog.h"
#include "crypto-protocol/futime.h"
using namespace fucrypto;
int main_test(int argc, char** argv) {
  spdlog_set_level("info");
  cout << "====== test short elgamal enc ======\n";
  int max_msg_n = 256;
  int plain_num = 100;
  if (argc > 1) max_msg_n = atoi(argv[1]);
  if (argc > 2) plain_num = atoi(argv[2]);
  auto c = (*ecc_lib_map)["openssl"]->new_curve("secp256k1");
  if (!c) return 0;
  short_elgamal::init_short_cipher(c.get(), max_msg_n);
  short_elgamal sh_elg;
  //   sh_elg.init_short_cipher(c.get(), msg_n);
  vector<uint32_t> plain(plain_num);
  for (size_t i = 0; i < plain_num; i++) {
    plain[i] = i % 2;
    // plain[i] = i % max_msg_n;
    // plain[i] = i;
  }

  auto pk = c->new_point();
  auto sk = c->gen_rand_bn();
  c->scalar_base_mul(sk.get(), pk.get());
  string cipher_0;
  std::vector<std::string> ciphers;
  //
  uint64_t start1 = get_time_now<uint64_t>();
  int fg = sh_elg.enc_list_fast(plain, cipher_0, ciphers, pk.get(), c.get());
  if (fg) {
    cout << "enc_list error ";
    return 0;
  }
  for (size_t i = 0; i < ciphers.size(); i++) {
    cout << "cipher_i:" << i << ",c0:" << cipher_0.size()
         << ",c1:" << ciphers[i].size() << endl;
  }
  auto use_t = get_use_time<uint64_t>(start1, MS);
  cout << "enc_list time:" << use_t << " ms" << endl;
  //
  vector<uint32_t> plain_dec;
  fg = sh_elg.dec_list_fast(cipher_0, ciphers, plain_dec, sk.get(), c.get());
  if (fg) {
    cout << "dec_list error ";
    return 0;
  }
  //   check
  if (plain.size() != plain_dec.size()) {
    cout << "check error " << endl;
    return 0;
  }
  auto use_t2 = get_use_time<uint64_t>(start1, MS);
  cout << "dec_list time:" << use_t2 << " ms" << endl;
  for (int i = 0; i < plain.size(); i++) {
    // cout << "dec i:" << i << ",plain_dec[i]:" << plain_dec[i]
    //      << ",plain[i]:" << plain[i] << endl;
    if (plain[i] != plain_dec[i]) {
      cout << "check val error i:" << i << endl;
      return 0;
    }
  }
  cout << "check ok " << endl;
  auto use_t3 = get_use_time<uint64_t>(start1, MS);
  cout << "check time:" << use_t3 << " ms" << endl;
  return 0;
}

int main(int argc, char** argv) {
  main_test(argc, argv);
  return 0;
}