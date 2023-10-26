#ifndef __ECC_OPENSSL_H__
#define __ECC_OPENSSL_H__
#include <openssl/bn.h>
#include <openssl/ec.h>
#if defined(__cplusplus) || defined(c_plusplus)
extern "C"
{
#endif
    namespace osuCrypto
    {
        class BigInt
        {
        public:
            BIGNUM *n = nullptr;
            BigInt();
            BigInt(const BigInt &oth);
            BigInt &operator=(BigInt oth);
            ~BigInt();
            int size();
            int to_bin(unsigned char *in);
            void from_bin(const unsigned char *in, int length);
            BigInt add(const BigInt &oth);
            BigInt mul(const BigInt &oth, BN_CTX *ctx);
            BigInt mod(const BigInt &oth, BN_CTX *ctx);
            BigInt add_mod(const BigInt &b, const BigInt &m, BN_CTX *ctx);
            BigInt mul_mod(const BigInt &b, const BigInt &m, BN_CTX *ctx);
        };
        class Curve;
        class Point
        {
        public:
            EC_POINT *point = nullptr;
            Curve *group = nullptr;
            Point(Curve *g, int &err_no);
            Point(const Point &p, int &err_no);
            ~Point();
            Point &operator=(Point p);

            int to_bin(unsigned char *buf, size_t buf_len);
            int size();
            int from_bin(Curve *g, const unsigned char *buf, size_t buf_len);
            Point add(Point &rhs, int &err_no);
            Point mul(const BigInt &m, int &err_no);
            Point inv(int &err_no);
            // bool operator==(Point &rhs);
        };

        class Curve
        {
        public:
            EC_GROUP *ec_group = nullptr;
            BN_CTX *bn_ctx = nullptr;
            BigInt order;
            unsigned char *scratch;
            size_t scratch_size = 256;
            // int errcode = 0;
            Curve(int &err_no);
            // 0 ,NID_secp256k1
            // 1 ,NID_X9_62_prime256v1
            Curve(int curve_type, int &err_no);
            ~Curve();
            // void resize_scratch(size_t size);
            void get_rand_bn(BigInt &n);
            Point get_generator(int &err_no);
            Point mul_gen(const BigInt &m, int &err_no);
        };
        void print_buffer_debug(const char *prefix, unsigned char *buf, int size);
        void print_point_debug(const char *prefix, Point &a);
        void print_bigint_debug(const char *prefix, BigInt &a);
    }

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif