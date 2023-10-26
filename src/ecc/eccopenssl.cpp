#include "eccopenssl.h"
#include <string>
#include <openssl/obj_mac.h>
#include <string.h>
#define ERR_NEW -1
#define ERR_CURVE_INIT -2
#define ERR_CURVE_GET_GENERATOR -3
#define ERR_CURVE_MUL_GEN -4
#define ERR_POINT_INV -5
#define ERR_POINT_MUL -6
#define ERR_POINT_ADD -7
#define ERR_POINT_FROM_BIN -8
#define ERR_POINT_SIZE -9
#define ERR_POINT_TO_BIN -10
#define ERR_POINT_INIT -11

namespace osuCrypto
{
    int CurveMap[10] = {
        NID_secp256k1, NID_X9_62_prime256v1,
        NID_secp256k1, NID_secp256k1, NID_secp256k1, NID_secp256k1,
        NID_secp256k1, NID_secp256k1, NID_secp256k1, NID_secp256k1};
    BigInt::BigInt()
    {
        n = BN_new();
    }
    BigInt::BigInt(const BigInt &oth)
    {
        n = BN_new();
        BN_copy(n, oth.n);
    }
    BigInt &BigInt::operator=(BigInt oth)
    {
        std::swap(n, oth.n);
        return *this;
    }
    BigInt::~BigInt()
    {
        if (n != nullptr)
            BN_free(n);
    }

    int BigInt::size()
    {
        return BN_num_bytes(n);
    }

    int BigInt::to_bin(unsigned char *in)
    {
        return BN_bn2bin(n, in);
    }

    void BigInt::from_bin(const unsigned char *in, int length)
    {
        BN_free(n);
        n = BN_bin2bn(in, length, nullptr);
    }

    BigInt BigInt::add(const BigInt &oth)
    {
        BigInt ret;
        BN_add(ret.n, n, oth.n);
        return ret;
    }

    BigInt BigInt::mul_mod(const BigInt &b, const BigInt &m, BN_CTX *ctx)
    {
        BigInt ret;
        BN_mod_mul(ret.n, n, b.n, m.n, ctx);
        return ret;
    }

    BigInt BigInt::add_mod(const BigInt &b, const BigInt &m, BN_CTX *ctx)
    {
        BigInt ret;
        BN_mod_add(ret.n, n, b.n, m.n, ctx);
        return ret;
    }

    BigInt BigInt::mul(const BigInt &oth, BN_CTX *ctx)
    {
        BigInt ret;
        BN_mul(ret.n, n, oth.n, ctx);
        return ret;
    }

    BigInt BigInt::mod(const BigInt &oth, BN_CTX *ctx)
    {
        BigInt ret;
        BN_mod(ret.n, n, oth.n, ctx);
        return ret;
    }

    Point::Point(Curve *g, int &err_no)
    {
        err_no = 0;
        if (g == nullptr)
        {
            err_no = ERR_POINT_INIT;
            return;
        }
        this->group = g;
        this->point = EC_POINT_new(this->group->ec_group);
        if (this->point == nullptr)
        {
            err_no = ERR_POINT_INIT;
            return;
        }
    }

    Point::~Point()
    {
        if (this->point != nullptr)
            EC_POINT_free(this->point);
    }

    Point::Point(const Point &p, int &err_no)
    {
        err_no = 0;
        if (p.group == nullptr)
        {
            err_no = ERR_POINT_INIT;
            return;
        }
        this->group = p.group;
        this->point = EC_POINT_new(group->ec_group);
        if (this->point == nullptr)
        {
            err_no = ERR_POINT_INIT;
            return;
        }
        int ret = EC_POINT_copy(point, p.point);
        if (ret == 0)
            err_no = ERR_POINT_INIT;
    }

    Point &Point::operator=(Point p)
    {
        std::swap(p.point, this->point);
        std::swap(p.group, this->group);
        return *this;
    }

    int Point::to_bin(unsigned char *buf, size_t buf_len)
    {
        // POINT_CONVERSION_COMPRESSED
        // POINT_CONVERSION_UNCOMPRESSED
        int ret = EC_POINT_point2oct(group->ec_group, point, POINT_CONVERSION_COMPRESSED, buf, buf_len, group->bn_ctx);
        if (ret == 0)
            return ERR_POINT_TO_BIN;
        return 0;
    }

    int Point::size()
    {
        // POINT_CONVERSION_COMPRESSED
        // POINT_CONVERSION_UNCOMPRESSED
        size_t ret = EC_POINT_point2oct(this->group->ec_group, point,
                                        POINT_CONVERSION_COMPRESSED,
                                        NULL, 0, group->bn_ctx);
        if (ret == 0)
            return ERR_POINT_SIZE;
        return (int)ret;
    }

    int Point::from_bin(Curve *g, const unsigned char *buf, size_t buf_len)
    {
        if (g == nullptr || buf == nullptr)
            return ERR_POINT_FROM_BIN;
        if (this->point == nullptr)
        {
            this->group = g;
            this->point = EC_POINT_new(this->group->ec_group);
            if (this->point == nullptr)
                return ERR_POINT_FROM_BIN;
        }
        int ret = EC_POINT_oct2point(this->group->ec_group, this->point,
                                     buf, buf_len, this->group->bn_ctx);
        if (ret == 0)
            return ERR_POINT_FROM_BIN;
        return 0;
    }

    Point Point::add(Point &rhs, int &err_no)
    {
        err_no = 0;
        Point ret(this->group, err_no);
        if (err_no != 0)
            return ret;
        int res = EC_POINT_add(this->group->ec_group, ret.point, this->point,
                               rhs.point, this->group->bn_ctx);
        if (res == 0)
            err_no = ERR_POINT_ADD;
        return ret;
    }

    Point Point::mul(const BigInt &m, int &err_no)
    {
        err_no = 0;
        Point ret(this->group, err_no);
        // Point ret2(*this);
        if (err_no != 0)
            return ret;
        int res = EC_POINT_mul(this->group->ec_group, ret.point, NULL,
                               this->point, m.n, this->group->bn_ctx);
        if (res == 0)
            err_no = ERR_POINT_MUL;
        return ret;
    }

    Point Point::inv(int &err_no)
    {
        // Point ret(*this, err_no);
        err_no = 0;
        Point ret(*this, err_no);
        if (err_no != 0)
            return ret;

        int res = EC_POINT_invert(this->group->ec_group, ret.point, this->group->bn_ctx);
        if (res == 0)
            err_no = ERR_POINT_INV;
        return ret;
    }
    // bool Point::operator==(Point &rhs)
    // {
    //     int ret = EC_POINT_cmp(group->ec_group, point, rhs.point, group->bn_ctx);
    //     if (ret == -1)
    //         error("ECC CMP");
    //     return (ret == 0);
    // }

    /*
    0 ,NID_secp256k1
    1 ,NID_X9_62_prime256v1
    */
    Curve::Curve(int &err_no)
    {
        err_no = 0;
        this->ec_group = EC_GROUP_new_by_curve_name(CurveMap[0]); // NIST P-256
        if (this->ec_group == nullptr)
        {
            err_no = ERR_CURVE_INIT;
            return;
        }
        this->bn_ctx = BN_CTX_new();
        if (this->bn_ctx == nullptr)
        {
            err_no = ERR_CURVE_INIT;
            return;
        }
        int fg = EC_GROUP_get_order(this->ec_group, this->order.n, this->bn_ctx);
        if (fg == 0)
        {
            err_no = ERR_CURVE_INIT;
            return;
        }
        this->scratch = new (std::nothrow) unsigned char[this->scratch_size];
        if (this->scratch == nullptr)
        {
            err_no = ERR_NEW;
        }
    }
    Curve::Curve(int curv_type, int &err_no)
    {
        err_no = 0;
        if (curv_type < 0 || curv_type >= 10)
        {
            this->ec_group = EC_GROUP_new_by_curve_name(CurveMap[0]);
        }
        else
        {
            this->ec_group = EC_GROUP_new_by_curve_name(CurveMap[curv_type]);
        }
        if (this->ec_group == nullptr)
        {
            err_no = ERR_CURVE_INIT;
            return;
        }
        this->bn_ctx = BN_CTX_new();
        if (this->bn_ctx == nullptr)
        {
            err_no = ERR_CURVE_INIT;
            return;
        }
        int fg = EC_GROUP_get_order(this->ec_group, this->order.n, this->bn_ctx);
        if (fg == 0)
        {
            err_no = ERR_CURVE_INIT;
            return;
        }
        this->scratch = new (std::nothrow) unsigned char[this->scratch_size];
        if (this->scratch == nullptr)
        {
            err_no = ERR_NEW;
        }
    }
    Curve::~Curve()
    {
        if (this->ec_group != nullptr)
            EC_GROUP_free(this->ec_group);
        if (this->bn_ctx != nullptr)
            BN_CTX_free(this->bn_ctx);
        if (this->scratch != nullptr)
            delete[] this->scratch;
    }

    // void Curve::resize_scratch(size_t size)
    // {
    //     if (size > scratch_size)
    //     {
    //         delete[] scratch;
    //         scratch_size = size;
    //         scratch = new unsigned char[scratch_size];
    //     }
    // }

    void Curve::get_rand_bn(BigInt &n)
    {
        BN_rand_range(n.n, this->order.n);
    }

    Point Curve::get_generator(int &err_no)
    {
        err_no = 0;
        Point res(this, err_no);
        if (err_no != 0)
            return res;
        int ret = EC_POINT_copy(res.point, EC_GROUP_get0_generator(this->ec_group));
        if (ret == 0)
            err_no = ERR_CURVE_GET_GENERATOR;
        return res;
    }

    Point Curve::mul_gen(const BigInt &m, int &err_no)
    {
        err_no = 0;
        Point res(this, err_no);
        if (err_no != 0)
            return res;
        int ret = EC_POINT_mul(this->ec_group, res.point, m.n, NULL, NULL, this->bn_ctx);
        if (ret == 0)
            err_no = ERR_CURVE_MUL_GEN;
        return res;
    }
    void print_buffer_debug(const char *prefix, unsigned char *buf, int size)
    {
        if (buf == nullptr)
            return;
        printf("%s:", prefix);
        for (int i = 0; i < size; i++)
            printf("%2x,", buf[i]);
        printf("  %dBytes\n", size);
    }
    void print_point_debug(const char *prefix, Point &a)
    {
        unsigned char buf[512];
        int buf_len = 512;
        a.to_bin(buf, buf_len);
        print_buffer_debug(prefix, buf, a.size());
    }
    void print_bigint_debug(const char *prefix, BigInt &a)
    {
        unsigned char buf[512] = {0};
        memset(buf, 0, 512);
        if (buf == nullptr)
            return;
        printf("%s:", prefix);
        int fg = a.to_bin(buf);
        for (int i = 0; i < fg; i++)
            printf("%2x,", buf[i]);
        printf("  %dBytes\n", fg);
    }
}
// #define ECC_OPENSSL_TEST
#ifdef ECC_OPENSSL_TEST
// #include <unordered_map>
// oc::
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <chrono>
#include <vector>
namespace oc = osuCrypto;
std::chrono::steady_clock::time_point get_start()
{
    return std::chrono::steady_clock::now();
}
float get_use_time(std::chrono::steady_clock::time_point &st)
{
    std::chrono::steady_clock::time_point cur_time = std::chrono::steady_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(cur_time - st);
    return dur.count();
}
int test1()
{
    int curve_type = 0, err_no = 0;
    oc::Curve c(curve_type, err_no);
    assert(err_no);
    oc::Point G = c.get_generator(err_no);
    assert(err_no);
    unsigned char buf[512];
    int buf_len = 512;
    // int fg = G.to_bin(buf, buf_len);
    // assert(fg == 0);
    // int G_size = G.size();
    // printf("G_size:%d\n", G_size);
    print_point_debug("", G);
    G.inv(err_no);
    assert(err_no == 0);
    oc::Point G2(&c, err_no);
    // fg = G2.to_bin(buf, buf_len);
    // assert(fg == 0);
    // int G2_size = G2.size();
    // printf("G2_size:%d\n", G2.size());
    // print_point_debug("", buf, G2.size());
    return 0;
}
int test2_right()
{
    int curve_type = 0, err_no = 0, buf_len = 512;
    // unsigned char buf[512];
    oc::Curve c(curve_type, err_no);
    assert(err_no == 0);
    oc::Point G = c.get_generator(err_no);
    assert(err_no == 0);
    // G.to_bin(buf, buf_len);
    print_point_debug("gen_g", G);
    oc::BigInt r1, r2;
    c.get_rand_bn(r1), c.get_rand_bn(r2);
    oc::Point r1_point(&c, err_no);
    assert(err_no == 0);
    oc::Point r12_point(&c, err_no);
    assert(err_no == 0);
    r1_point = G.mul(r1, err_no);
    assert(err_no == 0);
    // unsigned char buf_r1[512];
    // r1_point.to_bin(buf, buf_len);
    print_point_debug("g_r1 ", r1_point);
    r12_point = c.mul_gen(r1, err_no);
    assert(err_no == 0);
    // unsigned char buf[512];
    // r12_point.to_bin(buf, buf_len);
    print_point_debug("g_r1 ", r12_point);
    printf("\ng_ab test ............\n");
    oc::BigInt a, b;
    c.get_rand_bn(a), c.get_rand_bn(b);
    oc::Point g_a(&c, err_no);
    assert(err_no == 0);
    oc::Point g_b(&c, err_no);
    assert(err_no == 0);
    oc::Point g_ab(&c, err_no);
    assert(err_no == 0);
    oc::Point g_ba(&c, err_no);
    assert(err_no == 0);
    g_a = c.mul_gen(a, err_no);
    assert(err_no == 0);
    g_b = c.mul_gen(b, err_no);
    assert(err_no == 0);
    g_ab = g_a.mul(b, err_no);
    assert(err_no == 0);
    // g_ab.to_bin(buf, buf_len);
    assert(err_no == 0);
    print_point_debug("g_ab", g_ab);
    g_ba = g_b.mul(a, err_no);
    assert(err_no == 0);
    // g_ba.to_bin(buf, buf_len);
    print_point_debug("g_ba", g_ba);
    printf("\na+b test ............\n");
    oc::BigInt x, y;
    c.get_rand_bn(x), c.get_rand_bn(y);
    oc::Point g_x(&c, err_no), g_y(&c, err_no), g_y_1(&c, err_no),
        g_z(&c, err_no), res(&c, err_no);
    g_x = c.mul_gen(x, err_no);
    oc::print_point_debug("g_x  ", g_x);
    g_y = c.mul_gen(y, err_no);
    oc::print_point_debug("g_y  ", g_y);
    g_z = g_x.add(g_y, err_no);
    oc::print_point_debug("g_z  ", g_z);
    g_y_1 = g_y.inv(err_no);
    res = g_z.add(g_y_1, err_no);
    oc::print_point_debug("res_x", res);
    g_y_1 = g_x.inv(err_no);
    res = g_z.add(g_y_1, err_no);
    oc::print_point_debug("res_y", res);
    return 0;
}
// #include <map>
int test_bench(int count)
{
    int err_no = 0;
    oc::Curve c(0, err_no);
    assert(err_no == 0);
    std::vector<oc::Point *> g1_vec;
    std::vector<oc::Point *> g2_vec;
    std::vector<oc::BigInt> k_vec;
    std::chrono::steady_clock::time_point now = get_start();
    for (int i = 0; i < count; i++)
    {
        oc::BigInt k1, k2;
        c.get_rand_bn(k1), c.get_rand_bn(k2);
        // oc::Point g_k1(&c, err_no);
        oc::Point *g_k1 = new oc::Point(&c, err_no);
        assert(err_no == 0);
        // printf("---------1\n");
        oc::Point *g_k2 = new oc::Point(&c, err_no);
        assert(err_no == 0);
        *g_k1 = c.mul_gen(k1, err_no);
        assert(err_no == 0);
        g1_vec.push_back(g_k1);
        *g_k2 = c.mul_gen(k2, err_no);
        assert(err_no == 0);
        g2_vec.push_back(g_k2);
        k_vec.push_back(k1);
        // oc::print_point_debug("g2_vec", g_k2);
    }
    printf("gen g1,g2 use time:%f ms\n", get_use_time(now));
    now = get_start();
    for (int i = 0; i < count; i++)
    {
        oc::Point tmp(&c, err_no);
        assert(err_no == 0);
        tmp = (*(g1_vec[i])).add(*(g2_vec[i]), err_no);
        assert(err_no == 0);
        // oc::print_point_debug("tmp", tmp);
    }
    printf("gen add use time:%f ms\n", get_use_time(now));

    now = get_start();
    for (int i = 0; i < count; i++)
    {
        oc::Point tmp(&c, err_no);
        assert(err_no == 0);
        tmp = g1_vec[i]->mul(k_vec[i], err_no);
        assert(err_no == 0);
        // oc::print_point_debug("tmp", tmp);
    }
    printf("gen mul use time:%f ms\n", get_use_time(now));
    return 0;
}
int test_bench_is_33(int count)
{
    int err_no = 0;
    oc::Curve c(0, err_no);
    assert(err_no == 0);
    // std::vector<oc::Point *> g1_vec;
    // std::vector<oc::Point *> g2_vec;
    // std::vector<oc::BigInt> k_vec;
    std::chrono::steady_clock::time_point now = get_start();
    for (int i = 0; i < count; i++)
    {
        oc::BigInt k1, k2;
        c.get_rand_bn(k1), c.get_rand_bn(k2);
        print_bigint_debug("k1", k1);
        print_bigint_debug("k2", k2);
        // oc::Point g_k1(&c, err_no);
        oc::Point g_k1 = oc::Point(&c, err_no);
        assert(err_no == 0);
        // printf("---------1\n");
        oc::Point g_k2 = oc::Point(&c, err_no);
        assert(err_no == 0);
        g_k1 = c.mul_gen(k1, err_no);
        assert(err_no == 0);
        assert(g_k1.size() == 33);
        g_k2 = c.mul_gen(k2, err_no);
        assert(err_no == 0);
        assert(g_k2.size() == 33);
        printf("........test %d end \n", i);
    }
    printf("test point size is 33 use time:%f ms\n", get_use_time(now));
    return 0;
}
int main(int argc, char **argv)
{
    int testnum = 1;
    if (argc > 1)
    {
        testnum = atoi(argv[1]);
    }
    printf("testnum:%d\n", testnum);
    for (int i = 0; i < 1; i++)
    {
        // test2_right();
        // putchar('\n');
        // test_bench(testnum);
        test_bench_is_33(testnum);
    }
}
#endif