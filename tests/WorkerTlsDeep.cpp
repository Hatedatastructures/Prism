/**
 * @file WorkerTlsDeep.cpp
 * @brief instance/worker/tls 深度纯函数测试
 * @details 通过 #include 源文件访问 tls.cpp 中所有同步函数，
 *          覆盖 configure 和 make 的所有分支。
 *          使用 BoringSSL API 动态生成自签名证书进行测试。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include <filesystem>
#include <fstream>

#include "../src/prism/instance/worker/tls.cpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

using psm::testing::TestRunner;

namespace
{
    namespace tls = psm::instance::worker::tls;
    namespace ssl = boost::asio::ssl;

    struct TempCertKey
    {
        std::string cert_path;
        std::string key_path;

        ~TempCertKey()
        {
            std::error_code ec;
            std::filesystem::remove(cert_path, ec);
            std::filesystem::remove(key_path, ec);
        }
    };

    auto generate_temp_cert_key() -> TempCertKey
    {
        TempCertKey result;
        auto tmp = std::filesystem::temp_directory_path();
        result.cert_path = (tmp / "prism_test_tls_cert.pem").string();
        result.key_path = (tmp / "prism_test_tls_key.pem").string();

        // 生成 RSA-2048 密钥
        auto *bn = BN_new();
        BN_set_word(bn, RSA_F4);
        auto *rsa = RSA_new();
        RSA_generate_key_ex(rsa, 2048, bn, nullptr);
        BN_free(bn);

        auto *pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsa);

        // 生成自签名 X509 证书
        auto *x509 = X509_new();
        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

        auto *name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char *>("prism-test"), -1, -1, 0);
        X509_set_issuer_name(x509, name);

        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

        X509_set_pubkey(x509, pkey);
        X509_sign(x509, pkey, EVP_sha256());

        // 写证书文件
        auto *bp = BIO_new_file(result.cert_path.c_str(), "w");
        PEM_write_bio_X509(bp, x509);
        BIO_free(bp);

        // 写私钥文件
        auto *bk = BIO_new_file(result.key_path.c_str(), "w");
        PEM_write_bio_RSAPrivateKey(bk, rsa, nullptr, nullptr, 0, nullptr, nullptr);
        BIO_free(bk);

        X509_free(x509);
        EVP_PKEY_free(pkey);

        return result;
    }

    // ─── make() 测试 ─────────────────────────

    void TestMakeEmptyCertAndKey(TestRunner &runner)
    {
        psm::instance::config cfg;
        auto result = tls::make(cfg);
        runner.Check(!result, "make: empty cert+key -> nullptr");
    }

    void TestMakeEmptyKey(TestRunner &runner)
    {
        psm::instance::config cfg;
        cfg.cert.cert = "nonexistent.pem";
        auto result = tls::make(cfg);
        runner.Check(!result, "make: empty key -> nullptr");
    }

    void TestMakeEmptyCert(TestRunner &runner)
    {
        psm::instance::config cfg;
        cfg.cert.key = "nonexistent.pem";
        auto result = tls::make(cfg);
        runner.Check(!result, "make: empty cert -> nullptr");
    }

    void TestMakeInvalidCertPath(TestRunner &runner)
    {
        psm::instance::config cfg;
        cfg.cert.cert = "/nonexistent/path/cert.pem";
        cfg.cert.key = "/nonexistent/path/key.pem";

        bool threw = false;
        try
        {
            tls::make(cfg);
        }
        catch (const psm::exception::protocol &)
        {
            threw = true;
        }
        runner.Check(threw, "make: invalid cert path -> throws protocol");
    }

    void TestMakeValidCertKey(TestRunner &runner)
    {
        auto tmp = generate_temp_cert_key();

        psm::instance::config cfg;
        cfg.cert.cert = psm::memory::string(tmp.cert_path);
        cfg.cert.key = psm::memory::string(tmp.key_path);

        auto result = tls::make(cfg);
        runner.Check(!!result, "make: valid cert+key -> non-null context");
    }

    // ─── configure() 测试 ────────────────────

    void TestConfigureInvalidCert(TestRunner &runner)
    {
        ssl::context ctx(ssl::context::tls);
        bool threw = false;
        try
        {
            tls::configure(ctx, "/nonexistent/cert.pem", "/nonexistent/key.pem");
        }
        catch (const psm::exception::protocol &)
        {
            threw = true;
        }
        runner.Check(threw, "configure: invalid cert -> throws protocol");
    }

    void TestConfigureValidCertInvalidKey(TestRunner &runner)
    {
        auto tmp = generate_temp_cert_key();

        ssl::context ctx(ssl::context::tls);
        bool threw = false;
        try
        {
            tls::configure(ctx, tmp.cert_path, "/nonexistent/key.pem");
        }
        catch (const psm::exception::protocol &)
        {
            threw = true;
        }
        runner.Check(threw, "configure: valid cert + invalid key -> throws protocol");
    }

    void TestConfigureFullSuccess(TestRunner &runner)
    {
        auto tmp = generate_temp_cert_key();

        ssl::context ctx(ssl::context::tls);
        bool success = false;
        try
        {
            tls::configure(ctx, tmp.cert_path, tmp.key_path);
            success = true;
        }
        catch (...)
        {
            success = false;
        }
        runner.Check(success, "configure: valid cert+key -> success");

        auto *native = ctx.native_handle();
        runner.Check(native != nullptr, "configure: native handle is valid");
    }

    void TestConfigureIdempotent(TestRunner &runner)
    {
        auto tmp = generate_temp_cert_key();

        ssl::context ctx(ssl::context::tls);

        // 配置两次不应崩溃
        tls::configure(ctx, tmp.cert_path, tmp.key_path);
        tls::configure(ctx, tmp.cert_path, tmp.key_path);
        runner.Check(true, "configure: double configure -> no crash");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("WorkerTlsDeep");

    TestMakeEmptyCertAndKey(runner);
    TestMakeEmptyKey(runner);
    TestMakeEmptyCert(runner);
    TestMakeInvalidCertPath(runner);
    TestMakeValidCertKey(runner);

    TestConfigureInvalidCert(runner);
    TestConfigureValidCertInvalidKey(runner);
    TestConfigureFullSuccess(runner);
    TestConfigureIdempotent(runner);

    return runner.Summary();
}
