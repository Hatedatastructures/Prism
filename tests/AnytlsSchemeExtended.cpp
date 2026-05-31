/**
 * @file AnytlsSchemeExtended.cpp
 * @brief AnyTLS 方案扩展接口测试 — verify 分支覆盖
 */

#include <prism/config.hpp>
#include <prism/memory.hpp>
#include <prism/stealth/stack/anytls/scheme.hpp>
#include <prism/stealth/scheme.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstddef>
#include <span>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestAnytlsName(TestRunner &runner)
    {
        psm::stealth::anytls::scheme s;
        runner.Check(s.name() == "anytls", "anytls: name");
    }

    void TestAnytlsTier(TestRunner &runner)
    {
        psm::stealth::anytls::scheme s;
        runner.Check(s.tier() == 2, "anytls: tier=2");
    }

    void TestAnytlsUnique(TestRunner &runner)
    {
        psm::stealth::anytls::scheme s;
        runner.Check(!s.unique(), "anytls: unique=false");
    }

    void TestAnytlsCategory(TestRunner &runner)
    {
        psm::stealth::anytls::scheme s;
        runner.Check(s.category() == psm::stealth::scheme_category::stack,
                     "anytls: category=stack");
    }

    void TestAnytlsActiveDisabled(TestRunner &runner)
    {
        psm::stealth::anytls::scheme s;
        psm::config cfg;
        runner.Check(!s.active(cfg), "anytls: active disabled by default");
    }

    void TestAnytlsActiveEnabled(TestRunner &runner)
    {
        psm::stealth::anytls::scheme s;
        psm::config cfg;
        cfg.stealth.anytls.server_names.push_back(psm::memory::string("sni.example.com"));
        cfg.stealth.anytls.certificate = psm::memory::string("/path/cert.pem");
        cfg.stealth.anytls.private_key = psm::memory::string("/path/key.pem");
        psm::stealth::anytls::user u;
        u.username = psm::memory::string("admin");
        u.password = psm::memory::string("secret");
        cfg.stealth.anytls.users.push_back(std::move(u));
        runner.Check(s.active(cfg), "anytls: active enabled");
    }

    void TestAnytlsSnis(TestRunner &runner)
    {
        psm::stealth::anytls::scheme s;
        psm::config cfg;
        cfg.stealth.anytls.server_names.push_back(psm::memory::string("a.example.com"));
        cfg.stealth.anytls.server_names.push_back(psm::memory::string("b.example.com"));
        auto snis = s.snis(cfg);
        runner.Check(snis.size() == 2, "anytls: snis count=2");
    }

    void TestAnytlsGuess(TestRunner &runner)
    {
        psm::stealth::anytls::scheme s;
        psm::config cfg;
        auto result = s.guess(cfg);
        runner.Check(result.score == 100, "anytls: guess score=100");
        runner.Check(result.solo_flag == 0, "anytls: guess solo_flag=0");
    }

    void TestAnytlsVerifyNoEch(TestRunner &runner)
    {
        psm::stealth::anytls::scheme s;
        psm::config cfg;
        psm::protocol::tls::hello_features features{};
        std::array<std::byte, 64> raw{};
        auto result = s.verify(features, raw, cfg);
        runner.Check(result.score == 0, "anytls: verify no ech -> score=0");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("AnytlsSchemeExtended");

    TestAnytlsName(runner);
    TestAnytlsTier(runner);
    TestAnytlsUnique(runner);
    TestAnytlsCategory(runner);
    TestAnytlsActiveDisabled(runner);
    TestAnytlsActiveEnabled(runner);
    TestAnytlsSnis(runner);
    TestAnytlsGuess(runner);
    TestAnytlsVerifyNoEch(runner);

    return runner.Summary();
}
