/**
 * @file TrustTunnelPure.cpp
 * @brief TrustTunnel 方案纯函数与元数据接口测试
 */

#include <prism/config.hpp>
#include <prism/memory.hpp>
#include <prism/stealth/stack/trusttunnel/scheme.hpp>
#include <prism/stealth/scheme.hpp>
#include <prism/trace/spdlog.hpp>

#include <string>
#include <string_view>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestName(TestRunner &runner)
    {
        psm::stealth::trusttunnel::scheme s;
        runner.Check(s.name() == "trusttunnel", "name: trusttunnel");
    }

    void TestTier(TestRunner &runner)
    {
        psm::stealth::trusttunnel::scheme s;
        runner.Check(s.tier() == 2, "tier: 2");
    }

    void TestUnique(TestRunner &runner)
    {
        psm::stealth::trusttunnel::scheme s;
        runner.Check(!s.unique(), "unique: false");
    }

    void TestCategory(TestRunner &runner)
    {
        psm::stealth::trusttunnel::scheme s;
        runner.Check(s.category() == psm::stealth::scheme_category::stack,
                     "category: stack");
    }

    void TestGuess(TestRunner &runner)
    {
        psm::stealth::trusttunnel::scheme s;
        psm::config cfg;
        auto result = s.guess(cfg);
        runner.Check(result.score == 100, "guess: score=100");
        runner.Check(result.solo_flag == 0, "guess: solo_flag=0");
    }

    void TestActiveDisabled(TestRunner &runner)
    {
        psm::stealth::trusttunnel::scheme s;
        psm::config cfg;
        // 默认配置：无 server_names/certificate/private_key/users → enabled() = false
        runner.Check(!s.active(cfg), "active: disabled by default");
    }

    void TestActiveEnabled(TestRunner &runner)
    {
        psm::stealth::trusttunnel::scheme s;
        psm::config cfg;
        // 设置所有必需字段
        cfg.stealth.trusttunnel.server_names.push_back(psm::memory::string("example.com"));
        cfg.stealth.trusttunnel.certificate = psm::memory::string("/path/to/cert.pem");
        cfg.stealth.trusttunnel.private_key = psm::memory::string("/path/to/key.pem");
        psm::stealth::trusttunnel::user u;
        u.username = psm::memory::string("admin");
        u.password = psm::memory::string("secret");
        cfg.stealth.trusttunnel.users.push_back(std::move(u));

        runner.Check(s.active(cfg), "active: enabled with all fields");
    }

    void TestSnis(TestRunner &runner)
    {
        psm::stealth::trusttunnel::scheme s;
        psm::config cfg;
        cfg.stealth.trusttunnel.server_names.push_back(psm::memory::string("a.example.com"));
        cfg.stealth.trusttunnel.server_names.push_back(psm::memory::string("b.example.com"));

        auto snis = s.snis(cfg);
        runner.Check(snis.size() == 2, "snis: 2 entries");
        runner.Check(snis[0] == "a.example.com", "snis: first");
        runner.Check(snis[1] == "b.example.com", "snis: second");
    }

    void TestSnisEmpty(TestRunner &runner)
    {
        psm::stealth::trusttunnel::scheme s;
        psm::config cfg;
        auto snis = s.snis(cfg);
        runner.Check(snis.empty(), "snis: empty by default");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TrustTunnelPure");

    TestName(runner);
    TestTier(runner);
    TestUnique(runner);
    TestCategory(runner);
    TestGuess(runner);
    TestActiveDisabled(runner);
    TestActiveEnabled(runner);
    TestSnis(runner);
    TestSnisEmpty(runner);

    return runner.Summary();
}
