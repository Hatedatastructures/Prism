/**
 * @file NativeScheme.cpp
 * @brief 原生 TLS 伪装方案单元测试
 * @details 覆盖 native scheme 的 name/active/guess/tier/unique/weight 方法。
 */

#include <prism/stealth/facade/native.hpp>
#include <prism/config.hpp>
#include <prism/trace/spdlog.hpp>

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
        psm::stealth::native::native scheme;
        runner.Check(scheme.name() == std::string_view{"native"},
                     "native: name == 'native'");
    }

    void TestTier(TestRunner &runner)
    {
        psm::stealth::native::native scheme;
        runner.Check(scheme.tier() == 2, "native: tier == 2");
    }

    void TestUnique(TestRunner &runner)
    {
        psm::stealth::native::native scheme;
        runner.Check(scheme.unique() == false, "native: unique == false");
    }

    void TestActiveEnabled(TestRunner &runner)
    {
        psm::stealth::native::native scheme;
        psm::config cfg;
        cfg.stealth.native_tls.enabled = true;
        runner.Check(scheme.active(cfg) == true, "native: active when enabled=true");
    }

    void TestActiveDisabled(TestRunner &runner)
    {
        psm::stealth::native::native scheme;
        psm::config cfg;
        cfg.stealth.native_tls.enabled = false;
        runner.Check(scheme.active(cfg) == false, "native: inactive when enabled=false");
    }

    void TestActiveDefault(TestRunner &runner)
    {
        psm::stealth::native::native scheme;
        psm::config cfg; // 默认 enabled=true
        runner.Check(scheme.active(cfg) == true, "native: active by default");
    }

    void TestGuess(TestRunner &runner)
    {
        psm::stealth::native::native scheme;
        psm::config cfg;
        auto result = scheme.guess(cfg);
        runner.Check(result.score == 50, "native guess: score=50");
        runner.Check(result.solo_flag == 0, "native guess: solo_flag=0");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::trace::init({});

    TestRunner runner("NativeScheme");

    TestName(runner);
    TestTier(runner);
    TestUnique(runner);
    TestActiveEnabled(runner);
    TestActiveDisabled(runner);
    TestActiveDefault(runner);
    TestGuess(runner);

    return runner.Summary();
}
