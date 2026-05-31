/**
 * @file NativeSchemePure.cpp
 * @brief Native TLS 伪装方案纯函数单元测试
 * @details 测试 native scheme 的 name()、active()、guess() 同步方法。
 *          handshake() 是异步协程，此处仅覆盖同步可测路径。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/stealth.hpp>
#include <prism/config.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestNativeName(TestRunner &runner)
    {
        psm::stealth::native::native scheme;
        runner.Check(scheme.name() == std::string_view("native"),
                     "native: name() == 'native'");
    }

    void TestNativeActiveDisabled(TestRunner &runner)
    {
        psm::config cfg;
        cfg.stealth.native_tls.enabled = false;

        psm::stealth::native::native scheme;
        runner.Check(!scheme.active(cfg), "native: active=false when disabled");
    }

    void TestNativeActiveEnabled(TestRunner &runner)
    {
        psm::config cfg;
        cfg.stealth.native_tls.enabled = true;

        psm::stealth::native::native scheme;
        runner.Check(scheme.active(cfg), "native: active=true when enabled");
    }

    void TestNativeGuess(TestRunner &runner)
    {
        psm::config cfg;
        psm::stealth::native::native scheme;
        auto result = scheme.guess(cfg);

        runner.Check(result.score == 50, "native: guess score=50");
        runner.Check(result.solo_flag == 0, "native: guess solo_flag=0");
        runner.Check(result.note == std::string_view("native TLS fallback"),
                     "native: guess note='native TLS fallback'");
    }

    void TestNativeTier(TestRunner &runner)
    {
        psm::stealth::native::native scheme;
        runner.Check(scheme.tier() == 2, "native: tier=2");
    }

    void TestNativeCategory(TestRunner &runner)
    {
        psm::stealth::native::native scheme;
        runner.Check(scheme.category() == psm::stealth::scheme_category::facade,
                     "native: category=facade");
    }

    void TestNativeUnique(TestRunner &runner)
    {
        psm::stealth::native::native scheme;
        runner.Check(!scheme.unique(), "native: unique=false");
    }

    void TestNativeSniff(TestRunner &runner)
    {
        psm::stealth::native::native scheme;
        psm::stealth::hello_features feat;
        auto result = scheme.sniff(0, feat);
        runner.Check(!result.hit, "native: sniff hit=false");
        runner.Check(!result.solo, "native: sniff solo=false");
    }

    void TestNativeVerify(TestRunner &runner)
    {
        psm::stealth::native::native scheme;
        psm::stealth::hello_features feat;
        psm::config cfg;
        auto result = scheme.verify(feat, {}, cfg);
        runner.Check(result.score == 0, "native: verify score=0");
    }

    void TestNativeGuessDefault(TestRunner &runner)
    {
        // guess() 应调用 weight() 返回 50
        psm::stealth::native::native scheme;
        psm::config cfg;
        auto result = scheme.guess(cfg);
        runner.Check(result.score == 50, "native: guess score=50 (from weight)");
        runner.Check(result.solo_flag == 0, "native: guess solo_flag=0");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("NativeSchemePure");

    TestNativeName(runner);
    TestNativeActiveDisabled(runner);
    TestNativeActiveEnabled(runner);
    TestNativeGuess(runner);
    TestNativeTier(runner);
    TestNativeCategory(runner);
    TestNativeUnique(runner);
    TestNativeSniff(runner);
    TestNativeVerify(runner);
    TestNativeGuessDefault(runner);

    return runner.Summary();
}
