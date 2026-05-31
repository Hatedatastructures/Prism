/**
 * @file RealitySchemePure.cpp
 * @brief Reality scheme sniff() 全分支测试
 * @details 覆盖 sniff() 的 7 条分支路径
 */

#include <prism/memory.hpp>
#include <prism/stealth/facade/reality/scheme.hpp>
#include <prism/recognition/tls/features.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace rfeat = psm::recognition::tls;
    using fb = rfeat::feature_bit;

    void TestSniffRealityMarker(TestRunner &runner)
    {
        psm::stealth::reality::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(fb::reality_marker);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        runner.Check(result.hit, "reality marker: hit");
        runner.Check(result.solo, "reality marker: solo");
        runner.Check(result.hint == 950, "reality marker: hint=950");
    }

    void TestSniffX25519FullSession(TestRunner &runner)
    {
        psm::stealth::reality::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(fb::has_x25519 | fb::full_session);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        runner.Check(result.hit, "x25519+full: hit");
        runner.Check(!result.solo, "x25519+full: not solo");
        runner.Check(result.hint == 450, "x25519+full: hint=450");
    }

    void TestSniffX25519NonstdSession(TestRunner &runner)
    {
        psm::stealth::reality::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(fb::has_x25519 | fb::nonstd_session);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        runner.Check(result.hit, "x25519+nonstd: hit");
        runner.Check(!result.solo, "x25519+nonstd: not solo");
        runner.Check(result.hint == 400, "x25519+nonstd: hint=400");
    }

    void TestSniffX25519Only(TestRunner &runner)
    {
        psm::stealth::reality::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(fb::has_x25519);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        runner.Check(result.hit, "x25519 only: hit");
        runner.Check(!result.solo, "x25519 only: not solo");
        runner.Check(result.hint == 200, "x25519 only: hint=200");
    }

    void TestSniffSniFullSession(TestRunner &runner)
    {
        psm::stealth::reality::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(fb::has_sni | fb::full_session);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        runner.Check(result.hit, "sni+full: hit");
        runner.Check(!result.solo, "sni+full: not solo");
        runner.Check(result.hint == 100, "sni+full: hint=100");
    }

    void TestSniffSniOnly(TestRunner &runner)
    {
        psm::stealth::reality::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(fb::has_sni);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        runner.Check(result.hit, "sni only: hit");
        runner.Check(!result.solo, "sni only: not solo");
        runner.Check(result.hint == 100, "sni only: hint=100");
    }

    void TestSniffMiss(TestRunner &runner)
    {
        psm::stealth::reality::scheme sch;
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(0, features);
        runner.Check(!result.hit, "empty: miss");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RealitySchemePure");

    TestSniffRealityMarker(runner);
    TestSniffX25519FullSession(runner);
    TestSniffX25519NonstdSession(runner);
    TestSniffX25519Only(runner);
    TestSniffSniFullSession(runner);
    TestSniffSniOnly(runner);
    TestSniffMiss(runner);

    return runner.Summary();
}
