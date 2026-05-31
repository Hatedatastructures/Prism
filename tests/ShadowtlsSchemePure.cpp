/**
 * @file ShadowtlsSchemePure.cpp
 * @brief ShadowTLS scheme sniff/verify 纯函数测试
 * @details 测试 sniff 和 verify 方法的所有分支路径
 */

#include <prism/memory.hpp>
#include <prism/config.hpp>
#include <prism/stealth/facade/shadowtls/scheme.hpp>
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
    void TestSniffNonstdSession(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(psm::recognition::tls::feature_bit::nonstd_session);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        runner.Check(result.hit, "sniff: nonstd_session hit");
        runner.Check(!result.solo, "sniff: nonstd_session not solo");
        runner.Check(result.hint == 150, "sniff: nonstd_session hint=150");
    }

    void TestSniffMiss(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(psm::recognition::tls::feature_bit::has_x25519);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        runner.Check(!result.hit, "sniff: x25519 only -> miss");
    }

    void TestSniffEmpty(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme sch;
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(0, features);
        runner.Check(!result.hit, "sniff: empty bitmap -> miss");
    }

    void TestVerifyTooShort(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme sch;
        psm::protocol::tls::hello_features features;
        features.session_id_len = 32;
        std::array<std::byte, 10> small{};
        psm::config cfg;
        auto result = sch.verify(features, small, cfg);
        runner.Check(result.score == 50, "verify: too short -> score=50");
        runner.Check(result.solo_flag == 0, "verify: too short -> no solo");
    }

    void TestVerifyWrongSessionIdLen(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme sch;
        psm::protocol::tls::hello_features features;
        features.session_id_len = 16;
        std::array<std::byte, 100> buf{};
        psm::config cfg;
        auto result = sch.verify(features, buf, cfg);
        runner.Check(result.score == 50, "verify: wrong session_id_len -> score=50");
    }

    void TestVerifyV3NoUsers(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme sch;
        psm::protocol::tls::hello_features features;
        features.session_id_len = 32;
        std::array<std::byte, 100> buf{};
        psm::config cfg;
        cfg.stealth.shadowtls.version = 3;
        auto result = sch.verify(features, buf, cfg);
        runner.Check(result.score == 50, "verify: v3 no users -> score=50");
    }

    void TestVerifyV2NoPassword(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme sch;
        psm::protocol::tls::hello_features features;
        features.session_id_len = 32;
        std::array<std::byte, 100> buf{};
        psm::config cfg;
        cfg.stealth.shadowtls.version = 2;
        auto result = sch.verify(features, buf, cfg);
        runner.Check(result.score == 50, "verify: v2 no password -> score=50");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ShadowtlsSchemePure");

    TestSniffNonstdSession(runner);
    TestSniffMiss(runner);
    TestSniffEmpty(runner);
    TestVerifyTooShort(runner);
    TestVerifyWrongSessionIdLen(runner);
    TestVerifyV3NoUsers(runner);
    TestVerifyV2NoPassword(runner);

    return runner.Summary();
}
