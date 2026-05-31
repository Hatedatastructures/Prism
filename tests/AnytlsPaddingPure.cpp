/**
 * @file AnytlsPaddingPure.cpp
 * @brief AnyTLS padding 纯函数测试
 * @details 测试 parse_range / compute_md5_hex / random_in_range
 */

#include <prism/memory.hpp>
#include "../src/prism/stealth/stack/anytls/padding.cpp"
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestParseRangeMinMax(TestRunner &runner)
    {
        auto [lo, hi] = psm::stealth::anytls::parse_range("10-20");
        runner.Check(lo == 10, "parse_range: lo=10");
        runner.Check(hi == 20, "parse_range: hi=20");
    }

    void TestParseRangeSingleValue(TestRunner &runner)
    {
        auto [lo, hi] = psm::stealth::anytls::parse_range("42");
        runner.Check(lo == 42, "parse_range: single lo=42");
        runner.Check(hi == 42, "parse_range: single hi=42");
    }

    void TestParseRangeZero(TestRunner &runner)
    {
        auto [lo, hi] = psm::stealth::anytls::parse_range("0");
        runner.Check(lo == 0, "parse_range: zero lo=0");
        runner.Check(hi == 0, "parse_range: zero hi=0");
    }

    void TestComputeMd5Empty(TestRunner &runner)
    {
        auto hex = psm::stealth::anytls::compute_md5_hex("");
        runner.Check(hex == "d41d8cd98f00b204e9800998ecf8427e", "md5: empty string");
    }

    void TestComputeMd5Hello(TestRunner &runner)
    {
        auto hex = psm::stealth::anytls::compute_md5_hex("hello");
        runner.Check(hex == "5d41402abc4b2a76b9719d911017c592", "md5: hello");
    }

    void TestComputeMd5Length(TestRunner &runner)
    {
        auto hex = psm::stealth::anytls::compute_md5_hex("test");
        runner.Check(hex.size() == 32, "md5: length=32");
    }

    void TestRandomInRangeEqual(TestRunner &runner)
    {
        auto val = psm::stealth::anytls::random_in_range(5, 5);
        runner.Check(val == 5, "random: lo==hi returns lo");
    }

    void TestRandomInRangeGreater(TestRunner &runner)
    {
        auto val = psm::stealth::anytls::random_in_range(10, 5);
        runner.Check(val == 10, "random: lo>hi returns lo");
    }

    void TestRandomInRangeBounds(TestRunner &runner)
    {
        auto val = psm::stealth::anytls::random_in_range(0, 100);
        runner.Check(val >= 0 && val <= 100, "random: in [0, 100]");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("AnytlsPaddingPure");

    TestParseRangeMinMax(runner);
    TestParseRangeSingleValue(runner);
    TestParseRangeZero(runner);
    TestComputeMd5Empty(runner);
    TestComputeMd5Hello(runner);
    TestComputeMd5Length(runner);
    TestRandomInRangeEqual(runner);
    TestRandomInRangeGreater(runner);
    TestRandomInRangeBounds(runner);

    return runner.Summary();
}
