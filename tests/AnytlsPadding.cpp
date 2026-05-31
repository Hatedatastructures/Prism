/**
 * @file AnytlsPadding.cpp
 * @brief AnyTLS padding 方案解析器单元测试
 * @details 测试 padding_factory 构造和 generate_sizes 纯逻辑。
 */

#include <prism/memory.hpp>
#include <prism/stealth/stack/anytls/padding.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestEmptyScheme(TestRunner &runner)
    {
        psm::stealth::anytls::padding_factory factory("");
        runner.Check(factory.enabled() == false, "empty scheme → not enabled");
        runner.Check(factory.stop == 0, "empty scheme → stop = 0");
    }

    void TestDefaultFactory(TestRunner &runner)
    {
        psm::stealth::anytls::padding_factory factory;
        runner.Check(factory.enabled() == false, "default factory → not enabled");
    }

    void TestSimpleScheme(TestRunner &runner)
    {
        psm::stealth::anytls::padding_factory factory(
            "stop=3\n"
            "0=100-200\n"
            "1=50-50,c\n"
            "2=300-500");

        runner.Check(factory.enabled() == true, "simple scheme enabled");
        runner.Check(factory.stop == 3, "stop = 3");

        auto sizes0 = factory.generate_sizes(0);
        runner.Check(!sizes0.empty(), "pkt 0 has sizes");
        // "100-200" → single random value in [100, 200]
        runner.Check(sizes0[0] >= 100 && sizes0[0] <= 200, "pkt 0 size in [100,200]");

        auto sizes1 = factory.generate_sizes(1);
        runner.Check(sizes1.size() == 2, "pkt 1 has 2 segments");
        runner.Check(sizes1[0] == 50, "pkt 1 first segment = 50");
        runner.Check(sizes1[1] == psm::stealth::anytls::padding_factory::checkmark, "pkt 1 second segment is checkmark");
    }

    void TestGenerateBeyondStop(TestRunner &runner)
    {
        psm::stealth::anytls::padding_factory factory("stop=2\n0=100-200");
        auto sizes = factory.generate_sizes(5);
        runner.Check(sizes.size() == 1, "beyond stop → single checkmark");
        runner.Check(sizes[0] == psm::stealth::anytls::padding_factory::checkmark,
                     "beyond stop → checkmark");
    }

    void TestGenerateMissingPkt(TestRunner &runner)
    {
        psm::stealth::anytls::padding_factory factory("stop=5\n0=100-200\n2=300-400");
        auto sizes = factory.generate_sizes(1);
        runner.Check(sizes.size() == 1, "missing pkt → single checkmark");
        runner.Check(sizes[0] == psm::stealth::anytls::padding_factory::checkmark,
                     "missing pkt → checkmark");
    }

    void TestCheckmarkOnly(TestRunner &runner)
    {
        psm::stealth::anytls::padding_factory factory("stop=2\n0=c");
        auto sizes = factory.generate_sizes(0);
        runner.Check(sizes.size() == 1, "checkmark only → single entry");
        runner.Check(sizes[0] == psm::stealth::anytls::padding_factory::checkmark,
                     "checkmark only → checkmark value");
    }

    void TestMd5Computed(TestRunner &runner)
    {
        psm::stealth::anytls::padding_factory factory("stop=1\n0=100-200");
        runner.Check(!factory.md5.empty(), "MD5 computed for non-empty scheme");
        runner.Check(factory.md5.size() == 32, "MD5 hex string is 32 chars");
    }

    void TestEmptySchemeNoMd5(TestRunner &runner)
    {
        psm::stealth::anytls::padding_factory factory("");
        runner.Check(factory.md5.empty(), "empty scheme → no MD5");
    }

    void TestCrLfInScheme(TestRunner &runner)
    {
        // CRLF line endings should be handled
        psm::stealth::anytls::padding_factory factory("stop=1\r\n0=100-200\r\n");
        runner.Check(factory.enabled() == true, "CRLF scheme enabled");
        runner.Check(factory.stop == 1, "CRLF stop = 1");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("AnytlsPadding");

    TestEmptyScheme(runner);
    TestDefaultFactory(runner);
    TestSimpleScheme(runner);
    TestGenerateBeyondStop(runner);
    TestGenerateMissingPkt(runner);
    TestCheckmarkOnly(runner);
    TestMd5Computed(runner);
    TestEmptySchemeNoMd5(runner);
    TestCrLfInScheme(runner);

    return runner.Summary();
}
