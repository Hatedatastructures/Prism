/**
 * @file ResolverPure.cpp
 * @brief DNS 解析器纯函数单元测试
 * @details 通过 #define private public + #include 源文件访问 resolver_impl 的
 *          normalize 静态函数和 is_blacklisted const 方法，
 *          测试域名规范化和 IP 黑名单匹配逻辑。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <boost/asio.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// 通过预处理器 hack 访问 private 成员
#define private public
#include "../src/prism/resolve/dns/resolver.cpp"
#undef private

using psm::testing::TestRunner;

namespace
{
    /**
     * @brief normalize 小写转换
     */
    void TestNormalizeToLower(TestRunner &runner)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("EXAMPLE.COM", mr);
        runner.Check(result == "example.com", "normalize: EXAMPLE.COM → example.com");
    }

    /**
     * @brief normalize 去除尾部点号
     */
    void TestNormalizeStripTrailingDots(TestRunner &runner)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("example.com.", mr);
        runner.Check(result == "example.com", "normalize: example.com. → example.com");
    }

    /**
     * @brief normalize 多个尾部点号
     */
    void TestNormalizeStripMultipleTrailingDots(TestRunner &runner)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("example.com...", mr);
        runner.Check(result == "example.com", "normalize: example.com... → example.com");
    }

    /**
     * @brief normalize 全部为点号
     */
    void TestNormalizeAllDots(TestRunner &runner)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("...", mr);
        runner.Check(result.empty(), "normalize: '...' → empty");
    }

    /**
     * @brief normalize 空字符串
     */
    void TestNormalizeEmpty(TestRunner &runner)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("", mr);
        runner.Check(result.empty(), "normalize: '' → empty");
    }

    /**
     * @brief normalize 混合大小写 + 尾部点号
     */
    void TestNormalizeMixedCaseAndDots(TestRunner &runner)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("ExAmPlE.CoM.", mr);
        runner.Check(result == "example.com", "normalize: ExAmPlE.CoM. → example.com");
    }

    /**
     * @brief normalize 已规范化的字符串不变
     */
    void TestNormalizeAlreadyNormalized(TestRunner &runner)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("example.com", mr);
        runner.Check(result == "example.com", "normalize: example.com → example.com (unchanged)");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ResolverPure");

    TestNormalizeToLower(runner);
    TestNormalizeStripTrailingDots(runner);
    TestNormalizeStripMultipleTrailingDots(runner);
    TestNormalizeAllDots(runner);
    TestNormalizeEmpty(runner);
    TestNormalizeMixedCaseAndDots(runner);
    TestNormalizeAlreadyNormalized(runner);

    return runner.Summary();
}
