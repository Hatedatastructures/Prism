/**
 * @file ResolverPure.cpp
 * @brief DNS 解析器纯函数单元测试
 * @details 通过 #define private public + #include 源文件访问 resolver_impl 的
 *          normalize 静态函数和 is_blacklisted const 方法，
 *          测试域名规范化和 IP 黑名单匹配逻辑。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include <boost/asio.hpp>


#include <gtest/gtest.h>

// 通过预处理器 hack 访问 private 成员
#define private public
#include "../../src/prism/net/resolve/dns/resolver.cpp"
#undef private

namespace
{
    /**
     * @brief normalize 小写转换
     */
    TEST(ResolverPure, NormalizeToLower)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("EXAMPLE.COM", mr);
        EXPECT_TRUE(result == "example.com") << "normalize: EXAMPLE.COM -> example.com";
    }

    /**
     * @brief normalize 去除尾部点号
     */
    TEST(ResolverPure, NormalizeStripTrailingDots)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("example.com.", mr);
        EXPECT_TRUE(result == "example.com") << "normalize: example.com. -> example.com";
    }

    /**
     * @brief normalize 多个尾部点号
     */
    TEST(ResolverPure, NormalizeStripMultipleTrailingDots)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("example.com...", mr);
        EXPECT_TRUE(result == "example.com") << "normalize: example.com... -> example.com";
    }

    /**
     * @brief normalize 全部为点号
     */
    TEST(ResolverPure, NormalizeAllDots)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("...", mr);
        EXPECT_TRUE(result.empty()) << "normalize: '...' -> empty";
    }

    /**
     * @brief normalize 空字符串
     */
    TEST(ResolverPure, NormalizeEmpty)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("", mr);
        EXPECT_TRUE(result.empty()) << "normalize: '' -> empty";
    }

    /**
     * @brief normalize 混合大小写 + 尾部点号
     */
    TEST(ResolverPure, NormalizeMixedCaseAndDots)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("ExAmPlE.CoM.", mr);
        EXPECT_TRUE(result == "example.com") << "normalize: ExAmPlE.CoM. -> example.com";
    }

    /**
     * @brief normalize 已规范化的字符串不变
     */
    TEST(ResolverPure, NormalizeAlreadyNormalized)
    {
        auto *mr = psm::memory::current_resource();
        auto result = psm::resolve::dns::resolver_impl::normalize("example.com", mr);
        EXPECT_TRUE(result == "example.com") << "normalize: example.com -> example.com (unchanged)";
    }

} // namespace
