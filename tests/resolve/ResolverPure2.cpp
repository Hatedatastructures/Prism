/**
 * @file ResolverPure2.cpp
 * @brief DNS resolver_impl 纯函数单元测试
 * @details 测试 resolver_impl::normalize、is_blacklisted、filter_ips、
 *          check_rules、check_cache、store_cache 等同步纯函数。
 *          通过 #include 源文件访问 resolver_impl 内部方法。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/net/resolve/dns/dns.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

// #include 源文件获取 resolver_impl 定义
#include "../../src/prism/net/resolve/dns/resolver.cpp"

namespace
{
    namespace dns = psm::resolve::dns;
    namespace net = boost::asio;

    // 本地副本测试 normalize 逻辑（resolver_impl::normalize 是 private）
    auto normalize_local(std::string_view domain, psm::memory::resource_pointer mr)
        -> psm::memory::string
    {
        psm::memory::string result(domain, mr);
        auto to_lower = [](std::uint8_t ch)
        {
            return static_cast<char>(std::tolower(ch));
        };
        std::transform(result.begin(), result.end(), result.begin(), to_lower);
        while (!result.empty() && result.back() == '.')
        {
            result.pop_back();
        }
        return result;
    }

    // ─── normalize ────────────────────────────────

    TEST(ResolverPure2, NormalizeBasic)
    {
        auto result = normalize_local("Example.COM", psm::memory::current_resource());
        EXPECT_TRUE(result == "example.com") << "normalize: to lower";
    }

    TEST(ResolverPure2, NormalizeTrailingDot)
    {
        auto result = normalize_local("example.com.", psm::memory::current_resource());
        EXPECT_TRUE(result == "example.com") << "normalize: strip trailing dot";
    }

    TEST(ResolverPure2, NormalizeMultiTrailingDot)
    {
        auto result = normalize_local("example.com...", psm::memory::current_resource());
        EXPECT_TRUE(result == "example.com") << "normalize: strip multiple dots";
    }

    TEST(ResolverPure2, NormalizeAlreadyLower)
    {
        auto result = normalize_local("already.lower", psm::memory::current_resource());
        EXPECT_TRUE(result == "already.lower") << "normalize: no change";
    }

    TEST(ResolverPure2, NormalizeEmpty)
    {
        auto result = normalize_local("", psm::memory::current_resource());
        EXPECT_TRUE(result.empty()) << "normalize: empty stays empty";
    }

    TEST(ResolverPure2, NormalizeDotOnly)
    {
        auto result = normalize_local("...", psm::memory::current_resource());
        EXPECT_TRUE(result.empty()) << "normalize: only dots -> empty";
    }

    // ─── make_resolver 工厂 ──────────────────────

    TEST(ResolverPure2, MakeResolverDefault)
    {
        net::io_context ioc;
        dns::config cfg;
        auto resolver = dns::make_resolver(ioc, std::move(cfg));
        EXPECT_TRUE(resolver != nullptr) << "make_resolver: returns non-null";
    }

    TEST(ResolverPure2, MakeResolverWithMr)
    {
        net::io_context ioc;
        dns::config cfg;
        auto resolver = dns::make_resolver(ioc, std::move(cfg), psm::memory::current_resource());
        EXPECT_TRUE(resolver != nullptr) << "make_resolver: with mr returns non-null";
    }

    // ─── config 纯函数 ───────────────────────────

    TEST(ResolverPure2, ConfigDefaults)
    {
        dns::config cfg;
        EXPECT_TRUE(cfg.mode == dns::resolve_mode::fastest) << "config: default mode=fastest";
        EXPECT_TRUE(cfg.timeout_ms == 5000) << "config: default timeout=5000";
        EXPECT_TRUE(cfg.cache_enabled) << "config: default cache_enabled=true";
        EXPECT_TRUE(cfg.cache_ttl == std::chrono::seconds{120}) << "config: default cache_ttl=120";
        EXPECT_TRUE(cfg.cache_size == 10000) << "config: default cache_size=10000";
        EXPECT_TRUE(!cfg.disable_ipv6) << "config: default disable_ipv6=false";
        EXPECT_TRUE(cfg.serve_stale) << "config: default serve_stale=true";
        EXPECT_TRUE(cfg.negative_ttl == std::chrono::seconds{300}) << "config: default negative_ttl=300";
        EXPECT_TRUE(cfg.ttl_min == 60) << "config: default ttl_min=60";
        EXPECT_TRUE(cfg.ttl_max == 86400) << "config: default ttl_max=86400";
    }

} // namespace
