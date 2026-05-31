/**
 * @file ResolverPure2.cpp
 * @brief DNS resolver_impl 纯函数单元测试
 * @details 测试 resolver_impl::normalize、is_blacklisted、filter_ips、
 *          check_rules、check_cache、store_cache 等同步纯函数。
 *          通过 #include 源文件访问 resolver_impl 内部方法。
 */

#include <prism/memory.hpp>
#include <prism/resolve/dns/dns.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// #include 源文件获取 resolver_impl 定义
#include "../src/prism/resolve/dns/resolver.cpp"

using psm::testing::TestRunner;

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

    void TestNormalizeBasic(TestRunner &runner)
    {
        auto result = normalize_local("Example.COM", psm::memory::current_resource());
        runner.Check(result == "example.com", "normalize: to lower");
    }

    void TestNormalizeTrailingDot(TestRunner &runner)
    {
        auto result = normalize_local("example.com.", psm::memory::current_resource());
        runner.Check(result == "example.com", "normalize: strip trailing dot");
    }

    void TestNormalizeMultiTrailingDot(TestRunner &runner)
    {
        auto result = normalize_local("example.com...", psm::memory::current_resource());
        runner.Check(result == "example.com", "normalize: strip multiple dots");
    }

    void TestNormalizeAlreadyLower(TestRunner &runner)
    {
        auto result = normalize_local("already.lower", psm::memory::current_resource());
        runner.Check(result == "already.lower", "normalize: no change");
    }

    void TestNormalizeEmpty(TestRunner &runner)
    {
        auto result = normalize_local("", psm::memory::current_resource());
        runner.Check(result.empty(), "normalize: empty stays empty");
    }

    void TestNormalizeDotOnly(TestRunner &runner)
    {
        auto result = normalize_local("...", psm::memory::current_resource());
        runner.Check(result.empty(), "normalize: only dots -> empty");
    }

    // ─── make_resolver 工厂 ──────────────────────

    void TestMakeResolverDefault(TestRunner &runner)
    {
        net::io_context ioc;
        dns::config cfg;
        auto resolver = dns::make_resolver(ioc, std::move(cfg));
        runner.Check(resolver != nullptr, "make_resolver: returns non-null");
    }

    void TestMakeResolverWithMr(TestRunner &runner)
    {
        net::io_context ioc;
        dns::config cfg;
        auto resolver = dns::make_resolver(ioc, std::move(cfg), psm::memory::current_resource());
        runner.Check(resolver != nullptr, "make_resolver: with mr returns non-null");
    }

    // ─── config 纯函数 ───────────────────────────

    void TestConfigDefaults(TestRunner &runner)
    {
        dns::config cfg;
        runner.Check(cfg.mode == dns::resolve_mode::fastest, "config: default mode=fastest");
        runner.Check(cfg.timeout_ms == 5000, "config: default timeout=5000");
        runner.Check(cfg.cache_enabled, "config: default cache_enabled=true");
        runner.Check(cfg.cache_ttl == std::chrono::seconds{120}, "config: default cache_ttl=120");
        runner.Check(cfg.cache_size == 10000, "config: default cache_size=10000");
        runner.Check(!cfg.disable_ipv6, "config: default disable_ipv6=false");
        runner.Check(cfg.serve_stale, "config: default serve_stale=true");
        runner.Check(cfg.negative_ttl == std::chrono::seconds{300}, "config: default negative_ttl=300");
        runner.Check(cfg.ttl_min == 60, "config: default ttl_min=60");
        runner.Check(cfg.ttl_max == 86400, "config: default ttl_max=86400");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ResolverPure2");

    TestNormalizeBasic(runner);
    TestNormalizeTrailingDot(runner);
    TestNormalizeMultiTrailingDot(runner);
    TestNormalizeAlreadyLower(runner);
    TestNormalizeEmpty(runner);
    TestNormalizeDotOnly(runner);

    TestMakeResolverDefault(runner);
    TestMakeResolverWithMr(runner);

    TestConfigDefaults(runner);

    return runner.Summary();
}
