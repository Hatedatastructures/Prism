/**
 * @file DnsCache.cpp
 * @brief DNS Cache 单元测试
 * @details 测试 DNS 缓存的 LRU 淘汰、TTL 过期、serve-stale、负向缓存等核心逻辑。
 */

#include <prism/resolve/dns/detail/cache.hpp>
#include <prism/resolve/dns/detail/format.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include "common/test_runner.hpp"
#include <chrono>
#include <thread>

#ifdef WIN32
#include <windows.h>
#endif

using psm::resolve::dns::detail::cache;
using psm::resolve::dns::detail::qtype;

namespace net = boost::asio;

/**
 * @brief 创建 IP 地址列表辅助函数
 */
static auto MakeIps(std::initializer_list<const char *> strs)
    -> psm::memory::vector<net::ip::address>
{
    psm::memory::vector<net::ip::address> ips(psm::memory::current_resource());
    for (auto s : strs)
    {
        ips.push_back(net::ip::make_address(s));
    }
    return ips;
}

/**
 * @brief 测试基本 put/get
 */
void TestBasicPutGet(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestBasicPutGet ===");

    cache c(psm::memory::current_resource(), std::chrono::seconds(300), 100, false);

    // 缓存未命中
    auto miss = c.get("example.com", qtype::a);
    runner.Check(!miss.has_value(), "basic: miss returns nullopt");

    // 存入并命中
    auto ips = MakeIps({"1.2.3.4"});
    c.put("example.com", qtype::a, ips, 300);
    auto hit = c.get("example.com", qtype::a);
    runner.Check(hit.has_value() && hit->size() == 1, "basic: hit returns 1 IP");
    if (hit && !hit->empty())
    {
        runner.Check(hit->at(0).to_string() == "1.2.3.4", "basic: correct IP");
    }

    // 不同 qtype 不冲突
    auto miss_aaaa = c.get("example.com", qtype::aaaa);
    runner.Check(!miss_aaaa.has_value(), "basic: different qtype is miss");
}

/**
 * @brief 测试 LRU 淘汰
 */
void TestLruEviction(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestLruEviction ===");

    // max_entries = 3
    cache c(psm::memory::current_resource(), std::chrono::seconds(300), 3, false);

    auto ips = MakeIps({"1.1.1.1"});
    c.put("a.com", qtype::a, ips, 300);
    c.put("b.com", qtype::a, ips, 300);
    c.put("c.com", qtype::a, ips, 300);

    // 全部存在
    runner.Check(c.get("a.com", qtype::a).has_value(), "lru: a.com exists");
    runner.Check(c.get("b.com", qtype::a).has_value(), "lru: b.com exists");
    runner.Check(c.get("c.com", qtype::a).has_value(), "lru: c.com exists");

    // 插入第 4 个，应淘汰 LRU（a.com 最久未被访问）
    c.put("d.com", qtype::a, ips, 300);
    runner.Check(!c.get("a.com", qtype::a).has_value(), "lru: a.com evicted");
    runner.Check(c.get("d.com", qtype::a).has_value(), "lru: d.com exists");
}

/**
 * @brief 测试 TTL 过期
 */
void TestTtlExpiry(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestTtlExpiry ===");

    // TTL 1 秒
    cache c(psm::memory::current_resource(), std::chrono::seconds(300), 100, false);

    auto ips = MakeIps({"9.9.9.9"});
    c.put("short.com", qtype::a, ips, 1);

    // 立即读取应命中
    runner.Check(c.get("short.com", qtype::a).has_value(), "ttl: immediate hit");

    // 等待过期（serve_stale=false）
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    auto expired = c.get("short.com", qtype::a);
    runner.Check(!expired.has_value(), "ttl: expired entry returns nullopt (serve_stale=false)");
}

/**
 * @brief 测试 serve-stale 模式
 */
void TestServeStale(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestServeStale ===");

    // serve_stale=true
    cache c(psm::memory::current_resource(), std::chrono::seconds(300), 100, true);

    auto ips = MakeIps({"10.0.0.1"});
    c.put("stale.com", qtype::a, ips, 1);

    // 立即读取
    runner.Check(c.get("stale.com", qtype::a).has_value(), "stale: immediate hit");

    // 等待过期
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    auto stale = c.get("stale.com", qtype::a);
    runner.Check(stale.has_value() && !stale->empty(), "stale: expired entry returns stale data (serve_stale=true)");
}

/**
 * @brief 测试负向缓存
 */
void TestNegativeCache(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestNegativeCache ===");

    cache c(psm::memory::current_resource(), std::chrono::seconds(300), 100, false);

    // 存入负向缓存
    c.put_negative("nx.com", qtype::a, std::chrono::seconds(60));

    // 命中应返回空 vector（非 nullopt）
    auto neg = c.get("nx.com", qtype::a);
    runner.Check(neg.has_value(), "negative: returns value (not nullopt)");
    runner.Check(neg.has_value() && neg->empty(), "negative: returns empty IP list");
}

/**
 * @brief 测试 evict_expired
 */
void TestEvictExpired(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestEvictExpired ===");

    cache c(psm::memory::current_resource(), std::chrono::seconds(300), 100, false);

    auto ips = MakeIps({"1.0.0.1"});
    c.put("expire.com", qtype::a, ips, 1);

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    c.evict_expired();

    // 过期且 serve_stale=false，evict 后应彻底删除
    auto result = c.get("expire.com", qtype::a);
    runner.Check(!result.has_value(), "evict: expired entry removed");
}

int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    psm::testing::TestRunner runner("DnsCache");
    runner.LogInfo("Starting DnsCache tests...");

    TestBasicPutGet(runner);
    TestLruEviction(runner);
    TestTtlExpiry(runner);
    TestServeStale(runner);
    TestNegativeCache(runner);
    TestEvictExpired(runner);

    return runner.Summary();
}
