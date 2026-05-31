/**
 * @file PoolPure.cpp
 * @brief 连接池纯函数单元测试
 * @details 测试 endpoint_key 序列化 (to_key) 和 FNV-1a 哈希 (endpoint_hash)
 *          两个无副作用纯函数，覆盖 IPv4/IPv6 地址族、哈希一致性/区分性。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/connect/pool/pool.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include <array>
#include <cstdint>
#include <cstring>

using psm::testing::TestRunner;

namespace
{
    // ─── to_key IPv4 ──────────────────────────────────

    void TestToKeyIPv4(TestRunner &runner)
    {
        auto ep = psm::connect::tcp::endpoint(
            psm::connect::net::ip::make_address_v4("127.0.0.1"), 80);

        const auto key = psm::connect::to_key(ep);

        runner.Check(key.family == 4, "to_key IPv4: family=4");
        runner.Check(key.port == 80, "to_key IPv4: port=80");

        // 127.0.0.1 → 0x7F000001
        runner.Check(key.address[0] == 127, "to_key IPv4: address[0]=127");
        runner.Check(key.address[1] == 0, "to_key IPv4: address[1]=0");
        runner.Check(key.address[2] == 0, "to_key IPv4: address[2]=0");
        runner.Check(key.address[3] == 1, "to_key IPv4: address[3]=1");

        // IPv4 只填充前 4 字节，剩余应为零
        bool rest_zero = true;
        for (std::size_t i = 4; i < key.address.size(); ++i)
        {
            if (key.address[i] != 0)
            {
                rest_zero = false;
            }
        }
        runner.Check(rest_zero, "to_key IPv4: 高位字节为零");
    }

    // ─── to_key IPv6 ──────────────────────────────────

    void TestToKeyIPv6(TestRunner &runner)
    {
        auto ep = psm::connect::tcp::endpoint(
            psm::connect::net::ip::make_address_v6("::1"), 443);

        const auto key = psm::connect::to_key(ep);

        runner.Check(key.family == 6, "to_key IPv6: family=6");
        runner.Check(key.port == 443, "to_key IPv6: port=443");

        // ::1 → 最后一个字节为 1，其余为 0
        runner.Check(key.address[15] == 1, "to_key IPv6: address[15]=1");

        bool leading_zero = true;
        for (std::size_t i = 0; i < 15; ++i)
        {
            if (key.address[i] != 0)
            {
                leading_zero = false;
            }
        }
        runner.Check(leading_zero, "to_key IPv6: 前 15 字节为零");
    }

    // ─── endpoint_hash 一致性 ────────────────────────

    void TestEndpointHashConsistency(TestRunner &runner)
    {
        auto ep = psm::connect::tcp::endpoint(
            psm::connect::net::ip::make_address_v4("192.168.1.1"), 8080);

        const auto key1 = psm::connect::to_key(ep);
        const auto key2 = psm::connect::to_key(ep);

        psm::connect::endpoint_hash hasher;
        const auto h1 = hasher(key1);
        const auto h2 = hasher(key2);

        runner.Check(h1 == h2, "endpoint_hash: 相同端点 → 相同哈希");
    }

    // ─── endpoint_hash 区分性 ────────────────────────

    void TestEndpointHashDifferent(TestRunner &runner)
    {
        auto ep1 = psm::connect::tcp::endpoint(
            psm::connect::net::ip::make_address_v4("10.0.0.1"), 80);
        auto ep2 = psm::connect::tcp::endpoint(
            psm::connect::net::ip::make_address_v4("10.0.0.2"), 80);

        const auto key1 = psm::connect::to_key(ep1);
        const auto key2 = psm::connect::to_key(ep2);

        psm::connect::endpoint_hash hasher;
        runner.Check(hasher(key1) != hasher(key2),
                     "endpoint_hash: 不同地址 → 不同哈希");

        // 端口不同也应产生不同哈希
        auto ep3 = psm::connect::tcp::endpoint(
            psm::connect::net::ip::make_address_v4("10.0.0.1"), 443);
        const auto key3 = psm::connect::to_key(ep3);
        runner.Check(hasher(key1) != hasher(key3),
                     "endpoint_hash: 不同端口 → 不同哈希");
    }

    // ─── IPv4 vs IPv6 映射地址 ────────────────────────

    void TestEndpointHashIPv4v6(TestRunner &runner)
    {
        auto ep_v4 = psm::connect::tcp::endpoint(
            psm::connect::net::ip::make_address_v4("127.0.0.1"), 80);
        auto ep_v6 = psm::connect::tcp::endpoint(
            psm::connect::net::ip::make_address("::ffff:127.0.0.1"), 80);

        const auto key_v4 = psm::connect::to_key(ep_v4);
        const auto key_v6 = psm::connect::to_key(ep_v6);

        runner.Check(key_v4.family != key_v6.family,
                     "endpoint_hash IPv4/v6: family 不同");

        psm::connect::endpoint_hash hasher;
        runner.Check(hasher(key_v4) != hasher(key_v6),
                     "endpoint_hash IPv4/v6: 不同地址族 → 不同哈希");
    }

} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("PoolPure");

    TestToKeyIPv4(runner);
    TestToKeyIPv6(runner);
    TestEndpointHashConsistency(runner);
    TestEndpointHashDifferent(runner);
    TestEndpointHashIPv4v6(runner);

    return runner.Summary();
}
