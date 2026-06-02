/**
 * @file StealthExecutorPure2.cpp
 * @brief scheme_executor 纯函数测试
 * @details 通过 #include 源文件访问 anonymous namespace 函数：
 *          secondary_probe。构造/registry 测试通过公开接口。
 */

#include <gtest/gtest.h>

#include <prism/memory.hpp>

// 显式引入 scheme 子类（executor.cpp 不直接 include 它们）
#include <prism/stealth/facade/native.hpp>
#include <prism/stealth/facade/reality/scheme.hpp>

#include "../../src/prism/stealth/executor.cpp"

// secondary_probe 在 psm::stealth 的匿名命名空间中，
// #include 源文件后可在该 TU 内通过 using 访问
using psm::stealth::secondary_probe;

namespace
{
    namespace stealth = psm::stealth;

    // ─── secondary_probe（匿名命名空间）──────────────

    TEST(StealthExecutorPure2, SecondaryProbeEmpty)
    {
        psm::memory::vector<std::byte> preread;
        auto result = secondary_probe(preread);
        EXPECT_TRUE(result == psm::protocol::protocol_type::unknown)
            << "secondary_probe: empty preread -> unknown";
    }

    TEST(StealthExecutorPure2, SecondaryProbeHttp)
    {
        psm::memory::vector<std::byte> preread;
        const char *http = "GET / HTTP/1.1\r\n";
        for (auto c : std::string_view(http))
            preread.push_back(static_cast<std::byte>(c));

        auto result = secondary_probe(preread);
        EXPECT_TRUE(result == psm::protocol::protocol_type::http)
            << "secondary_probe: HTTP GET -> http";
    }

    TEST(StealthExecutorPure2, SecondaryProbeTls)
    {
        psm::memory::vector<std::byte> preread;
        preread.push_back(static_cast<std::byte>(0x16));
        preread.push_back(static_cast<std::byte>(0x03));
        preread.push_back(static_cast<std::byte>(0x01));
        for (std::size_t i = 0; i < 20; ++i)
            preread.push_back(std::byte{0});

        auto result = secondary_probe(preread);
        EXPECT_TRUE(result == psm::protocol::protocol_type::tls ||
                     result == psm::protocol::protocol_type::shadowsocks)
            << "secondary_probe: TLS bytes -> tls or shadowsocks fallback";
    }

    TEST(StealthExecutorPure2, SecondaryProbeGarbageFallsToShadowsocks)
    {
        psm::memory::vector<std::byte> preread;
        preread.push_back(static_cast<std::byte>(0xAA));
        preread.push_back(static_cast<std::byte>(0xBB));
        preread.push_back(static_cast<std::byte>(0xCC));

        auto result = secondary_probe(preread);
        EXPECT_TRUE(result == psm::protocol::protocol_type::shadowsocks)
            << "secondary_probe: garbage -> shadowsocks fallback";
    }

    TEST(StealthExecutorPure2, SecondaryProbeConnect)
    {
        psm::memory::vector<std::byte> preread;
        const char *connect = "CONNECT example.com:443 HTTP/1.1\r\n";
        for (auto c : std::string_view(connect))
            preread.push_back(static_cast<std::byte>(c));

        auto result = secondary_probe(preread);
        EXPECT_TRUE(result == psm::protocol::protocol_type::http)
            << "secondary_probe: CONNECT -> http";
    }

    TEST(StealthExecutorPure2, SecondaryProbePost)
    {
        psm::memory::vector<std::byte> preread;
        const char *post = "POST /api HTTP/1.1\r\n";
        for (auto c : std::string_view(post))
            preread.push_back(static_cast<std::byte>(c));

        auto result = secondary_probe(preread);
        EXPECT_TRUE(result == psm::protocol::protocol_type::http)
            << "secondary_probe: POST -> http";
    }

    TEST(StealthExecutorPure2, SecondaryProbeSocks5)
    {
        psm::memory::vector<std::byte> preread;
        preread.push_back(static_cast<std::byte>(0x05));
        preread.push_back(static_cast<std::byte>(0x01));
        preread.push_back(static_cast<std::byte>(0x00));

        auto result = secondary_probe(preread);
        // SOCKS5 无 TLS 内层特征，detect_tls 返回 unknown → 回退 shadowsocks
        EXPECT_TRUE(result == psm::protocol::protocol_type::shadowsocks)
            << "secondary_probe: socks5 bytes -> shadowsocks (no TLS fingerprint)";
    }

    TEST(StealthExecutorPure2, SecondaryProbeTls12)
    {
        psm::memory::vector<std::byte> preread;
        preread.push_back(static_cast<std::byte>(0x16));
        preread.push_back(static_cast<std::byte>(0x03));
        preread.push_back(static_cast<std::byte>(0x03));
        for (std::size_t i = 0; i < 20; ++i)
            preread.push_back(std::byte{0});

        auto result = secondary_probe(preread);
        EXPECT_TRUE(result == psm::protocol::protocol_type::tls ||
                     result == psm::protocol::protocol_type::shadowsocks)
            << "secondary_probe: TLS 1.2 bytes -> tls or shadowsocks";
    }

    // ─── scheme_registry 公开接口 ──────────────────────

    TEST(StealthExecutorPure2, RegistryEmpty)
    {
        stealth::scheme_registry registry;
        auto schemes = registry.all();
        EXPECT_TRUE(schemes.empty()) << "registry: empty -> no schemes";
    }

    TEST(StealthExecutorPure2, RegistryAddAndFind)
    {
        stealth::scheme_registry registry;
        registry.add(std::make_shared<psm::stealth::native::native>());
        auto schemes = registry.all();
        EXPECT_TRUE(schemes.size() == 1) << "registry: add native -> size 1";
        EXPECT_TRUE(schemes[0]->name() == std::string_view("native"))
            << "registry: scheme name is native";
    }

    TEST(StealthExecutorPure2, RegistryAddMultiple)
    {
        stealth::scheme_registry registry;
        registry.add(std::make_shared<psm::stealth::native::native>());
        registry.add(std::make_shared<psm::stealth::reality::scheme>());
        auto schemes = registry.all();
        EXPECT_TRUE(schemes.size() == 2) << "registry: 2 schemes";
    }

    // ─── scheme_executor 构造 ──────────────────────────

    TEST(StealthExecutorPure2, ExecutorConstruction)
    {
        stealth::scheme_registry registry;
        stealth::scheme_executor executor(registry);
        EXPECT_TRUE(registry.all().empty()) << "executor: constructed with empty registry";
    }

    TEST(StealthExecutorPure2, ExecutorWithSchemes)
    {
        stealth::scheme_registry registry;
        registry.add(std::make_shared<psm::stealth::native::native>());
        registry.add(std::make_shared<psm::stealth::reality::scheme>());
        stealth::scheme_executor executor(registry);
        EXPECT_TRUE(registry.all().size() == 2) << "executor: constructed with 2 schemes";
    }

} // namespace
