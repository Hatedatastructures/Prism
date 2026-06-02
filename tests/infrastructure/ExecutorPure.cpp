/**
 * @file ExecutorPure.cpp
 * @brief Stealth 方案执行器纯函数单元测试
 * @details 通过 #include 源文件访问匿名命名空间中的 secondary_probe 辅助函数，
 *          测试其空预读和非空预读的协议检测逻辑。
 *          find_scheme 测试通过 registry::find 间接验证。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/stealth.hpp>
#include <prism/config.hpp>
#include <gtest/gtest.h>

// #include 源文件以访问匿名命名空间中的 secondary_probe
#include "../../src/prism/stealth/executor.cpp"

namespace
{
    /**
     * @brief secondary_probe 空预读返回 unknown
     */
    TEST(ExecutorPure, SecondaryProbeEmpty)
    {
        psm::memory::vector<std::byte> empty_preread;
        auto result = psm::stealth::secondary_probe(empty_preread);
        EXPECT_TRUE(result == psm::protocol::protocol_type::unknown)
            << "secondary_probe: empty preread -> unknown";
    }

    /**
     * @brief secondary_probe HTTP GET 请求检测
     */
    TEST(ExecutorPure, SecondaryProbeHttpGet)
    {
        const char *http_get = "GET / HTTP/1.1\r\nHost: example.com\r\n";
        const auto *ptr = reinterpret_cast<const std::byte *>(http_get);
        psm::memory::vector<std::byte> preread(ptr, ptr + std::strlen(http_get));
        auto result = psm::stealth::secondary_probe(preread);
        EXPECT_TRUE(result == psm::protocol::protocol_type::http)
            << "secondary_probe: HTTP GET -> http";
    }

    /**
     * @brief secondary_probe 非 HTTP 非 SOCKS5 字节视为 shadowsocks
     */
    TEST(ExecutorPure, SecondaryProbeShadowsocks)
    {
        const char *random = "\x17\x03\x03\x00\x05hello";
        const auto *ptr = reinterpret_cast<const std::byte *>(random);
        psm::memory::vector<std::byte> preread(ptr, ptr + std::strlen(random));
        auto result = psm::stealth::secondary_probe(preread);
        EXPECT_TRUE(result == psm::protocol::protocol_type::shadowsocks)
            << "secondary_probe: random bytes -> shadowsocks";
    }

    /**
     * @brief secondary_probe SOCKS5 握手检测
     */
    TEST(ExecutorPure, SecondaryProbeSocks5)
    {
        const unsigned char socks5_data[] = {0x05, 0x01, 0x00};
        const auto *ptr = reinterpret_cast<const std::byte *>(socks5_data);
        psm::memory::vector<std::byte> preread(ptr, ptr + sizeof(socks5_data));
        auto result = psm::stealth::secondary_probe(preread);
        // SOCKS5 无 TLS 内层特征，detect_tls 返回 unknown → 回退 shadowsocks
        EXPECT_TRUE(result == psm::protocol::protocol_type::shadowsocks)
            << "secondary_probe: SOCKS5 -> shadowsocks (no TLS fingerprint)";
    }

    /**
     * @brief scheme_registry::find 在空注册表中查找返回 nullptr
     */
    TEST(ExecutorPure, RegistryFindEmpty)
    {
        psm::stealth::scheme_registry registry;
        auto found = registry.find("native");
        EXPECT_TRUE(!found) << "registry::find: empty -> nullptr";
    }

    /**
     * @brief scheme_registry::find 在有 native 的注册表中查找命中
     */
    TEST(ExecutorPure, RegistryFindHit)
    {
        psm::stealth::scheme_registry registry;
        auto scheme = std::make_shared<psm::stealth::native::native>();
        registry.add(scheme);
        auto found = registry.find("native");
        EXPECT_TRUE(found != nullptr) << "registry::find: native registered -> found";
        EXPECT_TRUE(found->name() == std::string_view("native"))
            << "registry::find: found name == 'native'";
    }

    /**
     * @brief scheme_registry::find 查找不存在的方案返回 nullptr
     */
    TEST(ExecutorPure, RegistryFindMiss)
    {
        psm::stealth::scheme_registry registry;
        auto scheme = std::make_shared<psm::stealth::native::native>();
        registry.add(scheme);
        auto found = registry.find("nonexistent");
        EXPECT_TRUE(!found) << "registry::find: nonexistent -> nullptr";
    }

    /**
     * @brief scheme_executor 从注册表初始化
     */
    TEST(ExecutorPure, ExecutorFromRegistry)
    {
        psm::stealth::scheme_registry registry;
        auto scheme = std::make_shared<psm::stealth::native::native>();
        registry.add(scheme);
        psm::stealth::scheme_executor executor(registry);
        EXPECT_TRUE(registry.all().size() == 1) << "executor: registry contains 1 scheme after add";
    }
} // namespace
