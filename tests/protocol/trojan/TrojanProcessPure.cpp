/**
 * @file TrojanProcessPure.cpp
 * @brief Trojan 协议处理模块纯函数测试
 * @details 验证 Trojan process.hpp 头文件 include 正确性、config/request/command
 *          结构体构造与默认值、to_string 辅助函数。
 *          process.cpp 中的 handle() 是需要 session 基础设施的 async 协程，
 *          此测试覆盖其依赖的类型定义和配置对象。
 */

#include <prism/core/core.hpp>
#include <prism/proto/protocol/trojan/process.hpp>
#include <prism/proto/protocol/trojan/config.hpp>
#include <prism/proto/protocol/trojan/packet.hpp>
#include <prism/proto/protocol/trojan/constants.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstdint>
#include <cstring>


#include <gtest/gtest.h>

namespace
{
    using psm::protocol::trojan::command;
    using psm::protocol::trojan::address_type;
    using psm::protocol::trojan::config;
    using psm::protocol::trojan::request;
    using psm::protocol::trojan::ipv4_address;
    using psm::protocol::trojan::ipv6_address;
    using psm::protocol::trojan::domain_address;
    using psm::protocol::trojan::address;
    using psm::protocol::trojan::to_string;

    TEST(TrojanProcessPure, ConfigDefaults)
    {
        config cfg;
        EXPECT_TRUE(cfg.enable_tcp == true) << "config: enable_tcp=true";
        EXPECT_TRUE(cfg.enable_udp == false) << "config: enable_udp=false";
        EXPECT_TRUE(cfg.idle_timeout == 60) << "config: idle_timeout=60";
        EXPECT_TRUE(cfg.max_dgram == 65535) << "config: max_dgram=65535";
    }

    TEST(TrojanProcessPure, CommandEnumValues)
    {
        EXPECT_TRUE(static_cast<std::uint8_t>(command::connect) == 0x01)
            << "command: connect=0x01";
        EXPECT_TRUE(static_cast<std::uint8_t>(command::udp_associate) == 0x03)
            << "command: udp_associate=0x03";
        EXPECT_TRUE(static_cast<std::uint8_t>(command::mux) == 0x7f)
            << "command: mux=0x7f";
    }

    TEST(TrojanProcessPure, AddressTypeEnumValues)
    {
        EXPECT_TRUE(static_cast<std::uint8_t>(address_type::ipv4) == 0x01)
            << "address_type: ipv4=0x01";
        EXPECT_TRUE(static_cast<std::uint8_t>(address_type::domain) == 0x03)
            << "address_type: domain=0x03";
        EXPECT_TRUE(static_cast<std::uint8_t>(address_type::ipv6) == 0x04)
            << "address_type: ipv6=0x04";
    }

    TEST(TrojanProcessPure, RequestConstruction)
    {
        request req;
        req.cmd = command::connect;
        req.port = 443;
        req.destination_address = ipv4_address{{127, 0, 0, 1}};
        std::memset(req.credential.data(), 'a', 56);

        EXPECT_TRUE(req.cmd == command::connect) << "request: cmd=connect";
        EXPECT_TRUE(req.port == 443) << "request: port=443";
        EXPECT_TRUE(std::holds_alternative<ipv4_address>(req.destination_address))
            << "request: address type=ipv4";
        EXPECT_TRUE(req.credential[0] == 'a') << "request: credential[0]='a'";
        EXPECT_TRUE(req.credential[55] == 'a') << "request: credential[55]='a'";
    }

    TEST(TrojanProcessPure, RequestCredentialArray)
    {
        request req;
        EXPECT_TRUE(req.credential.size() == 56) << "request: credential 56 bytes";
    }

    TEST(TrojanProcessPure, ToStringIPv4)
    {
        ipv4_address addr{{192, 168, 1, 1}};
        address var = addr;
        auto result = to_string(var);
        EXPECT_TRUE(result == "192.168.1.1") << "to_string: IPv4 192.168.1.1";
    }

    TEST(TrojanProcessPure, ToStringIPv6)
    {
        ipv6_address addr{};
        addr.bytes[0] = 0x20;
        addr.bytes[1] = 0x01;
        addr.bytes[15] = 0x01;
        address var = addr;
        auto result = to_string(var);
        EXPECT_TRUE(!result.empty()) << "to_string: IPv6 non-empty";
    }

    TEST(TrojanProcessPure, ToStringDomain)
    {
        domain_address addr{};
        addr.length = 11;
        const char *domain = "example.com";
        std::memcpy(addr.value.data(), domain, 11);
        address var = addr;
        auto result = to_string(var);
        EXPECT_TRUE(result == "example.com") << "to_string: domain example.com";
    }

    TEST(TrojanProcessPure, ConfigCustomValues)
    {
        config cfg;
        cfg.enable_tcp = false;
        cfg.enable_udp = true;
        cfg.idle_timeout = 120;
        cfg.max_dgram = 1400;

        EXPECT_TRUE(cfg.enable_tcp == false) << "config: enable_tcp=false";
        EXPECT_TRUE(cfg.enable_udp == true) << "config: enable_udp=true";
        EXPECT_TRUE(cfg.idle_timeout == 120) << "config: idle_timeout=120";
        EXPECT_TRUE(cfg.max_dgram == 1400) << "config: max_dgram=1400";
    }

} // namespace
