/**
 * @file VlessProcessPure.cpp
 * @brief VLESS 协议处理模块纯函数测试
 * @details 验证 VLESS process.hpp 头文件 include 正确性、config/request/command
 *          结构体构造与默认值、to_string 辅助函数。
 *          process.cpp 中的 handle() 是需要 session 基础设施的 async 协程，
 *          此测试覆盖其依赖的类型定义和配置对象。
 */

#include <prism/core/core.hpp>
#include <prism/proto/protocol/vless/process.hpp>
#include <prism/proto/protocol/vless/config.hpp>
#include <prism/proto/protocol/vless/packet.hpp>
#include <prism/proto/protocol/vless/constants.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstdint>
#include <cstring>


#include <gtest/gtest.h>

namespace
{
    using psm::protocol::vless::command;
    using psm::protocol::vless::address_type;
    using psm::protocol::vless::config;
    using psm::protocol::vless::request;
    using psm::protocol::vless::ipv4_address;
    using psm::protocol::vless::ipv6_address;
    using psm::protocol::vless::domain_address;
    using psm::protocol::vless::address;
    using psm::protocol::vless::to_string;
    using psm::protocol::vless::version;

    TEST(VlessProcessPure, ConfigDefaults)
    {
        config cfg;
        EXPECT_TRUE(cfg.enable_udp == false) << "config: 默认 enable_udp=false";
        EXPECT_TRUE(cfg.idle_timeout == 60) << "config: 默认 idle_timeout=60";
        EXPECT_TRUE(cfg.max_dgram == 65535) << "config: 默认 max_dgram=65535";
    }

    TEST(VlessProcessPure, CommandEnumValues)
    {
        EXPECT_TRUE(static_cast<std::uint8_t>(command::tcp) == 0x01)
            << "command: tcp=0x01";
        EXPECT_TRUE(static_cast<std::uint8_t>(command::udp) == 0x02)
            << "command: udp=0x02";
        EXPECT_TRUE(static_cast<std::uint8_t>(command::mux) == 0x7F)
            << "command: mux=0x7F";
    }

    TEST(VlessProcessPure, AddressTypeEnumValues)
    {
        EXPECT_TRUE(static_cast<std::uint8_t>(address_type::ipv4) == 0x01)
            << "address_type: ipv4=0x01";
        EXPECT_TRUE(static_cast<std::uint8_t>(address_type::domain) == 0x02)
            << "address_type: domain=0x02";
        EXPECT_TRUE(static_cast<std::uint8_t>(address_type::ipv6) == 0x03)
            << "address_type: ipv6=0x03";
    }

    TEST(VlessProcessPure, VersionConstant)
    {
        EXPECT_TRUE(version == 0x00) << "version: 固定为 0x00";
    }

    TEST(VlessProcessPure, RequestConstruction)
    {
        request req;
        std::uint8_t uuid_bytes[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
        std::memcpy(req.uuid.data(), uuid_bytes, 16);
        req.cmd = command::tcp;
        req.port = 8080;
        req.destination_address = ipv4_address{{10, 0, 0, 1}};

        EXPECT_TRUE(req.cmd == command::tcp) << "request: cmd=tcp";
        EXPECT_TRUE(req.port == 8080) << "request: port=8080";
        EXPECT_TRUE(req.uuid[0] == 0x01) << "request: uuid[0]=0x01";
        EXPECT_TRUE(req.uuid[15] == 0x10) << "request: uuid[15]=0x10";
        EXPECT_TRUE(std::holds_alternative<ipv4_address>(req.destination_address))
            << "request: 地址类型=ipv4";
    }

    TEST(VlessProcessPure, RequestUuidSize)
    {
        request req;
        EXPECT_TRUE(req.uuid.size() == 16) << "request: uuid 固定 16 字节";
    }

    TEST(VlessProcessPure, ToStringIPv4)
    {
        ipv4_address addr{{127, 0, 0, 1}};
        address var = addr;
        auto result = to_string(var);
        EXPECT_TRUE(result == "127.0.0.1") << "to_string: IPv4 loopback";
    }

    TEST(VlessProcessPure, ToStringDomain)
    {
        domain_address addr{};
        addr.length = 7;
        const char *domain = "test.io";
        std::memcpy(addr.value.data(), domain, 7);
        address var = addr;
        auto result = to_string(var);
        EXPECT_TRUE(result == "test.io") << "to_string: domain test.io";
    }

    TEST(VlessProcessPure, ConfigCustomValues)
    {
        config cfg;
        cfg.enable_udp = true;
        cfg.idle_timeout = 300;
        cfg.max_dgram = 9000;

        EXPECT_TRUE(cfg.enable_udp == true) << "config: 自定义 enable_udp=true";
        EXPECT_TRUE(cfg.idle_timeout == 300) << "config: 自定义 idle_timeout=300";
        EXPECT_TRUE(cfg.max_dgram == 9000) << "config: 自定义 max_dgram=9000";
    }

} // namespace
