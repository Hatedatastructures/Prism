/**
 * @file VlessProcessPure.cpp
 * @brief VLESS 协议处理模块纯函数测试
 * @details 验证 VLESS process.hpp 头文件 include 正确性、config/request/command
 *          结构体构造与默认值、to_string 辅助函数。
 *          process.cpp 中的 handle() 是需要 session 基础设施的 async 协程，
 *          此测试覆盖其依赖的类型定义和配置对象。
 */

#include <prism/memory.hpp>
#include <prism/protocol/vless/process.hpp>
#include <prism/protocol/vless/config.hpp>
#include <prism/protocol/vless/packet.hpp>
#include <prism/protocol/vless/constants.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstdint>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

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

    void TestConfigDefaults(TestRunner &runner)
    {
        config cfg;
        runner.Check(cfg.enable_udp == false, "config: 默认 enable_udp=false");
        runner.Check(cfg.idle_timeout == 60, "config: 默认 idle_timeout=60");
        runner.Check(cfg.max_dgram == 65535, "config: 默认 max_dgram=65535");
    }

    void TestCommandEnumValues(TestRunner &runner)
    {
        runner.Check(static_cast<std::uint8_t>(command::tcp) == 0x01,
                     "command: tcp=0x01");
        runner.Check(static_cast<std::uint8_t>(command::udp) == 0x02,
                     "command: udp=0x02");
        runner.Check(static_cast<std::uint8_t>(command::mux) == 0x7F,
                     "command: mux=0x7F");
    }

    void TestAddressTypeEnumValues(TestRunner &runner)
    {
        runner.Check(static_cast<std::uint8_t>(address_type::ipv4) == 0x01,
                     "address_type: ipv4=0x01");
        runner.Check(static_cast<std::uint8_t>(address_type::domain) == 0x02,
                     "address_type: domain=0x02");
        runner.Check(static_cast<std::uint8_t>(address_type::ipv6) == 0x03,
                     "address_type: ipv6=0x03");
    }

    void TestVersionConstant(TestRunner &runner)
    {
        runner.Check(version == 0x00, "version: 固定为 0x00");
    }

    void TestRequestConstruction(TestRunner &runner)
    {
        request req;
        std::uint8_t uuid_bytes[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
        std::memcpy(req.uuid.data(), uuid_bytes, 16);
        req.cmd = command::tcp;
        req.port = 8080;
        req.destination_address = ipv4_address{{10, 0, 0, 1}};

        runner.Check(req.cmd == command::tcp, "request: cmd=tcp");
        runner.Check(req.port == 8080, "request: port=8080");
        runner.Check(req.uuid[0] == 0x01, "request: uuid[0]=0x01");
        runner.Check(req.uuid[15] == 0x10, "request: uuid[15]=0x10");
        runner.Check(std::holds_alternative<ipv4_address>(req.destination_address),
                     "request: 地址类型=ipv4");
    }

    void TestRequestUuidSize(TestRunner &runner)
    {
        request req;
        runner.Check(req.uuid.size() == 16, "request: uuid 固定 16 字节");
    }

    void TestToStringIPv4(TestRunner &runner)
    {
        ipv4_address addr{{127, 0, 0, 1}};
        address var = addr;
        auto result = to_string(var);
        runner.Check(result == "127.0.0.1", "to_string: IPv4 loopback");
    }

    void TestToStringDomain(TestRunner &runner)
    {
        domain_address addr{};
        addr.length = 7;
        const char *domain = "test.io";
        std::memcpy(addr.value.data(), domain, 7);
        address var = addr;
        auto result = to_string(var);
        runner.Check(result == "test.io", "to_string: domain test.io");
    }

    void TestConfigCustomValues(TestRunner &runner)
    {
        config cfg;
        cfg.enable_udp = true;
        cfg.idle_timeout = 300;
        cfg.max_dgram = 9000;

        runner.Check(cfg.enable_udp == true, "config: 自定义 enable_udp=true");
        runner.Check(cfg.idle_timeout == 300, "config: 自定义 idle_timeout=300");
        runner.Check(cfg.max_dgram == 9000, "config: 自定义 max_dgram=9000");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("VlessProcessPure");

    TestConfigDefaults(runner);
    TestCommandEnumValues(runner);
    TestAddressTypeEnumValues(runner);
    TestVersionConstant(runner);
    TestRequestConstruction(runner);
    TestRequestUuidSize(runner);
    TestToStringIPv4(runner);
    TestToStringDomain(runner);
    TestConfigCustomValues(runner);

    return runner.Summary();
}
