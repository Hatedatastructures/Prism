/**
 * @file TrojanProcessPure.cpp
 * @brief Trojan 协议处理模块纯函数测试
 * @details 验证 Trojan process.hpp 头文件 include 正确性、config/request/command
 *          结构体构造与默认值、to_string 辅助函数。
 *          process.cpp 中的 handle() 是需要 session 基础设施的 async 协程，
 *          此测试覆盖其依赖的类型定义和配置对象。
 */

#include <prism/memory.hpp>
#include <prism/protocol/trojan/process.hpp>
#include <prism/protocol/trojan/config.hpp>
#include <prism/protocol/trojan/packet.hpp>
#include <prism/protocol/trojan/constants.hpp>
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
    using psm::protocol::trojan::command;
    using psm::protocol::trojan::address_type;
    using psm::protocol::trojan::config;
    using psm::protocol::trojan::request;
    using psm::protocol::trojan::ipv4_address;
    using psm::protocol::trojan::ipv6_address;
    using psm::protocol::trojan::domain_address;
    using psm::protocol::trojan::address;
    using psm::protocol::trojan::to_string;

    void TestConfigDefaults(TestRunner &runner)
    {
        config cfg;
        runner.Check(cfg.enable_tcp == true, "config: 默认 enable_tcp=true");
        runner.Check(cfg.enable_udp == false, "config: 默认 enable_udp=false");
        runner.Check(cfg.idle_timeout == 60, "config: 默认 idle_timeout=60");
        runner.Check(cfg.max_dgram == 65535, "config: 默认 max_dgram=65535");
    }

    void TestCommandEnumValues(TestRunner &runner)
    {
        runner.Check(static_cast<std::uint8_t>(command::connect) == 0x01,
                     "command: connect=0x01");
        runner.Check(static_cast<std::uint8_t>(command::udp_associate) == 0x03,
                     "command: udp_associate=0x03");
        runner.Check(static_cast<std::uint8_t>(command::mux) == 0x7f,
                     "command: mux=0x7f");
    }

    void TestAddressTypeEnumValues(TestRunner &runner)
    {
        runner.Check(static_cast<std::uint8_t>(address_type::ipv4) == 0x01,
                     "address_type: ipv4=0x01");
        runner.Check(static_cast<std::uint8_t>(address_type::domain) == 0x03,
                     "address_type: domain=0x03");
        runner.Check(static_cast<std::uint8_t>(address_type::ipv6) == 0x04,
                     "address_type: ipv6=0x04");
    }

    void TestRequestConstruction(TestRunner &runner)
    {
        request req;
        req.cmd = command::connect;
        req.port = 443;
        req.destination_address = ipv4_address{{127, 0, 0, 1}};
        std::memset(req.credential.data(), 'a', 56);

        runner.Check(req.cmd == command::connect, "request: cmd=connect");
        runner.Check(req.port == 443, "request: port=443");
        runner.Check(std::holds_alternative<ipv4_address>(req.destination_address),
                     "request: 地址类型=ipv4");
        runner.Check(req.credential[0] == 'a', "request: credential[0]='a'");
        runner.Check(req.credential[55] == 'a', "request: credential[55]='a'");
    }

    void TestRequestCredentialArray(TestRunner &runner)
    {
        request req;
        runner.Check(req.credential.size() == 56, "request: credential 固定 56 字节");
    }

    void TestToStringIPv4(TestRunner &runner)
    {
        ipv4_address addr{{192, 168, 1, 1}};
        address var = addr;
        auto result = to_string(var);
        runner.Check(result == "192.168.1.1", "to_string: IPv4 192.168.1.1");
    }

    void TestToStringIPv6(TestRunner &runner)
    {
        ipv6_address addr{};
        addr.bytes[0] = 0x20;
        addr.bytes[1] = 0x01;
        addr.bytes[15] = 0x01;
        address var = addr;
        auto result = to_string(var);
        runner.Check(!result.empty(), "to_string: IPv6 非空");
    }

    void TestToStringDomain(TestRunner &runner)
    {
        domain_address addr{};
        addr.length = 11;
        const char *domain = "example.com";
        std::memcpy(addr.value.data(), domain, 11);
        address var = addr;
        auto result = to_string(var);
        runner.Check(result == "example.com", "to_string: domain example.com");
    }

    void TestConfigCustomValues(TestRunner &runner)
    {
        config cfg;
        cfg.enable_tcp = false;
        cfg.enable_udp = true;
        cfg.idle_timeout = 120;
        cfg.max_dgram = 1400;

        runner.Check(cfg.enable_tcp == false, "config: 自定义 enable_tcp=false");
        runner.Check(cfg.enable_udp == true, "config: 自定义 enable_udp=true");
        runner.Check(cfg.idle_timeout == 120, "config: 自定义 idle_timeout=120");
        runner.Check(cfg.max_dgram == 1400, "config: 自定义 max_dgram=1400");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TrojanProcessPure");

    TestConfigDefaults(runner);
    TestCommandEnumValues(runner);
    TestAddressTypeEnumValues(runner);
    TestRequestConstruction(runner);
    TestRequestCredentialArray(runner);
    TestToStringIPv4(runner);
    TestToStringIPv6(runner);
    TestToStringDomain(runner);
    TestConfigCustomValues(runner);

    return runner.Summary();
}
