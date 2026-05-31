/**
 * @file ShadowsocksProcessPure.cpp
 * @brief Shadowsocks 协议处理模块纯函数测试
 * @details 验证 Shadowsocks process.hpp 头文件 include 正确性、config/request
 *          结构体构造与默认值、cipher_method 枚举值、协议常量。
 *          process.cpp 中的 handle() 是需要 session 基础设施的 async 协程，
 *          此测试覆盖其依赖的类型定义和配置对象。
 */

#include <prism/memory.hpp>
#include <prism/protocol/shadowsocks/process.hpp>
#include <prism/protocol/shadowsocks/config.hpp>
#include <prism/protocol/shadowsocks/packet.hpp>
#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstdint>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    using psm::protocol::shadowsocks::cipher_method;
    using psm::protocol::shadowsocks::config;
    using psm::protocol::shadowsocks::request;
    using psm::protocol::shadowsocks::ipv4_address;
    using psm::protocol::shadowsocks::ipv6_address;
    using psm::protocol::shadowsocks::domain_address;
    using psm::protocol::shadowsocks::address;

    void TestConfigDefaults(TestRunner &runner)
    {
        config cfg;
        runner.Check(cfg.psk.empty(), "config: 默认 psk 为空");
        runner.Check(cfg.method.empty(), "config: 默认 method 为空");
        runner.Check(cfg.enable_tcp == true, "config: 默认 enable_tcp=true");
        runner.Check(cfg.enable_udp == false, "config: 默认 enable_udp=false");
        runner.Check(cfg.timestamp_window == 30, "config: 默认 timestamp_window=30");
        runner.Check(cfg.salt_ttl == 60, "config: 默认 salt_ttl=60");
        runner.Check(cfg.idle_timeout == 60, "config: 默认 idle_timeout=60");
    }

    void TestConfigCustomValues(TestRunner &runner)
    {
        config cfg;
        cfg.psk = "dGVzdA==";
        cfg.method = "2022-blake3-aes-128-gcm";
        cfg.enable_tcp = false;
        cfg.enable_udp = true;
        cfg.timestamp_window = 120;
        cfg.salt_ttl = 300;
        cfg.idle_timeout = 180;

        runner.Check(cfg.psk == "dGVzdA==", "config: 自定义 psk");
        runner.Check(cfg.method == "2022-blake3-aes-128-gcm", "config: 自定义 method");
        runner.Check(cfg.enable_tcp == false, "config: 自定义 enable_tcp=false");
        runner.Check(cfg.enable_udp == true, "config: 自定义 enable_udp=true");
        runner.Check(cfg.timestamp_window == 120, "config: 自定义 timestamp_window=120");
        runner.Check(cfg.salt_ttl == 300, "config: 自定义 salt_ttl=300");
        runner.Check(cfg.idle_timeout == 180, "config: 自定义 idle_timeout=180");
    }

    void TestCipherMethodEnum(TestRunner &runner)
    {
        // 验证枚举值可赋值和比较
        cipher_method m = cipher_method::aes_128_gcm;
        runner.Check(m == cipher_method::aes_128_gcm, "cipher_method: aes_128_gcm");

        m = cipher_method::aes_256_gcm;
        runner.Check(m == cipher_method::aes_256_gcm, "cipher_method: aes_256_gcm");

        m = cipher_method::chacha20_poly1305;
        runner.Check(m == cipher_method::chacha20_poly1305, "cipher_method: chacha20_poly1305");
    }

    void TestRequestConstruction(TestRunner &runner)
    {
        request req;
        req.method = cipher_method::aes_256_gcm;
        req.port = 443;
        req.destination_address = ipv4_address{{1, 1, 1, 1}};

        runner.Check(req.method == cipher_method::aes_256_gcm, "request: method=aes_256_gcm");
        runner.Check(req.port == 443, "request: port=443");
        runner.Check(std::holds_alternative<ipv4_address>(req.destination_address),
                     "request: 地址类型=ipv4");
    }

    void TestRequestDefaultValues(TestRunner &runner)
    {
        request req;
        runner.Check(req.port == 0, "request: 默认 port=0");
    }

    void TestConstants(TestRunner &runner)
    {
        using psm::protocol::shadowsocks::request_type;
        using psm::protocol::shadowsocks::response_type;
        using psm::protocol::shadowsocks::aead_tag_len;
        using psm::protocol::shadowsocks::fixed_hdr_plain;
        using psm::protocol::shadowsocks::fixed_hdr_size;
        using psm::protocol::shadowsocks::len_block_size;
        using psm::protocol::shadowsocks::max_chunk_size;

        runner.Check(request_type == 0x00, "constant: request_type=0x00");
        runner.Check(response_type == 0x01, "constant: response_type=0x01");
        runner.Check(aead_tag_len == 16, "constant: aead_tag_len=16");
        runner.Check(fixed_hdr_plain == 11, "constant: fixed_hdr_plain=11");
        runner.Check(fixed_hdr_size == 27, "constant: fixed_hdr_size=27");
        runner.Check(len_block_size == 18, "constant: len_block_size=18");
        runner.Check(max_chunk_size == 0x3FFF, "constant: max_chunk_size=0x3FFF");
    }

    void TestAddressTypes(TestRunner &runner)
    {
        // IPv4 地址构造
        ipv4_address v4{{10, 0, 0, 1}};
        runner.Check(v4.bytes[0] == 10, "address: ipv4 byte 0");
        runner.Check(v4.bytes[3] == 1, "address: ipv4 byte 3");

        // IPv6 地址构造
        ipv6_address v6{};
        v6.bytes[0] = 0xFF;
        runner.Check(v6.bytes[0] == 0xFF, "address: ipv6 byte 0");

        // 域名地址构造
        domain_address domain{};
        domain.length = 3;
        std::memcpy(domain.value.data(), "com", 3);
        runner.Check(domain.length == 3, "address: domain length=3");

        // variant 地址
        address addr = v4;
        runner.Check(std::holds_alternative<ipv4_address>(addr),
                     "address: variant holds ipv4");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ShadowsocksProcessPure");

    TestConfigDefaults(runner);
    TestConfigCustomValues(runner);
    TestCipherMethodEnum(runner);
    TestRequestConstruction(runner);
    TestRequestDefaultValues(runner);
    TestConstants(runner);
    TestAddressTypes(runner);

    return runner.Summary();
}
