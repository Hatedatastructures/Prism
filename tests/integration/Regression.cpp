/**
 * @file Regression.cpp
 * @brief 回归测试：验证关键修复点
 * @details 测试以下关键修复：
 * 1. IPv6 host:port 解析 (recognition::resolve)
 * 2. TLS 内层协议探测 (recognition::probe::detect_tls)
 * 3. Trojan lease 持有和释放 (account::directory)
 */

#include <prism/proto/protocol/types.hpp>
#include <prism/proto/protocol/common/target.hpp>
#include <prism/stealth/recognition/target.hpp>
#include <prism/stealth/recognition/probe/analyzer.hpp>
#include <prism/account/directory.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include <string>
#include <string_view>

/**
 * @brief 测试 IPv6 host:port 解析
 */
TEST(Regression, IPv6Parsing)
{
    psm::memory::resource_pointer mr = psm::memory::current_resource();

    // 封装解析逻辑，返回 {host, port} 便于断言
    auto parse = [&](const std::string_view input) -> std::pair<psm::memory::string, psm::memory::string>
    {
        psm::protocol::target t = psm::recognition::resolve(input, mr);
        return {t.host, t.port};
    };

    // IPv6 回环地址，方括号应被正确剥离
    {
        auto [h, p] = parse("[::1]:443");
        EXPECT_TRUE(h == "::1") << "[::1]:443 host";
        EXPECT_TRUE(p == "443") << "[::1]:443 port";
    }

    // 含全局单播前缀的 IPv6 地址
    {
        auto [h, p] = parse("[2001:db8::1]:8080");
        EXPECT_TRUE(h == "2001:db8::1") << "[2001:db8::1]:8080 host";
        EXPECT_TRUE(p == "8080") << "[2001:db8::1]:8080 port";
    }

    // 链路本地 IPv6 地址
    {
        auto [h, p] = parse("[fe80::1]:443");
        EXPECT_TRUE(h == "fe80::1") << "[fe80::1]:443 host";
        EXPECT_TRUE(p == "443") << "[fe80::1]:443 port";
    }

    // 普通域名应不受影响
    {
        auto [h, p] = parse("example.com:8080");
        EXPECT_TRUE(h == "example.com") << "example.com:8080 host";
        EXPECT_TRUE(p == "8080") << "example.com:8080 port";
    }

    // IPv4 地址应正常解析
    {
        auto [h, p] = parse("192.168.1.1:443");
        EXPECT_TRUE(h == "192.168.1.1") << "192.168.1.1:443 host";
        EXPECT_TRUE(p == "443") << "192.168.1.1:443 port";
    }
}

/**
 * @brief 测试 TLS 内层协议探测
 */
TEST(Regression, InnerProtocolDetection)
{
    // 完整 HTTP 请求应被识别为 HTTP 协议
    {
        std::string http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        auto result = psm::recognition::probe::detect_tls(http_request);
        EXPECT_TRUE(result == psm::protocol::protocol_type::http)
            << "HTTP detection";
    }

    // 部分数据也能通过前缀 "GET " 识别为 HTTP
    {
        std::string partial_data = "GET ";
        auto result = psm::recognition::probe::detect_tls(partial_data);
        EXPECT_TRUE(result == psm::protocol::protocol_type::http)
            << "partial HTTP detection";
    }

    // 数据过短且无已知前缀，返回 unknown（等待更多数据）
    {
        std::string short_data(30, 'a');
        auto result = psm::recognition::probe::detect_tls(short_data);
        EXPECT_TRUE(result == psm::protocol::protocol_type::unknown)
            << "short data should be unknown (insufficient for detection)";
    }

    // 60+ 字节无已知前缀，返回 unknown（调用者决定 fallback）
    {
        std::string long_data(70, 'b');
        auto result = psm::recognition::probe::detect_tls(long_data);
        EXPECT_TRUE(result == psm::protocol::protocol_type::unknown)
            << "long unrecognized data should be unknown";
    }

    // 模拟 Trojan 协议特征：56 字节哈希 + \r\n + CRLF
    {
        std::string trojan_like(60, 'a');
        trojan_like[56] = '\r';
        trojan_like[57] = '\n';
        trojan_like[58] = 0x01;
        trojan_like[59] = 0x01;
        auto result = psm::recognition::probe::detect_tls(trojan_like);
        EXPECT_TRUE(result == psm::protocol::protocol_type::trojan)
            << "Trojan detection";
    }

    // 同样长度但 CRLF 位置不是有效 Trojan 格式，返回 unknown
    {
        std::string invalid_trojan(60, 'a');
        invalid_trojan[56] = 'x';
        auto result = psm::recognition::probe::detect_tls(invalid_trojan);
        EXPECT_TRUE(result == psm::protocol::protocol_type::unknown)
            << "invalid Trojan should be unknown";
    }
}

/**
 * @brief 测试 Trojan lease 持有和释放
 */
TEST(Regression, TrojanLease)
{
    psm::account::directory dir;
    // 插入凭据，最大并发连接数限制为 2
    dir.upsert("test_credential", 2);

    {
        // 获取第一个 lease，应成功
        auto lease1 = psm::account::try_acquire(dir, "test_credential");
        ASSERT_TRUE(lease1) << "first lease acquire";

        // 活跃连接数应递增为 1
        auto entry = dir.find("test_credential");
        ASSERT_TRUE(entry) << "entry exists";
        EXPECT_TRUE(entry->active_connections.load() == 1) << "active connections after first lease";

        // 获取第二个 lease，未达上限，应成功
        auto lease2 = psm::account::try_acquire(dir, "test_credential");
        ASSERT_TRUE(lease2) << "second lease acquire";

        // 活跃连接数应递增为 2
        EXPECT_TRUE(entry->active_connections.load() == 2) << "active connections after second lease";

        // 超过并发限制，第三次获取应失败
        auto lease3 = psm::account::try_acquire(dir, "test_credential");
        EXPECT_TRUE(!lease3) << "third lease should fail (limit=2)";
    }

    // 所有 lease 离开作用域后，活跃连接数应归零
    auto entry = dir.find("test_credential");
    ASSERT_TRUE(entry) << "entry exists after release";
    EXPECT_TRUE(entry->active_connections.load() == 0) << "active connections should be 0 after release";
}
