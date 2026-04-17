/**
 * @file Regression.cpp
 * @brief 回归测试：验证关键修复点
 * @details 测试以下关键修复：
 * 1. IPv6 host:port 解析 (analysis::resolve)
 * 2. TLS 内层协议探测 (analysis::detect_tls)
 * 3. Trojan lease 持有和释放 (account::directory)
 */

#include <prism/protocol/analysis.hpp>
#include <prism/agent/account/directory.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <string>
#include <string_view>

namespace
{
    int passed = 0;
    int failed = 0;

    /**
     * @brief 输出信息级别日志
     * @param msg 日志消息
     */
    void LogInfo(const std::string_view msg)
    {
        psm::trace::info("[Regression] {}", msg);
    }

    /**
     * @brief 记录测试通过并递增计数器
     * @param msg 测试名称
     */
    void LogPass(const std::string_view msg)
    {
        ++passed;
        psm::trace::info("[Regression] PASS: {}", msg);
    }

    /**
     * @brief 记录测试失败并递增计数器
     * @param msg 失败原因
     */
    void LogFail(const std::string_view msg)
    {
        ++failed;
        psm::trace::error("[Regression] FAIL: {}", msg);
    }
} // namespace

/**
 * @brief 测试 IPv6 host:port 解析
 */
void TestIPv6Parsing()
{
    LogInfo("=== TestIPv6Parsing ===");

    // 回归背景：早期 resolve 无法正确剥离 IPv6 方括号
    psm::memory::resource_pointer mr = psm::memory::current_resource();

    // 封装解析逻辑，返回 {host, port} 便于断言
    auto parse = [&](const std::string_view input) -> std::pair<psm::memory::string, psm::memory::string>
    {
        psm::protocol::analysis::target t = psm::protocol::analysis::resolve(input, mr);
        return {t.host, t.port};
    };

    // IPv6 回环地址，方括号应被正确剥离
    {
        auto [h, p] = parse("[::1]:443");
        if (h != "::1" || p != "443")
        {
            LogFail("[::1]:443 parsing");
            return;
        }
    }

    // 含全局单播前缀的 IPv6 地址
    {
        auto [h, p] = parse("[2001:db8::1]:8080");
        if (h != "2001:db8::1" || p != "8080")
        {
            LogFail("[2001:db8::1]:8080 parsing");
            return;
        }
    }

    // 链路本地 IPv6 地址
    {
        auto [h, p] = parse("[fe80::1]:443");
        if (h != "fe80::1" || p != "443")
        {
            LogFail("[fe80::1]:443 parsing");
            return;
        }
    }

    // 普通域名应不受影响
    {
        auto [h, p] = parse("example.com:8080");
        if (h != "example.com" || p != "8080")
        {
            LogFail("example.com:8080 parsing");
            return;
        }
    }

    // IPv4 地址应正常解析
    {
        auto [h, p] = parse("192.168.1.1:443");
        if (h != "192.168.1.1" || p != "443")
        {
            LogFail("192.168.1.1:443 parsing");
            return;
        }
    }

    LogPass("IPv6Parsing");
}

/**
 * @brief 测试 TLS 内层协议探测
 */
void TestInnerProtocolDetection()
{
    LogInfo("=== TestInnerProtocolDetection ===");

    // 回归背景：TLS 隧道建立后需探测内层协议类型

    // 完整 HTTP 请求应被识别为 HTTP 协议
    {
        std::string http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        auto result = psm::protocol::analysis::detect_tls(http_request);
        if (result != psm::protocol::protocol_type::http)
        {
            LogFail("HTTP detection");
            return;
        }
    }

    // 部分数据也能通过前缀 "GET " 识别为 HTTP
    {
        std::string partial_data = "GET ";
        auto result = psm::protocol::analysis::detect_tls(partial_data);
        if (result != psm::protocol::protocol_type::http)
        {
            LogFail("partial HTTP detection");
            return;
        }
    }

    // 数据过短且无已知前缀，返回 unknown（等待更多数据）
    {
        std::string short_data(30, 'a');
        auto result = psm::protocol::analysis::detect_tls(short_data);
        if (result != psm::protocol::protocol_type::unknown)
        {
            LogFail("short data should be unknown (insufficient for detection)");
            return;
        }
    }

    // 60+ 字节无已知前缀，排除法回退为 shadowsocks
    {
        std::string long_data(70, 'b');
        auto result = psm::protocol::analysis::detect_tls(long_data);
        if (result != psm::protocol::protocol_type::shadowsocks)
        {
            LogFail("long unrecognized data should be shadowsocks (exclusion fallback)");
            return;
        }
    }

    // 模拟 Trojan 协议特征：56 字节哈希 + \r\n + CRLF
    {
        std::string trojan_like(60, 'a');
        trojan_like[56] = '\r';
        trojan_like[57] = '\n';
        trojan_like[58] = 0x01;
        trojan_like[59] = 0x01;
        auto result = psm::protocol::analysis::detect_tls(trojan_like);
        if (result != psm::protocol::protocol_type::trojan)
        {
            LogFail("Trojan detection");
            return;
        }
    }

    // 同样长度但 CRLF 位置不是有效 Trojan 格式，排除法回退为 shadowsocks
    {
        std::string invalid_trojan(60, 'a');
        invalid_trojan[56] = 'x';
        auto result = psm::protocol::analysis::detect_tls(invalid_trojan);
        if (result != psm::protocol::protocol_type::shadowsocks)
        {
            LogFail("invalid Trojan should be shadowsocks (exclusion fallback)");
            return;
        }
    }

    LogPass("InnerProtocolDetection");
}

/**
 * @brief 测试 Trojan lease 持有和释放
 */
void TestTrojanLease()
{
    LogInfo("=== TestTrojanLease ===");

    // 回归背景：早期 lease 析构时未正确递减活跃连接数
    psm::agent::account::directory dir;
    // 插入凭据，最大并发连接数限制为 2
    dir.upsert("test_credential", 2);

    {
        // 获取第一个 lease，应成功
        auto lease1 = psm::agent::account::try_acquire(dir, "test_credential");
        if (!lease1)
        {
            LogFail("first lease acquire");
            return;
        }

        // 活跃连接数应递增为 1
        auto entry = dir.find("test_credential");
        if (!entry || entry->active_connections.load() != 1)
        {
            LogFail("active connections after first lease");
            return;
        }

        // 获取第二个 lease，未达上限，应成功
        auto lease2 = psm::agent::account::try_acquire(dir, "test_credential");
        if (!lease2)
        {
            LogFail("second lease acquire");
            return;
        }

        // 活跃连接数应递增为 2
        if (entry->active_connections.load() != 2)
        {
            LogFail("active connections after second lease");
            return;
        }

        // 超过并发限制，第三次获取应失败
        auto lease3 = psm::agent::account::try_acquire(dir, "test_credential");
        if (lease3)
        {
            LogFail("third lease should fail (limit=2)");
            return;
        }
    }

    // 所有 lease 离开作用域后，活跃连接数应归零
    auto entry = dir.find("test_credential");
    if (!entry || entry->active_connections.load() != 0)
    {
        LogFail("active connections should be 0 after release");
        return;
    }

    LogPass("TrojanLease");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，运行回归场景测试，覆盖 IPv6 host:port 解析、
 * TLS 内层协议探测以及 Trojan lease 持有与释放等关键修复点的验证，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化 PMR 全局内存池
    psm::memory::system::enable_global_pooling();
    // 初始化日志系统
    psm::trace::init({});

    LogInfo("Starting regression tests...");

    TestIPv6Parsing();
    TestInnerProtocolDetection();
    TestTrojanLease();

    LogInfo("Regression tests completed.");

    psm::trace::info("[Regression] Results: {} passed, {} failed", passed, failed);

    return failed > 0 ? 1 : 0;
}
