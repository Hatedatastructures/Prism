/**
 * @file DnsPacket.cpp
 * @brief DNS 报文编解码单元测试
 * @details 测试 psm::resolve::message 的序列化/反序列化、
 * IPv4/IPv6 地址提取、TTL 计算以及 TCP 帧封装等功能。
 * 覆盖以下测试用例：
 * 1. 构造递归查询报文 (TestMakeQuery)
 * 2. Pack/Unpack 往返一致性 (TestPackUnpackRoundTrip)
 * 3. IPv4 地址提取 (TestExtractIPv4)
 * 4. IPv6 地址提取 (TestExtractIPv6)
 * 5. IPv4 错误长度处理 (TestExtractIPv4BadLength)
 * 6. 批量 IP 地址提取 (TestExtractIPs)
 * 7. 最小 TTL 计算 (TestMinTtl)
 * 8. TCP 帧封装与解析 (TestPackUnpackTcp)
 */

#include <prism/memory.hpp>
#include <prism/resolve/packet.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstdint>
#include <optional>
#include <string_view>

namespace net = boost::asio;

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
        psm::trace::info("[DnsPacket] {}", msg);
    }

    /**
     * @brief 记录测试通过并递增计数器
     * @param msg 测试名称
     */
    void LogPass(const std::string_view msg)
    {
        ++passed;
        psm::trace::info("[DnsPacket] PASS: {}", msg);
    }

    /**
     * @brief 记录测试失败并递增计数器
     * @param msg 失败原因
     */
    void LogFail(const std::string_view msg)
    {
        ++failed;
        psm::trace::error("[DnsPacket] FAIL: {}", msg);
    }
} // namespace

/**
 * @brief 测试构造递归查询报文
 */
void TestMakeQuery()
{
    LogInfo("=== Testing make_query ===");

    // 获取当前线程的 PMR 资源，用于临时分配
    psm::memory::resource_pointer mr = psm::memory::current_resource();

    // 构造 A 记录递归查询
    auto msg = psm::resolve::message::make_query("example.com", psm::resolve::qtype::a, mr);

    // id 初始为 0，由上层分配实际事务 ID
    if (msg.id != 0)
    {
        LogFail("id should be 0 (unassigned)");
        return;
    }

    // rd=1 表示请求递归解析
    if (!msg.rd)
    {
        LogFail("rd should be true (recursion desired)");
        return;
    }

    // qr=0 表示这是查询报文
    if (msg.qr)
    {
        LogFail("qr should be false (query, not response)");
        return;
    }

    // 应恰好包含一个问题段
    if (msg.questions.size() != 1)
    {
        LogFail("questions.size() should be 1");
        return;
    }

    // 问题段域名应与输入一致
    if (msg.questions[0].name != "example.com")
    {
        LogFail("question name should be 'example.com'");
        return;
    }

    // 查询类型应为 A (IPv4)
    if (msg.questions[0].qtype != psm::resolve::qtype::a)
    {
        LogFail("question qtype should be A (1)");
        return;
    }

    LogPass("make_query");
}

/**
 * @brief 测试 Pack/Unpack 往返一致性
 */
void TestPackUnpackRoundTrip()
{
    LogInfo("=== Testing pack/unpack round trip ===");

    psm::memory::resource_pointer mr = psm::memory::current_resource();

    // === 测试查询报文的序列化/反序列化往返 ===
    {
        auto original = psm::resolve::message::make_query("example.com", psm::resolve::qtype::a, mr);
        // 序列化为线格式字节流
        auto wire = original.pack();

        auto opt = psm::resolve::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        if (!opt)
        {
            LogFail("unpack query returned nullopt");
            return;
        }

        // 从线格式恢复后的报文
        auto &restored = *opt;

        if (restored.id != original.id)
        {
            LogFail("query: id mismatch after round trip");
            return;
        }

        if (!restored.rd)
        {
            LogFail("query: rd should be true after round trip");
            return;
        }

        if (restored.questions.size() != 1 || restored.questions[0].name != "example.com")
        {
            LogFail("query: question name mismatch after round trip");
            return;
        }

        if (restored.questions[0].qtype != psm::resolve::qtype::a)
        {
            LogFail("query: question qtype mismatch after round trip");
            return;
        }
    }

    // === 测试带应答记录的响应报文往返 ===
    {
        psm::resolve::message msg(mr);
        msg.id = 0x1234;  // 事务 ID
        msg.qr = true;     // 响应标志
        msg.rd = true;     // 递归请求已被设置
        msg.ra = true;     // 递归可用

        // 构造问题段
        psm::resolve::question q(mr);
        q.name = "example.com";
        q.qtype = psm::resolve::qtype::a;
        msg.questions.push_back(std::move(q));

        // 构造应答记录：example.com → 8.8.8.8，TTL=300 秒
        psm::resolve::record ans(mr);
        ans.name = "example.com";
        ans.type = psm::resolve::qtype::a;
        ans.ttl = 300;
        // rdata 为 4 字节 IPv4 地址 8.8.8.8
        ans.rdata = {8, 8, 8, 8};
        msg.answers.push_back(std::move(ans));

        auto wire = msg.pack();

        // 从线格式恢复响应报文
        auto opt = psm::resolve::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        if (!opt)
        {
            LogFail("unpack response returned nullopt");
            return;
        }

        auto &restored = *opt;

        // 验证事务 ID 在往返中保持一致
        if (restored.id != 0x1234)
        {
            LogFail("response: id mismatch");
            return;
        }

        // qr 标志应为响应
        if (!restored.qr)
        {
            LogFail("response: qr should be true");
            return;
        }

        // 应答段数量
        if (restored.answers.size() != 1)
        {
            LogFail("response: answers count mismatch");
            return;
        }

        // 应答记录域名
        if (restored.answers[0].name != "example.com")
        {
            LogFail("response: answer name mismatch");
            return;
        }

        // 应答记录类型
        if (restored.answers[0].type != psm::resolve::qtype::a)
        {
            LogFail("response: answer type mismatch");
            return;
        }

        // TTL 值
        if (restored.answers[0].ttl != 300)
        {
            LogFail("response: answer TTL mismatch");
            return;
        }

        // rdata 应为 4 字节的 8.8.8.8
        if (restored.answers[0].rdata.size() != 4 ||
            restored.answers[0].rdata[0] != 8 ||
            restored.answers[0].rdata[1] != 8 ||
            restored.answers[0].rdata[2] != 8 ||
            restored.answers[0].rdata[3] != 8)
        {
            LogFail("response: answer rdata mismatch");
            return;
        }
    }

    LogPass("pack/unpack round trip");
}

/**
 * @brief 测试 IPv4 地址提取
 */
void TestExtractIPv4()
{
    LogInfo("=== Testing extract_ipv4 ===");

    // 测试公网地址 8.8.8.8（Google DNS）
    {
        psm::memory::resource_pointer mr = psm::memory::current_resource();
        psm::resolve::record rec(mr);
        rec.type = psm::resolve::qtype::a;
        // 4 字节 rdata 对应 IPv4 地址
        rec.rdata = {8, 8, 8, 8};

        auto result = psm::resolve::extract_ipv4(rec);
        if (!result)
        {
            LogFail("extract_ipv4 returned nullopt for 8.8.8.8");
            return;
        }

        auto expected = net::ip::make_address_v4("8.8.8.8");
        // 通过 uint 比较确保数值一致
        if (result->to_uint() != expected.to_uint())
        {
            LogFail("extract_ipv4: 8.8.8.8 mismatch");
            return;
        }
    }

    // 测试私有地址 192.168.1.1
    {
        psm::memory::resource_pointer mr = psm::memory::current_resource();
        psm::resolve::record rec(mr);
        rec.type = psm::resolve::qtype::a;
        rec.rdata = {192, 168, 1, 1};

        auto result = psm::resolve::extract_ipv4(rec);
        if (!result)
        {
            LogFail("extract_ipv4 returned nullopt for 192.168.1.1");
            return;
        }

        auto expected = net::ip::make_address_v4("192.168.1.1");
        if (result->to_uint() != expected.to_uint())
        {
            LogFail("extract_ipv4: 192.168.1.1 mismatch");
            return;
        }
    }

    LogPass("extract_ipv4");
}

/**
 * @brief 测试 IPv6 地址提取
 */
void TestExtractIPv6()
{
    LogInfo("=== Testing extract_ipv6 ===");

    psm::memory::resource_pointer mr = psm::memory::current_resource();
    psm::resolve::record rec(mr);
    rec.type = psm::resolve::qtype::aaaa;
    // IPv6 环回地址 ::1 = 15 字节零 + 末字节 1（共 16 字节）
    rec.rdata = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    auto result = psm::resolve::extract_ipv6(rec);
    if (!result)
    {
        LogFail("extract_ipv6 returned nullopt for ::1");
        return;
    }

    // 通过字节序列比较验证 IPv6 地址
    auto expected = net::ip::make_address_v6("::1");
    if (result->to_bytes() != expected.to_bytes())
    {
        LogFail("extract_ipv6: ::1 mismatch");
        return;
    }

    LogPass("extract_ipv6");
}

/**
 * @brief 测试 IPv4 错误长度处理
 */
void TestExtractIPv4BadLength()
{
    LogInfo("=== Testing extract_ipv4 with bad lengths ===");

    psm::memory::resource_pointer mr = psm::memory::current_resource();

    // rdata 仅 3 字节，不足 IPv4 所需的 4 字节
    {
        psm::resolve::record rec(mr);
        rec.rdata = {1, 2, 3};

        auto result = psm::resolve::extract_ipv4(rec);
        if (result.has_value())
        {
            LogFail("extract_ipv4 should return nullopt for 3-byte rdata");
            return;
        }
    }

    // rdata 有 5 字节，超出 IPv4 长度
    {
        psm::resolve::record rec(mr);
        rec.rdata = {1, 2, 3, 4, 5};

        auto result = psm::resolve::extract_ipv4(rec);
        if (result.has_value())
        {
            LogFail("extract_ipv4 should return nullopt for 5-byte rdata");
            return;
        }
    }

    LogPass("extract_ipv4 bad length");
}

/**
 * @brief 测试批量 IP 地址提取
 */
void TestExtractIPs()
{
    LogInfo("=== Testing extract_ips ===");

    psm::memory::resource_pointer mr = psm::memory::current_resource();
    psm::resolve::message msg(mr);

    // A 记录：Cloudflare DNS 1.1.1.1（4 字节 rdata）
    {
        psm::resolve::record rec(mr);
        rec.name = "example.com";
        rec.type = psm::resolve::qtype::a;
        rec.ttl = 300;
        rec.rdata = {1, 1, 1, 1};
        msg.answers.push_back(std::move(rec));
    }

    // AAAA 记录：IPv6 环回地址 ::1（16 字节 rdata）
    {
        psm::resolve::record rec(mr);
        rec.name = "example.com";
        rec.type = psm::resolve::qtype::aaaa;
        rec.ttl = 300;
        rec.rdata = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        msg.answers.push_back(std::move(rec));
    }

    // 批量提取所有 A/AAAA 记录的 IP 地址
    auto ips = msg.extract_ips();
    if (ips.size() != 2)
    {
        LogFail("extract_ips should return 2 addresses");
        return;
    }

    LogPass("extract_ips");
}

/**
 * @brief 测试最小 TTL 计算
 */
void TestMinTtl()
{
    LogInfo("=== Testing min_ttl ===");

    psm::memory::resource_pointer mr = psm::memory::current_resource();

    // 三条记录，TTL 分别为 300、600、60，取最小值
    {
        psm::resolve::message msg(mr);

        psm::resolve::record r1(mr);
        r1.ttl = 300;
        msg.answers.push_back(std::move(r1));

        psm::resolve::record r2(mr);
        r2.ttl = 600;
        msg.answers.push_back(std::move(r2));

        psm::resolve::record r3(mr);
        r3.ttl = 60;
        msg.answers.push_back(std::move(r3));

        // 最小 TTL 为 60 秒
        if (msg.min_ttl() != 60)
        {
            LogFail("min_ttl should be 60, got " + std::to_string(msg.min_ttl()));
            return;
        }
    }

    // 单条记录，TTL=3600（1 小时）
    {
        psm::resolve::message msg(mr);

        psm::resolve::record r(mr);
        r.ttl = 3600;
        msg.answers.push_back(std::move(r));

        if (msg.min_ttl() != 3600)
        {
            LogFail("min_ttl should be 3600 for single record");
            return;
        }
    }

    LogPass("min_ttl");
}

/**
 * @brief 测试 TCP 帧解析 (unpack_tcp)
 */
void TestPackUnpackTcp()
{
    LogInfo("=== Testing unpack_tcp ===");

    psm::memory::resource_pointer mr = psm::memory::current_resource();

    auto original = psm::resolve::message::make_query("test.org", psm::resolve::qtype::aaaa, mr);
    auto wire = original.pack();

    // 手动构建 TCP 帧：2 字节大端长度前缀 + DNS 线格式数据
    psm::memory::vector<std::uint8_t> tcp_frame(mr);
    const auto wire_size = static_cast<std::uint16_t>(wire.size());
    // 高字节（大端序）
    tcp_frame.push_back(static_cast<std::uint8_t>((wire_size >> 8) & 0xFF));
    // 低字节
    tcp_frame.push_back(static_cast<std::uint8_t>(wire_size & 0xFF));
    // 追加 DNS 报文体
    tcp_frame.insert(tcp_frame.end(), wire.begin(), wire.end());

    // 解析 TCP 帧，分离长度前缀后还原报文
    auto opt = psm::resolve::unpack_tcp(
        std::span<const std::uint8_t>(tcp_frame.data(), tcp_frame.size()), mr);
    if (!opt)
    {
        LogFail("unpack_tcp returned nullopt");
        return;
    }

    auto &restored = *opt;

    if (restored.id != original.id)
    {
        LogFail("TCP round trip: id mismatch");
        return;
    }

    if (restored.questions.size() != original.questions.size())
    {
        LogFail("TCP round trip: question count mismatch");
        return;
    }

    if (restored.questions[0].name != "test.org")
    {
        LogFail("TCP round trip: question name mismatch");
        return;
    }

    if (restored.questions[0].qtype != psm::resolve::qtype::aaaa)
    {
        LogFail("TCP round trip: question qtype mismatch");
        return;
    }

    LogPass("unpack_tcp");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行 DNS 报文构造、Pack/Unpack 往返一致性、
 * IPv4/IPv6 地址提取、错误长度处理、批量 IP 提取、最小 TTL 计算及 TCP 帧封装解析等测试用例，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化全局 PMR 内存池
    psm::memory::system::enable_global_pooling();
    // 初始化日志系统
    psm::trace::init({});

    LogInfo("Starting DNS packet tests...");

    TestMakeQuery();
    TestPackUnpackRoundTrip();
    TestExtractIPv4();
    TestExtractIPv6();
    TestExtractIPv4BadLength();
    TestExtractIPs();
    TestMinTtl();
    TestPackUnpackTcp();

    LogInfo("DNS packet tests completed.");

    psm::trace::info("[DnsPacket] Results: {} passed, {} failed", passed, failed);

    return failed > 0 ? 1 : 0;
}
