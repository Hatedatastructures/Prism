/**
 * @file Smux.cpp
 * @brief smux 多路复用帧编解码单元测试
 * @details 验证 psm::multiplex::smux 模块的帧编解码功能，覆盖以下场景：
 * 1. 帧头反序列化（SYN/FIN/PSH/NOP 命令）
 * 2. 地址解析（IPv4/IPv6/域名 + Flags 标志位）
 * 3. UDP 数据报与 length-prefixed 编解码往返
 * 4. 截断数据与版本不匹配的容错处理
 */

#include <prism/multiplex/smux/frame.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
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
    void log_info(const std::string_view msg)
    {
        psm::trace::info("[Smux] {}", msg);
    }

    /**
     * @brief 记录测试通过并递增计数器
     * @param msg 测试名称
     */
    void log_pass(const std::string_view msg)
    {
        ++passed;
        psm::trace::info("[Smux] PASS: {}", msg);
    }

    /**
     * @brief 记录测试失败并递增计数器
     * @param msg 失败原因
     */
    void log_fail(const std::string_view msg)
    {
        ++failed;
        psm::trace::error("[Smux] FAIL: {}", msg);
    }

    /**
     * @brief 构建 smux 协议帧的 8 字节头部
     * @param cmd 帧命令类型 (SYN/FIN/PSH/NOP)
     * @param length 载荷长度 (小端序)
     * @param stream_id 流标识符 (小端序)
     * @return 8 字节帧头数组
     */
    // 构建 smux 8 字节帧头：版本(1B) + 命令(1B) + 长度(2B LE) + 流ID(4B LE)
    [[nodiscard]] auto build_smux_frame(psm::multiplex::smux::command cmd,
                                        std::uint16_t length,
                                        std::uint32_t stream_id)
        -> std::array<std::byte, 8>
    {
        std::array<std::byte, 8> buf{};
        buf[0] = std::byte{psm::multiplex::smux::protocol_version};
        buf[1] = std::byte{static_cast<std::uint8_t>(cmd)};
        // 长度字段，小端序低字节在前
        buf[2] = std::byte{static_cast<std::uint8_t>(length & 0xFF)};
        buf[3] = std::byte{static_cast<std::uint8_t>((length >> 8) & 0xFF)};
        // 流 ID 字段，小端序逐字节写入
        buf[4] = std::byte{static_cast<std::uint8_t>(stream_id & 0xFF)};
        buf[5] = std::byte{static_cast<std::uint8_t>((stream_id >> 8) & 0xFF)};
        buf[6] = std::byte{static_cast<std::uint8_t>((stream_id >> 16) & 0xFF)};
        buf[7] = std::byte{static_cast<std::uint8_t>((stream_id >> 24) & 0xFF)};
        return buf;
    }
} // namespace

/**
 * @brief 测试 SYN 帧反序列化
 */
void TestDeserializeSyn()
{
    log_info("=== TestDeserializeSyn ===");

    namespace smux = psm::multiplex::smux;
    // 构造 SYN 帧：载荷长度 0，流 ID 为 1
    auto buf = build_smux_frame(smux::command::syn, 0, 1);
    auto result = smux::deserialization(std::span<const std::byte>{buf});

    // 反序列化必须成功
    if (!result)
    {
        log_fail("SYN deserialization returned nullopt");
        return;
    }
    // 逐一验证帧头各字段是否与构造值一致
    if (result->version != smux::protocol_version)
    {
        log_fail("SYN version mismatch");
        return;
    }
    if (result->cmd != smux::command::syn)
    {
        log_fail("SYN cmd mismatch");
        return;
    }
    if (result->length != 0)
    {
        log_fail("SYN length should be 0");
        return;
    }
    if (result->stream_id != 1)
    {
        log_fail("SYN stream_id should be 1");
        return;
    }

    log_pass("DeserializeSyn");
}

/**
 * @brief 测试 FIN 帧反序列化
 */
void TestDeserializeFin()
{
    log_info("=== TestDeserializeFin ===");

    namespace smux = psm::multiplex::smux;
    // 构造 FIN 帧：流 ID 为 5，表示关闭该流
    auto buf = build_smux_frame(smux::command::fin, 0, 5);
    auto result = smux::deserialization(std::span<const std::byte>{buf});

    if (!result)
    {
        log_fail("FIN deserialization returned nullopt");
        return;
    }
    // 验证命令类型和流 ID 正确解析
    if (result->cmd != smux::command::fin)
    {
        log_fail("FIN cmd mismatch");
        return;
    }
    if (result->stream_id != 5)
    {
        log_fail("FIN stream_id should be 5");
        return;
    }

    log_pass("DeserializeFin");
}

/**
 * @brief 测试 PSH 帧反序列化
 */
void TestDeserializePush()
{
    log_info("=== TestDeserializePush ===");

    namespace smux = psm::multiplex::smux;
    // 构造 PSH 帧：载荷长度 100，流 ID 为 2
    auto buf = build_smux_frame(smux::command::push, 100, 2);
    auto result = smux::deserialization(std::span<const std::byte>{buf});

    if (!result)
    {
        log_fail("PSH deserialization returned nullopt");
        return;
    }
    // 验证载荷长度字段正确还原
    if (result->cmd != smux::command::push)
    {
        log_fail("PSH cmd mismatch");
        return;
    }
    if (result->length != 100)
    {
        log_fail("PSH length should be 100");
        return;
    }
    if (result->stream_id != 2)
    {
        log_fail("PSH stream_id should be 2");
        return;
    }

    log_pass("DeserializePush");
}

/**
 * @brief 测试 NOP 帧反序列化
 */
void TestDeserializeNop()
{
    log_info("=== TestDeserializeNop ===");

    namespace smux = psm::multiplex::smux;
    // 构造 NOP 帧：心跳保活，无载荷、无流 ID
    auto buf = build_smux_frame(smux::command::nop, 0, 0);
    auto result = smux::deserialization(std::span<const std::byte>{buf});

    if (!result)
    {
        log_fail("NOP deserialization returned nullopt");
        return;
    }
    // NOP 帧所有业务字段应为零
    if (result->cmd != smux::command::nop)
    {
        log_fail("NOP cmd mismatch");
        return;
    }
    if (result->length != 0)
    {
        log_fail("NOP length should be 0");
        return;
    }
    if (result->stream_id != 0)
    {
        log_fail("NOP stream_id should be 0");
        return;
    }

    log_pass("DeserializeNop");
}

/**
 * @brief 测试版本不匹配时返回 nullopt
 */
void TestDeserializeVersionMismatch()
{
    log_info("=== TestDeserializeVersionMismatch ===");

    // 手工构造版本号 0xFF 的帧，模拟非法版本
    std::array<std::byte, 8> buf{};
    buf[0] = std::byte{0xFF};

    // 非法版本应导致反序列化返回 nullopt
    auto result = psm::multiplex::smux::deserialization(std::span<const std::byte>{buf});
    if (result.has_value())
    {
        log_fail("Version 0xFF should return nullopt");
        return;
    }

    log_pass("DeserializeVersionMismatch");
}

/**
 * @brief 测试截断数据时返回 nullopt
 */
void TestDeserializeTruncated()
{
    log_info("=== TestDeserializeTruncated ===");

    // 帧头需 8 字节，7 字节应被判定为截断
    std::array<std::byte, 7> short_buf{};
    auto result = psm::multiplex::smux::deserialization(std::span<const std::byte>{short_buf});
    if (result.has_value())
    {
        log_fail("7 bytes should return nullopt");
        return;
    }

    // 空数据同样应返回 nullopt
    auto result2 = psm::multiplex::smux::deserialization(std::span<const std::byte>{});
    if (result2.has_value())
    {
        log_fail("0 bytes should return nullopt");
        return;
    }

    log_pass("DeserializeTruncated");
}

/**
 * @brief 测试 IPv4 地址解析
 */
void TestParseAddressIPv4()
{
    log_info("=== TestParseAddressIPv4 ===");

    namespace smux = psm::multiplex::smux;
    psm::memory::resource_pointer mr = psm::memory::current_resource();

    // 地址缓冲区：Flags(2B BE) + 类型(1B) + IPv4(4B) + 端口(2B BE)
    // 类型 0x01=IPv4，地址 127.0.0.1，端口 80(0x0050)
    std::array<std::byte, 9> buf{};
    buf[0] = std::byte{0x00};
    buf[1] = std::byte{0x00};
    buf[2] = std::byte{0x01};
    buf[3] = std::byte{0x7F};
    buf[4] = std::byte{0x00};
    buf[5] = std::byte{0x00};
    buf[6] = std::byte{0x01};
    buf[7] = std::byte{0x00};
    buf[8] = std::byte{0x50};

    auto result = smux::parse_mux_address(std::span<const std::byte>{buf}, mr);
    if (!result)
    {
        log_fail("IPv4 parsing returned nullopt");
        return;
    }
    // 验证解析出的主机、端口、标志位
    if (result->host != "127.0.0.1")
    {
        log_fail(std::format("IPv4 host='{}', expected '127.0.0.1'", result->host));
        return;
    }
    if (result->port != 80)
    {
        log_fail(std::format("IPv4 port={}, expected 80", result->port));
        return;
    }
    // Flags=0x0000 表示 TCP 且非 PacketAddr 模式
    if (result->is_udp)
    {
        log_fail("IPv4 is_udp should be false");
        return;
    }
    if (result->packet_addr)
    {
        log_fail("IPv4 packet_addr should be false");
        return;
    }

    log_pass("ParseAddressIPv4");
}

/**
 * @brief 测试域名地址解析
 */
void TestParseAddressDomain()
{
    log_info("=== TestParseAddressDomain ===");

    namespace smux = psm::multiplex::smux;
    psm::memory::resource_pointer mr = psm::memory::current_resource();

    const std::string domain = "example.com";
    const auto domain_len = static_cast<std::uint8_t>(domain.size());

    // 地址缓冲区：Flags(2B) + 类型(1B=0x03 域名) + 长度(1B) + 域名 + 端口(2B BE)
    psm::memory::vector<std::byte> buf(mr);
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x03});
    buf.push_back(std::byte{domain_len});
    for (char c : domain)
    {
        buf.push_back(std::byte{static_cast<unsigned char>(c)});
    }
    // 端口 443(0x01BB)，大端序
    buf.push_back(std::byte{0x01});
    buf.push_back(std::byte{0xBB});

    auto result = smux::parse_mux_address(std::span<const std::byte>{buf}, mr);
    if (!result)
    {
        log_fail("Domain parsing returned nullopt");
        return;
    }
    if (result->host != "example.com")
    {
        log_fail(std::format("Domain host='{}', expected 'example.com'", result->host));
        return;
    }
    if (result->port != 443)
    {
        log_fail(std::format("Domain port={}, expected 443", result->port));
        return;
    }

    log_pass("ParseAddressDomain");
}

/**
 * @brief 测试 IPv6 地址解析
 */
void TestParseAddressIPv6()
{
    log_info("=== TestParseAddressIPv6 ===");

    namespace smux = psm::multiplex::smux;
    psm::memory::resource_pointer mr = psm::memory::current_resource();

    // 地址缓冲区：Flags(2B) + 类型(1B=0x04 IPv6) + 16B 地址 + 端口(2B BE)
    // IPv6 地址为 ::1（前 15 字节为 0，末字节为 1）
    psm::memory::vector<std::byte> buf(mr);
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x04});
    for (int i = 0; i < 15; ++i)
    {
        buf.push_back(std::byte{0x00});
    }
    buf.push_back(std::byte{0x01});
    // 端口 443(0x01BB)，大端序
    buf.push_back(std::byte{0x01});
    buf.push_back(std::byte{0xBB});

    auto result = smux::parse_mux_address(std::span<const std::byte>{buf}, mr);
    if (!result)
    {
        log_fail("IPv6 parsing returned nullopt");
        return;
    }
    if (result->host.empty())
    {
        log_fail("IPv6 host should not be empty");
        return;
    }
    if (result->port != 443)
    {
        log_fail(std::format("IPv6 port={}, expected 443", result->port));
        return;
    }

    log_pass("ParseAddressIPv6");
}

/**
 * @brief 测试 Flags 标志位解析（UDP 和 PacketAddr）
 */
void TestParseAddressFlags()
{
    log_info("=== TestParseAddressFlags ===");

    namespace smux = psm::multiplex::smux;
    psm::memory::resource_pointer mr = psm::memory::current_resource();

    // Flags=0x0001 表示 UDP 模式，非 PacketAddr
    {
        // 地址缓冲区布局同 IPv4，仅 Flags 字段不同
        std::array<std::byte, 9> buf{};
        buf[0] = std::byte{0x00};
        buf[1] = std::byte{0x01};
        buf[2] = std::byte{0x01};
        buf[3] = std::byte{0x7F};
        buf[4] = std::byte{0x00};
        buf[5] = std::byte{0x00};
        buf[6] = std::byte{0x01};
        buf[7] = std::byte{0x00};
        buf[8] = std::byte{0x50};

        auto result = smux::parse_mux_address(std::span<const std::byte>{buf}, mr);
        if (!result || !result->is_udp || result->packet_addr)
        {
            log_fail("Flags 0x0001 mismatch");
            return;
        }
    }

    // Flags=0x0002 表示 PacketAddr 模式，非 UDP
    {
        std::array<std::byte, 9> buf{};
        buf[0] = std::byte{0x00};
        buf[1] = std::byte{0x02};
        buf[2] = std::byte{0x01};
        buf[3] = std::byte{0x7F};
        buf[4] = std::byte{0x00};
        buf[5] = std::byte{0x00};
        buf[6] = std::byte{0x01};
        buf[7] = std::byte{0x00};
        buf[8] = std::byte{0x50};

        auto result = smux::parse_mux_address(std::span<const std::byte>{buf}, mr);
        if (!result || result->is_udp || !result->packet_addr)
        {
            log_fail("Flags 0x0002 mismatch");
            return;
        }
    }

    // Flags=0x0003 表示同时启用 UDP 和 PacketAddr
    {
        std::array<std::byte, 9> buf{};
        buf[0] = std::byte{0x00};
        buf[1] = std::byte{0x03};
        buf[2] = std::byte{0x01};
        buf[3] = std::byte{0x7F};
        buf[4] = std::byte{0x00};
        buf[5] = std::byte{0x00};
        buf[6] = std::byte{0x01};
        buf[7] = std::byte{0x00};
        buf[8] = std::byte{0x50};

        auto result = smux::parse_mux_address(std::span<const std::byte>{buf}, mr);
        if (!result || !result->is_udp || !result->packet_addr)
        {
            log_fail("Flags 0x0003 mismatch");
            return;
        }
    }

    log_pass("ParseAddressFlags");
}

/**
 * @brief 测试 UDP 数据报编解码往返
 */
void TestUdpDatagramRoundTrip()
{
    log_info("=== TestUdpDatagramRoundTrip ===");

    namespace smux = psm::multiplex::smux;
    psm::memory::resource_pointer mr = psm::memory::current_resource();

    // 构造 5 字节测试载荷
    const std::array<std::byte, 5> payload = {
        std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}, std::byte{0x42}};

    // 编码为 UDP 数据报格式，再解码，验证往返一致性
    auto encoded = smux::build_udp_datagram("127.0.0.1", 53, std::span<const std::byte>{payload}, mr);
    auto result = smux::parse_udp_datagram(encoded, mr);

    if (!result)
    {
        log_fail("UDP datagram round-trip returned nullopt");
        return;
    }
    // 验证地址和端口在往返中保持一致
    if (result->host != "127.0.0.1")
    {
        log_fail(std::format("UDP datagram host='{}', expected '127.0.0.1'", result->host));
        return;
    }
    if (result->port != 53)
    {
        log_fail(std::format("UDP datagram port={}, expected 53", result->port));
        return;
    }
    // 验证载荷长度和逐字节内容一致
    if (result->payload.size() != payload.size())
    {
        log_fail(std::format("UDP datagram payload size={}, expected {}", result->payload.size(), payload.size()));
        return;
    }
    // 逐字节比对载荷，确保编解码无损
    for (std::size_t i = 0; i < payload.size(); ++i)
    {
        if (result->payload[i] != payload[i])
        {
            log_fail(std::format("UDP datagram payload mismatch at byte {}", i));
            return;
        }
    }

    log_pass("UdpDatagramRoundTrip");
}

/**
 * @brief 测试 UDP length-prefixed 编解码往返
 */
void TestUdpLengthPrefixedRoundTrip()
{
    log_info("=== TestUdpLengthPrefixedRoundTrip ===");

    namespace smux = psm::multiplex::smux;
    psm::memory::resource_pointer mr = psm::memory::current_resource();

    // 构造 8 字节顺序载荷
    const std::array<std::byte, 8> payload = {
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};

    // length-prefixed 格式：长度前缀(2B BE) + 载荷
    auto encoded = smux::build_udp_length_prefixed(std::span<const std::byte>{payload}, mr);
    auto result = smux::parse_udp_length_prefixed(encoded);

    if (!result)
    {
        log_fail("UDP length-prefixed round-trip returned nullopt");
        return;
    }
    if (result->payload.size() != payload.size())
    {
        log_fail(std::format("UDP length-prefixed payload size={}, expected {}",
                             result->payload.size(), payload.size()));
        return;
    }
    for (std::size_t i = 0; i < payload.size(); ++i)
    {
        if (result->payload[i] != payload[i])
        {
            log_fail(std::format("UDP length-prefixed payload mismatch at byte {}", i));
            return;
        }
    }

    log_pass("UdpLengthPrefixedRoundTrip");
}

/**
 * @brief 测试 UDP 截断数据返回 nullopt
 */
void TestParseUdpTruncated()
{
    log_info("=== TestParseUdpTruncated ===");

    namespace smux = psm::multiplex::smux;
    psm::memory::resource_pointer mr = psm::memory::current_resource();

    // 空数据无法解析出有效地址和载荷
    auto result1 = smux::parse_udp_datagram(std::span<const std::byte>{}, mr);
    if (result1.has_value())
    {
        log_fail("Empty data should return nullopt");
        return;
    }

    // 仅 1 字节同样不足以解析地址类型
    const std::byte one = std::byte{0x01};
    auto result2 = smux::parse_udp_datagram(std::span<const std::byte>{&one, 1}, mr);
    if (result2.has_value())
    {
        log_fail("1 byte should return nullopt");
        return;
    }

    log_pass("ParseUdpTruncated");
}

/**
 * @brief 测试地址解析截断数据返回 nullopt
 */
void TestParseAddressTruncated()
{
    log_info("=== TestParseAddressTruncated ===");

    namespace smux = psm::multiplex::smux;
    psm::memory::resource_pointer mr = psm::memory::current_resource();

    // 6 字节不足以容纳最小地址格式（Flags+类型+端口=5B，至少还需 1B 地址）
    std::array<std::byte, 6> short_buf{};
    auto result1 = smux::parse_mux_address(std::span<const std::byte>{short_buf}, mr);
    if (result1.has_value())
    {
        log_fail("6 bytes should return nullopt");
        return;
    }

    // 空数据应返回 nullopt
    auto result2 = smux::parse_mux_address(std::span<const std::byte>{}, mr);
    if (result2.has_value())
    {
        log_fail("Empty data should return nullopt");
        return;
    }

    log_pass("ParseAddressTruncated");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，运行 smux 帧反序列化、地址解析、
 *          UDP 数据报导编解码等全部测试用例，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化 PMR 全局内存池和日志系统
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    log_info("Starting smux tests...");

    // 帧头反序列化测试：覆盖四种命令类型
    TestDeserializeSyn();
    TestDeserializeFin();
    TestDeserializePush();
    TestDeserializeNop();
    // 容错测试：非法版本号和截断数据
    TestDeserializeVersionMismatch();
    TestDeserializeTruncated();
    // 地址解析测试：IPv4/域名/IPv6/标志位
    TestParseAddressIPv4();
    TestParseAddressDomain();
    TestParseAddressIPv6();
    TestParseAddressFlags();
    // UDP 数据报编解码往返测试
    TestUdpDatagramRoundTrip();
    TestUdpLengthPrefixedRoundTrip();
    // UDP 和地址解析截断容错测试
    TestParseUdpTruncated();
    TestParseAddressTruncated();

    log_info("Smux tests completed.");

    psm::trace::info("[Smux] Results: {} passed, {} failed", passed, failed);

    return failed > 0 ? 1 : 0;
}
