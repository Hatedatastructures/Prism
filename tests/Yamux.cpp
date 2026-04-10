/**
 * @file Yamux.cpp
 * @brief yamux 多路复用帧编解码单元测试
 * @details 验证 psm::multiplex::yamux 模块的帧编解码功能，覆盖以下场景：
 * 1. 帧头编解码往返（Data/WindowUpdate/Ping/GoAway）
 * 2. 特殊帧构建（WindowUpdate/Ping/GoAway）
 * 3. 会话级帧判断、标志位操作与大端字节序验证
 * 4. 截断数据与版本不匹配的容错处理
 */

#include <prism/multiplex/yamux/frame.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
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
        psm::trace::info("[Yamux] {}", msg);
    }

    /**
     * @brief 记录测试通过并递增计数器
     * @param msg 测试名称
     */
    void log_pass(const std::string_view msg)
    {
        ++passed;
        psm::trace::info("[Yamux] PASS: {}", msg);
    }

    /**
     * @brief 记录测试失败并递增计数器
     * @param msg 失败原因
     */
    void log_fail(const std::string_view msg)
    {
        ++failed;
        psm::trace::error("[Yamux] FAIL: {}", msg);
    }
} // namespace

/**
 * @brief 测试帧头编解码往返，覆盖所有 4 种消息类型
 */
void TestBuildParseHeaderRoundTrip()
{
    log_info("=== TestBuildParseHeaderRoundTrip ===");

    namespace yamux = psm::multiplex::yamux;

    // 遍历所有 4 种消息类型，验证编解码往返一致性
    const yamux::message_type types[] = {
        yamux::message_type::data,
        yamux::message_type::window_update,
        yamux::message_type::ping,
        yamux::message_type::go_away,
    };

    for (const auto msg_type : types)
    {
        // 构造帧头：统一使用 SYN 标志、流 ID=1、长度=100
        yamux::frame_header hdr{};
        hdr.version = yamux::protocol_version;
        hdr.type = msg_type;
        hdr.flag = yamux::flags::syn;
        hdr.stream_id = 1;
        hdr.length = 100;

        // 编码为 12 字节大端序帧头，再解析回来
        auto encoded = yamux::build_header(hdr);
        auto result = yamux::parse_header(encoded);

        if (!result)
        {
            log_fail(std::format("Round-trip returned nullopt for message_type={}",
                                 static_cast<int>(msg_type)));
            return;
        }
        // 逐一验证各字段在编解码后保持不变
        if (result->version != hdr.version)
        {
            log_fail(std::format("Version mismatch for message_type={}", static_cast<int>(msg_type)));
            return;
        }
        if (result->type != hdr.type)
        {
            log_fail(std::format("Type mismatch for message_type={}", static_cast<int>(msg_type)));
            return;
        }
        if (result->flag != hdr.flag)
        {
            log_fail(std::format("Flag mismatch for message_type={}", static_cast<int>(msg_type)));
            return;
        }
        if (result->stream_id != hdr.stream_id)
        {
            log_fail(std::format("StreamID mismatch for message_type={}", static_cast<int>(msg_type)));
            return;
        }
        if (result->length != hdr.length)
        {
            log_fail(std::format("Length mismatch for message_type={}", static_cast<int>(msg_type)));
            return;
        }
    }

    log_pass("BuildParseHeaderRoundTrip");
}

/**
 * @brief 测试版本不匹配时返回 nullopt
 */
void TestParseHeaderVersionMismatch()
{
    log_info("=== TestParseHeaderVersionMismatch ===");

    // yamux 帧头 12 字节：版本(1B) + 类型(1B) + 标志(2B BE) + 流ID(4B BE) + 长度(4B BE)
    // 首字节设为非法版本 0xFF
    std::array<std::byte, 12> buf{};
    buf[0] = std::byte{0xFF};
    for (std::size_t i = 1; i < 12; ++i)
    {
        buf[i] = std::byte{0x00};
    }

    // 非法版本应导致解析返回 nullopt
    auto result = psm::multiplex::yamux::parse_header(std::span<const std::byte>{buf});
    if (result.has_value())
    {
        log_fail("Version 0xFF should return nullopt");
        return;
    }

    log_pass("ParseHeaderVersionMismatch");
}

/**
 * @brief 测试截断数据时返回 nullopt
 */
void TestParseHeaderTruncated()
{
    log_info("=== TestParseHeaderTruncated ===");

    // 帧头需 12 字节，11 字节应被判定为截断
    std::array<std::byte, 11> short_buf{};
    auto result = psm::multiplex::yamux::parse_header(std::span<const std::byte>{short_buf});
    if (result.has_value())
    {
        log_fail("11 bytes should return nullopt");
        return;
    }

    // 空数据同样应返回 nullopt
    auto result2 = psm::multiplex::yamux::parse_header(std::span<const std::byte>{});
    if (result2.has_value())
    {
        log_fail("0 bytes should return nullopt");
        return;
    }

    log_pass("ParseHeaderTruncated");
}

/**
 * @brief 测试 WindowUpdate 帧构建与解析
 */
void TestBuildWindowUpdateFrame()
{
    log_info("=== TestBuildWindowUpdateFrame ===");

    namespace yamux = psm::multiplex::yamux;

    // 构造 WindowUpdate 帧：ACK 标志、流 ID=42、窗口增量=32768
    auto encoded = yamux::build_window_update_frame(yamux::flags::ack, 42, 32768);
    auto result = yamux::parse_header(encoded);

    if (!result)
    {
        log_fail("WindowUpdate frame parsing returned nullopt");
        return;
    }
    // 验证类型、流 ID 和窗口增量值
    if (result->type != yamux::message_type::window_update)
    {
        log_fail("WindowUpdate type mismatch");
        return;
    }
    if (result->stream_id != 42)
    {
        log_fail(std::format("WindowUpdate stream_id={}, expected 42", result->stream_id));
        return;
    }
    // length 字段在此处承载窗口增量值
    if (result->length != 32768)
    {
        log_fail(std::format("WindowUpdate length={}, expected 32768", result->length));
        return;
    }

    log_pass("BuildWindowUpdateFrame");
}

/**
 * @brief 测试 Ping 帧构建与解析
 */
void TestBuildPingFrame()
{
    log_info("=== TestBuildPingFrame ===");

    namespace yamux = psm::multiplex::yamux;

    // 构造 Ping 帧：SYN 标志、ping ID=99（存入 length 字段）
    auto encoded = yamux::build_ping_frame(yamux::flags::syn, 99);
    auto result = yamux::parse_header(encoded);

    if (!result)
    {
        log_fail("Ping frame parsing returned nullopt");
        return;
    }
    if (result->type != yamux::message_type::ping)
    {
        log_fail("Ping type mismatch");
        return;
    }
    // Ping 帧的 length 字段承载 ping ID
    if (result->length != 99)
    {
        log_fail(std::format("Ping length={}, expected 99", result->length));
        return;
    }

    log_pass("BuildPingFrame");
}

/**
 * @brief 测试 GoAway 帧构建与解析
 */
void TestBuildGoAwayFrame()
{
    log_info("=== TestBuildGoAwayFrame ===");

    namespace yamux = psm::multiplex::yamux;

    // 构造 GoAway 帧：错误码 protocol_error
    auto encoded = yamux::build_go_away_frame(yamux::go_away_code::protocol_error);
    auto result = yamux::parse_header(encoded);

    if (!result)
    {
        log_fail("GoAway frame parsing returned nullopt");
        return;
    }
    if (result->type != yamux::message_type::go_away)
    {
        log_fail("GoAway type mismatch");
        return;
    }
    // GoAway 帧的流 ID 必须为 0（会话级帧）
    if (result->stream_id != 0)
    {
        log_fail(std::format("GoAway stream_id={}, expected 0", result->stream_id));
        return;
    }
    // length 字段承载错误码，protocol_error=1
    if (result->length != 1)
    {
        log_fail(std::format("GoAway length={}, expected 1 (protocol_error)", result->length));
        return;
    }

    log_pass("BuildGoAwayFrame");
}

/**
 * @brief 测试 is_session() 判断
 */
void TestFrameHeaderIsSession()
{
    log_info("=== TestFrameHeaderIsSession ===");

    namespace yamux = psm::multiplex::yamux;

    // 流 ID 为 0 表示会话级帧（如 GoAway、Ping）
    yamux::frame_header session_hdr{};
    session_hdr.stream_id = 0;
    if (!session_hdr.is_session())
    {
        log_fail("stream_id=0 should be session");
        return;
    }

    // 流 ID 非 0 表示普通流级帧
    yamux::frame_header stream_hdr{};
    stream_hdr.stream_id = 5;
    if (stream_hdr.is_session())
    {
        log_fail("stream_id=5 should not be session");
        return;
    }

    log_pass("FrameHeaderIsSession");
}

/**
 * @brief 测试 has_flag 辅助函数
 */
void TestHasFlag()
{
    log_info("=== TestHasFlag ===");

    namespace yamux = psm::multiplex::yamux;
    using yamux::flags;

    // 组合 SYN|FIN 标志位
    const auto syn_fin = static_cast<flags>(static_cast<std::uint16_t>(flags::syn) | static_cast<std::uint16_t>(flags::fin));

    // SYN|FIN 应包含 SYN
    if (!yamux::has_flag(syn_fin, flags::syn))
    {
        log_fail("has_flag(syn|fin, syn) should be true");
        return;
    }

    // SYN|FIN 不应包含 ACK
    if (yamux::has_flag(syn_fin, flags::ack))
    {
        log_fail("has_flag(syn|fin, ack) should be false");
        return;
    }

    // none 标志不应包含任何位
    if (yamux::has_flag(flags::none, flags::syn))
    {
        log_fail("has_flag(none, syn) should be false");
        return;
    }

    log_pass("HasFlag");
}

/**
 * @brief 测试 flags 按位与运算
 */
void TestFlagBitwiseAnd()
{
    log_info("=== TestFlagBitwiseAnd ===");

    namespace yamux = psm::multiplex::yamux;
    using yamux::flags;

    // 不同标志位按位与应为 none
    if ((flags::syn & flags::fin) != flags::none)
    {
        log_fail("(syn & fin) should be none");
        return;
    }

    // 组合标志位与其中之一按位与应返回该标志
    const auto syn_fin = static_cast<flags>(static_cast<std::uint16_t>(flags::syn) | static_cast<std::uint16_t>(flags::fin));
    if ((syn_fin & flags::syn) != flags::syn)
    {
        log_fail("((syn|fin) & syn) should be syn");
        return;
    }

    log_pass("FlagBitwiseAnd");
}

/**
 * @brief 测试大端字节序编码正确性
 */
void TestBigEndianByteOrder()
{
    log_info("=== TestBigEndianByteOrder ===");

    namespace yamux = psm::multiplex::yamux;

    // 构造帧头，使用特征明显的值以验证字节序
    yamux::frame_header hdr{};
    hdr.version = yamux::protocol_version;
    hdr.type = yamux::message_type::data;
    hdr.flag = yamux::flags::none;
    hdr.stream_id = 0x12345678;
    hdr.length = 0xAABBCCDD;

    auto encoded = yamux::build_header(hdr);

    // 验证 stream_id 的 4 字节为大端序：0x12 0x34 0x56 0x78
    if (encoded[4] != std::byte{0x12} || encoded[5] != std::byte{0x34} ||
        encoded[6] != std::byte{0x56} || encoded[7] != std::byte{0x78})
    {
        log_fail("StreamID big-endian bytes mismatch");
        return;
    }

    // 验证 length 的 4 字节为大端序：0xAA 0xBB 0xCC 0xDD
    if (encoded[8] != std::byte{0xAA} || encoded[9] != std::byte{0xBB} ||
        encoded[10] != std::byte{0xCC} || encoded[11] != std::byte{0xDD})
    {
        log_fail("Length big-endian bytes mismatch");
        return;
    }

    log_pass("BigEndianByteOrder");
}

/**
 * @brief 测试 WindowUpdate 编解码往返
 */
void TestWindowUpdateRoundTrip()
{
    log_info("=== TestWindowUpdateRoundTrip ===");

    namespace yamux = psm::multiplex::yamux;

    // 窗口增量 65536，流 ID=7
    const std::uint32_t delta = 65536;
    const std::uint32_t sid = 7;

    // 构建 WindowUpdate 帧并解析，验证增量值不丢失
    auto encoded = yamux::build_window_update_frame(yamux::flags::syn, sid, delta);
    auto result = yamux::parse_header(encoded);

    if (!result)
    {
        log_fail("WindowUpdate round-trip returned nullopt");
        return;
    }
    if (result->type != yamux::message_type::window_update)
    {
        log_fail("WindowUpdate round-trip type mismatch");
        return;
    }
    if (result->stream_id != sid)
    {
        log_fail(std::format("WindowUpdate round-trip stream_id={}, expected {}", result->stream_id, sid));
        return;
    }
    if (result->length != delta)
    {
        log_fail(std::format("WindowUpdate round-trip delta={}, expected {}", result->length, delta));
        return;
    }

    log_pass("WindowUpdateRoundTrip");
}

/**
 * @brief 测试 Ping 编解码往返
 */
void TestPingRoundTrip()
{
    log_info("=== TestPingRoundTrip ===");

    namespace yamux = psm::multiplex::yamux;

    // ping ID=12345，存入 length 字段
    const std::uint32_t ping_id = 12345;

    // 构建 Ping 帧并解析，验证 ping ID 往返一致
    auto encoded = yamux::build_ping_frame(yamux::flags::syn, ping_id);
    auto result = yamux::parse_header(encoded);

    if (!result)
    {
        log_fail("Ping round-trip returned nullopt");
        return;
    }
    if (result->type != yamux::message_type::ping)
    {
        log_fail("Ping round-trip type mismatch");
        return;
    }
    if (result->length != ping_id)
    {
        log_fail(std::format("Ping round-trip ping_id={}, expected {}", result->length, ping_id));
        return;
    }

    log_pass("PingRoundTrip");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，运行 yamux 帧头编解码、特殊帧构建、
 *          会话级判断、标志位操作、大端字节序等全部测试用例，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化 PMR 全局内存池和日志系统
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    log_info("Starting yamux tests...");

    // 帧头编解码往返：覆盖全部 4 种消息类型
    TestBuildParseHeaderRoundTrip();
    // 容错测试：非法版本号和截断数据
    TestParseHeaderVersionMismatch();
    TestParseHeaderTruncated();
    // 特殊帧构建与解析
    TestBuildWindowUpdateFrame();
    TestBuildPingFrame();
    TestBuildGoAwayFrame();
    // 帧头属性和标志位操作
    TestFrameHeaderIsSession();
    TestHasFlag();
    TestFlagBitwiseAnd();
    // 大端字节序验证
    TestBigEndianByteOrder();
    // WindowUpdate 和 Ping 往返测试
    TestWindowUpdateRoundTrip();
    TestPingRoundTrip();

    log_info("Yamux tests completed.");

    psm::trace::info("[Yamux] Results: {} passed, {} failed", passed, failed);

    return failed > 0 ? 1 : 0;
}
