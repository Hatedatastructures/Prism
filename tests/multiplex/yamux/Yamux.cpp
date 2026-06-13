/**
 * @file Yamux.cpp
 * @brief yamux 多路复用帧编解码单元测试
 * @details 验证 psm::multiplex::yamux 模块的帧编解码功能，覆盖以下场景：
 * 1. 帧头编解码往返（Data/WindowUpdate/Ping/GoAway）
 * 2. 特殊帧构建（WindowUpdate/Ping/GoAway）
 * 3. 会话级帧判断、标志位操作与大端字节序验证
 * 4. 截断数据与版本不匹配的容错处理
 */

#include <prism/proto/multiplex/yamux/frame.hpp>
#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <gtest/gtest.h>

/**
 * @brief 测试帧头编解码往返，覆盖所有 4 种消息类型
 */
TEST(Yamux, BuildParseHeaderRoundTrip)
{
    namespace yamux = psm::multiplex::yamux;

    const yamux::message_type types[] = {
        yamux::message_type::data,
        yamux::message_type::window_update,
        yamux::message_type::ping,
        yamux::message_type::go_away,
    };

    for (const auto msg_type : types)
    {
        yamux::frame_header hdr{};
        hdr.version = yamux::protocol_version;
        hdr.type = msg_type;
        hdr.flag = yamux::flags::syn;
        hdr.stream_id = 1;
        hdr.length = 100;

        auto encoded = yamux::build_header(hdr);
        auto result = yamux::parse_header(encoded);

        ASSERT_TRUE(result.has_value())
            << std::format("Round-trip returned nullopt for message_type={}", static_cast<int>(msg_type));
        EXPECT_TRUE(result->version == hdr.version)
            << std::format("Version mismatch for message_type={}", static_cast<int>(msg_type));
        EXPECT_TRUE(result->type == hdr.type)
            << std::format("Type mismatch for message_type={}", static_cast<int>(msg_type));
        EXPECT_TRUE(result->flag == hdr.flag)
            << std::format("Flag mismatch for message_type={}", static_cast<int>(msg_type));
        EXPECT_TRUE(result->stream_id == hdr.stream_id)
            << std::format("StreamID mismatch for message_type={}", static_cast<int>(msg_type));
        EXPECT_TRUE(result->length == hdr.length)
            << std::format("Length mismatch for message_type={}", static_cast<int>(msg_type));
    }
}

/**
 * @brief 测试版本不匹配时返回 nullopt
 */
TEST(Yamux, ParseHeaderVersionMismatch)
{
    std::array<std::byte, 12> buf{};
    buf[0] = std::byte{0xFF};
    for (std::size_t i = 1; i < 12; ++i)
    {
        buf[i] = std::byte{0x00};
    }

    auto result = psm::multiplex::yamux::parse_header(std::span<const std::byte>{buf});
    EXPECT_TRUE(!result.has_value()) << "Version 0xFF should return nullopt";
}

/**
 * @brief 测试截断数据时返回 nullopt
 */
TEST(Yamux, ParseHeaderTruncated)
{
    std::array<std::byte, 11> short_buf{};
    auto result = psm::multiplex::yamux::parse_header(std::span<const std::byte>{short_buf});
    EXPECT_TRUE(!result.has_value()) << "11 bytes should return nullopt";

    auto result2 = psm::multiplex::yamux::parse_header(std::span<const std::byte>{});
    EXPECT_TRUE(!result2.has_value()) << "0 bytes should return nullopt";
}

/**
 * @brief 测试 WindowUpdate 帧构建与解析
 */
TEST(Yamux, BuildWindowUpdateFrame)
{
    namespace yamux = psm::multiplex::yamux;

    auto encoded = yamux::build_winupd(yamux::flags::ack, 42, 32768);
    auto result = yamux::parse_header(encoded);

    ASSERT_TRUE(result.has_value()) << "WindowUpdate frame parsing returned nullopt";
    EXPECT_TRUE(result->type == yamux::message_type::window_update) << "WindowUpdate type mismatch";
    EXPECT_TRUE(result->stream_id == 42) << std::format("WindowUpdate stream_id={}, expected 42", result->stream_id);
    EXPECT_TRUE(result->length == 32768) << std::format("WindowUpdate length={}, expected 32768", result->length);
}

/**
 * @brief 测试 Ping 帧构建与解析
 */
TEST(Yamux, BuildPingFrame)
{
    namespace yamux = psm::multiplex::yamux;

    auto encoded = yamux::build_ping(yamux::flags::syn, 99);
    auto result = yamux::parse_header(encoded);

    ASSERT_TRUE(result.has_value()) << "Ping frame parsing returned nullopt";
    EXPECT_TRUE(result->type == yamux::message_type::ping) << "Ping type mismatch";
    EXPECT_TRUE(result->length == 99) << std::format("Ping length={}, expected 99", result->length);
}

/**
 * @brief 测试 GoAway 帧构建与解析
 */
TEST(Yamux, BuildGoAwayFrame)
{
    namespace yamux = psm::multiplex::yamux;

    auto encoded = yamux::build_goaway(yamux::away_code::protocol_error);
    auto result = yamux::parse_header(encoded);

    ASSERT_TRUE(result.has_value()) << "GoAway frame parsing returned nullopt";
    EXPECT_TRUE(result->type == yamux::message_type::go_away) << "GoAway type mismatch";
    EXPECT_TRUE(result->stream_id == 0) << std::format("GoAway stream_id={}, expected 0", result->stream_id);
    EXPECT_TRUE(result->length == 1) << std::format("GoAway length={}, expected 1 (protocol_error)", result->length);
}

/**
 * @brief 测试 is_session() 判断
 */
TEST(Yamux, FrameHeaderIsSession)
{
    namespace yamux = psm::multiplex::yamux;

    yamux::frame_header session_hdr{};
    session_hdr.stream_id = 0;
    EXPECT_TRUE(session_hdr.is_session()) << "stream_id=0 should be session";

    yamux::frame_header stream_hdr{};
    stream_hdr.stream_id = 5;
    EXPECT_TRUE(!stream_hdr.is_session()) << "stream_id=5 should not be session";
}

/**
 * @brief 测试 has_flag 辅助函数
 */
TEST(Yamux, HasFlag)
{
    namespace yamux = psm::multiplex::yamux;
    using yamux::flags;

    const auto syn_fin = static_cast<flags>(static_cast<std::uint16_t>(flags::syn) | static_cast<std::uint16_t>(flags::fin));

    EXPECT_TRUE(yamux::has_flag(syn_fin, flags::syn)) << "has_flag(syn|fin, syn) should be true";
    EXPECT_TRUE(!yamux::has_flag(syn_fin, flags::ack)) << "has_flag(syn|fin, ack) should be false";
    EXPECT_TRUE(!yamux::has_flag(flags::none, flags::syn)) << "has_flag(none, syn) should be false";
}

/**
 * @brief 测试 flags 按位与运算
 */
TEST(Yamux, FlagBitwiseAnd)
{
    namespace yamux = psm::multiplex::yamux;
    using yamux::flags;

    EXPECT_TRUE((flags::syn & flags::fin) == flags::none) << "(syn & fin) should be none";

    const auto syn_fin = static_cast<flags>(static_cast<std::uint16_t>(flags::syn) | static_cast<std::uint16_t>(flags::fin));
    EXPECT_TRUE((syn_fin & flags::syn) == flags::syn) << "((syn|fin) & syn) should be syn";
}

/**
 * @brief 测试大端字节序编码正确性
 */
TEST(Yamux, BigEndianByteOrder)
{
    namespace yamux = psm::multiplex::yamux;

    yamux::frame_header hdr{};
    hdr.version = yamux::protocol_version;
    hdr.type = yamux::message_type::data;
    hdr.flag = yamux::flags::none;
    hdr.stream_id = 0x12345678;
    hdr.length = 0xAABBCCDD;

    auto encoded = yamux::build_header(hdr);

    EXPECT_TRUE(encoded[4] == std::byte{0x12} && encoded[5] == std::byte{0x34} &&
                encoded[6] == std::byte{0x56} && encoded[7] == std::byte{0x78})
        << "StreamID big-endian bytes mismatch";

    EXPECT_TRUE(encoded[8] == std::byte{0xAA} && encoded[9] == std::byte{0xBB} &&
                encoded[10] == std::byte{0xCC} && encoded[11] == std::byte{0xDD})
        << "Length big-endian bytes mismatch";
}

/**
 * @brief 测试 WindowUpdate 编解码往返
 */
TEST(Yamux, WindowUpdateRoundTrip)
{
    namespace yamux = psm::multiplex::yamux;

    const std::uint32_t delta = 65536;
    const std::uint32_t sid = 7;

    auto encoded = yamux::build_winupd(yamux::flags::syn, sid, delta);
    auto result = yamux::parse_header(encoded);

    ASSERT_TRUE(result.has_value()) << "WindowUpdate round-trip returned nullopt";
    EXPECT_TRUE(result->type == yamux::message_type::window_update) << "WindowUpdate round-trip type mismatch";
    EXPECT_TRUE(result->stream_id == sid) << std::format("WindowUpdate round-trip stream_id={}, expected {}", result->stream_id, sid);
    EXPECT_TRUE(result->length == delta) << std::format("WindowUpdate round-trip delta={}, expected {}", result->length, delta);
}

/**
 * @brief 测试 Ping 编解码往返
 */
TEST(Yamux, PingRoundTrip)
{
    namespace yamux = psm::multiplex::yamux;

    const std::uint32_t ping_id = 12345;

    auto encoded = yamux::build_ping(yamux::flags::syn, ping_id);
    auto result = yamux::parse_header(encoded);

    ASSERT_TRUE(result.has_value()) << "Ping round-trip returned nullopt";
    EXPECT_TRUE(result->type == yamux::message_type::ping) << "Ping round-trip type mismatch";
    EXPECT_TRUE(result->length == ping_id) << std::format("Ping round-trip ping_id={}, expected {}", result->length, ping_id);
}
