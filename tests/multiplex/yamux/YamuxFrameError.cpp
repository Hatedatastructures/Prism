/**
 * @file YamuxFrameError.cpp
 * @brief yamux 帧格式错误路径与往返测试
 */

#include <prism/core/core.hpp>
#include <prism/proto/multiplex/yamux/frame.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstdint>
#include <cstring>

#include <gtest/gtest.h>

namespace
{
    using namespace psm::multiplex::yamux;

    TEST(YamuxFrameError, ParseHeaderTooShort)
    {
        std::array<std::byte, 6> short_buf{};
        auto result = parse_header(short_buf);
        EXPECT_TRUE(!result.has_value()) << "parse_header: too short -> nullopt";
    }

    TEST(YamuxFrameError, ParseHeaderBadVersion)
    {
        std::array<std::byte, frame_hdrsize> buf{};
        buf[0] = std::byte{0x99};
        auto result = parse_header(buf);
        EXPECT_TRUE(!result.has_value()) << "parse_header: bad version -> nullopt";
    }

    TEST(YamuxFrameError, ParseHeaderBadType)
    {
        std::array<std::byte, frame_hdrsize> buf{};
        buf[0] = std::byte{protocol_version};
        buf[1] = std::byte{0xFF};
        auto result = parse_header(buf);
        EXPECT_TRUE(!result.has_value()) << "parse_header: bad type -> nullopt";
    }

    TEST(YamuxFrameError, RoundtripDataSyn)
    {
        const std::byte data[] = {std::byte{0x01}, std::byte{0x02}};
        auto frame = build_syn(1, data);

        auto parsed = parse_header(frame.header);
        ASSERT_TRUE(parsed.has_value()) << "roundtrip syn: parsed";
        EXPECT_TRUE(parsed->type == message_type::data) << "roundtrip syn: type=data";
        EXPECT_TRUE(static_cast<int>(parsed->flag) == static_cast<int>(flags::syn)) << "roundtrip syn: flag=syn";
        EXPECT_TRUE(parsed->stream_id == 1) << "roundtrip syn: stream_id=1";
    }

    TEST(YamuxFrameError, RoundtripFin)
    {
        auto buf = build_fin(42);
        auto parsed = parse_header(buf);
        ASSERT_TRUE(parsed.has_value()) << "roundtrip fin: parsed";
        EXPECT_TRUE(parsed->type == message_type::data) << "roundtrip fin: type=data";
        EXPECT_TRUE(static_cast<int>(parsed->flag) == static_cast<int>(flags::fin)) << "roundtrip fin: flag=fin";
        EXPECT_TRUE(parsed->stream_id == 42) << "roundtrip fin: stream_id=42";
        EXPECT_TRUE(parsed->length == 0) << "roundtrip fin: length=0";
    }

    TEST(YamuxFrameError, RoundtripWindowUpdate)
    {
        auto buf = build_winupd(flags::none, 5, 32768);
        auto parsed = parse_header(buf);
        ASSERT_TRUE(parsed.has_value()) << "roundtrip winupd: parsed";
        EXPECT_TRUE(parsed->type == message_type::window_update) << "roundtrip winupd: type=window_update";
        EXPECT_TRUE(parsed->stream_id == 5) << "roundtrip winupd: stream_id=5";
        EXPECT_TRUE(parsed->length == 32768) << "roundtrip winupd: length=delta";
    }

    TEST(YamuxFrameError, RoundtripPing)
    {
        auto buf = build_ping(flags::syn, 12345);
        auto parsed = parse_header(buf);
        ASSERT_TRUE(parsed.has_value()) << "roundtrip ping: parsed";
        EXPECT_TRUE(parsed->type == message_type::ping) << "roundtrip ping: type=ping";
        EXPECT_TRUE(parsed->stream_id == 0) << "roundtrip ping: stream_id=0";
        EXPECT_TRUE(parsed->length == 12345) << "roundtrip ping: length=ping_id";
    }

    TEST(YamuxFrameError, RoundtripGoaway)
    {
        auto buf = build_goaway(away_code::protocol_error);
        auto parsed = parse_header(buf);
        ASSERT_TRUE(parsed.has_value()) << "roundtrip goaway: parsed";
        EXPECT_TRUE(parsed->type == message_type::go_away) << "roundtrip goaway: type=go_away";
        EXPECT_TRUE(parsed->stream_id == 0) << "roundtrip goaway: stream_id=0";
        EXPECT_TRUE(parsed->length == static_cast<std::uint32_t>(away_code::protocol_error)) << "roundtrip goaway: length=protocol_error";
    }

    TEST(YamuxFrameError, RoundtripDataWithPayload)
    {
        const std::byte data[] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
        auto frame = build_data(flags::none, 10, data);
        auto parsed = parse_header(frame.header);
        ASSERT_TRUE(parsed.has_value()) << "roundtrip data: parsed";
        EXPECT_TRUE(parsed->type == message_type::data) << "roundtrip data: type=data";
        EXPECT_TRUE(parsed->stream_id == 10) << "roundtrip data: stream_id=10";
        EXPECT_TRUE(parsed->length == 3) << "roundtrip data: length=3";
    }

    TEST(YamuxFrameError, IsSession)
    {
        frame_header hdr;
        hdr.stream_id = 0;
        EXPECT_TRUE(hdr.is_session()) << "is_session: stream 0 is session";
        hdr.stream_id = 1;
        EXPECT_TRUE(!hdr.is_session()) << "is_session: stream 1 is not session";
        hdr.stream_id = 999;
        EXPECT_TRUE(!hdr.is_session()) << "is_session: stream 999 is not session";
    }

    TEST(YamuxFrameError, ParseHeaderEmpty)
    {
        std::span<const std::byte> empty;
        auto result = parse_header(empty);
        EXPECT_TRUE(!result.has_value()) << "parse_header: empty -> nullopt";
    }

} // namespace
