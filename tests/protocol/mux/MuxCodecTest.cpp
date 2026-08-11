/**
 * @file MuxCodecTest.cpp
 * @brief 三套多路复用帧编解码单测（新接口：纯函数 build/parse_header）
 * @details 覆盖：build→parse_header 往返、半包 need_more、坏版本、
 *          非法命令、超长帧、多字节字段字节序。
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <common/mux/h2mux/codec.hpp>
#include <common/mux/smux/codec.hpp>
#include <common/mux/yamux/codec.hpp>

namespace
{
    using namespace psmtest;
    using namespace psmtest::mux;

    /// @brief 便捷转换：字符串 → 只读字节 span
    /// @param s 输入字符串
    /// @return 指向字符串缓冲的字节 span
    [[nodiscard]] inline auto bytes(std::string_view s) -> std::span<const std::uint8_t>
    {
        return {reinterpret_cast<const std::uint8_t *>(s.data()), s.size()};
    }

    TEST(MuxCodec, SmuxRoundtrip)
    {
        const std::string payload = "smux payload";
        const auto wire = smux::build_push(0x01020304, bytes(payload));
        smux::frame_header out{};
        EXPECT_EQ(smux::parse_header(wire, out), error::none);
        EXPECT_EQ(out.cmd, smux::command::push);
        EXPECT_EQ(out.length, payload.size());
        EXPECT_EQ(out.stream_id, 0x01020304u);
        // 小端字节序：length = 0x000C，stream_id = 04 03 02 01
        EXPECT_EQ(wire[2], 0x0C);
        EXPECT_EQ(wire[3], 0x00);
        EXPECT_EQ(wire[4], 0x04);
        EXPECT_EQ(wire[5], 0x03);
        EXPECT_EQ(wire[6], 0x02);
        EXPECT_EQ(wire[7], 0x01);
    }

    TEST(MuxCodec, SmuxNeedMore)
    {
        const std::array<std::uint8_t, 3> short_data{0x01, 0x02, 0x03};
        smux::frame_header out{};
        EXPECT_EQ(smux::parse_header(short_data, out), error::need_more);
    }

    TEST(MuxCodec, SmuxBadVersion)
    {
        // smux 版本错误（0x02 ≠ 0x01）
        {
            auto wire = smux::build_push(1, bytes(std::string_view("x")));
            wire[0] = 0x02;
            smux::frame_header out{};
            EXPECT_EQ(smux::parse_header(wire, out), error::bad_magic);
        }
        // yamux 版本错误（0x01 ≠ 0x00）
        {
            auto wire = yamux::build_data(yamux::flags::none, 1, bytes(std::string_view("x")));
            wire[0] = 0x01;
            yamux::frame_header out{};
            EXPECT_EQ(yamux::parse_header(wire, out), error::bad_magic);
        }
        // smux 非法命令（cmd = 0x09）
        {
            auto wire = smux::build_push(1, bytes(std::string_view("x")));
            wire[1] = 0x09;
            smux::frame_header out{};
            EXPECT_EQ(smux::parse_header(wire, out), error::bad_message);
        }
        // yamux 非法类型（type = 0x05）
        {
            auto wire = yamux::build_data(yamux::flags::none, 1, bytes(std::string_view("x")));
            wire[1] = 0x05;
            yamux::frame_header out{};
            EXPECT_EQ(yamux::parse_header(wire, out), error::bad_message);
        }
    }

    TEST(MuxCodec, YamuxRoundtrip)
    {
        const std::string payload = "yamux payload";
        const auto wire = yamux::build_data(yamux::flags::ack, 7, bytes(payload));
        yamux::frame_header out{};
        EXPECT_EQ(yamux::parse_header(wire, out), error::none);
        EXPECT_EQ(out.type, yamux::message_type::data);
        EXPECT_TRUE(yamux::has_flag(out.flag, yamux::flags::ack));
        EXPECT_EQ(out.stream_id, 7u);
        EXPECT_EQ(out.length, payload.size());
        // 大端字节序：flags = 00 02，stream_id = 00 00 00 07，length = 00 00 00 0D
        EXPECT_EQ(wire[2], 0x00);
        EXPECT_EQ(wire[3], 0x02);
        EXPECT_EQ(wire[4], 0x00);
        EXPECT_EQ(wire[7], 0x07);
        EXPECT_EQ(wire[8], 0x00);
        EXPECT_EQ(wire[11], static_cast<std::uint8_t>(payload.size()));
    }

    TEST(MuxCodec, YamuxWindowUpdate)
    {
        const auto wire = yamux::build_winupd(yamux::flags::syn, 3, 0x00040000u);
        yamux::frame_header out{};
        EXPECT_EQ(yamux::parse_header(wire, out), error::none);
        EXPECT_EQ(out.type, yamux::message_type::window_update);
        EXPECT_EQ(out.stream_id, 3u);
        EXPECT_EQ(out.length, 0x00040000u);
        // 大端字节序：delta = 00 04 00 00
        EXPECT_EQ(wire[8], 0x00);
        EXPECT_EQ(wire[9], 0x04);
        EXPECT_EQ(wire[10], 0x00);
        EXPECT_EQ(wire[11], 0x00);
    }

    TEST(MuxCodec, H2muxRoundtrip)
    {
        const std::string payload = "h2 payload";
        const auto wire = h2mux::build_data(5, bytes(payload));
        h2mux::frame_header out{};
        EXPECT_EQ(h2mux::parse_header(wire, out), error::none);
        EXPECT_EQ(out.type, h2mux::frame_type::data);
        EXPECT_EQ(out.length, payload.size());
        EXPECT_EQ(out.stream_id, 5u);
        // 大端字节序：length = 00 00 00 0B，stream_id = 00 00 00 05
        EXPECT_EQ(wire[1], 0x00);
        EXPECT_EQ(wire[4], static_cast<std::uint8_t>(payload.size()));
        EXPECT_EQ(wire[5], 0x00);
        EXPECT_EQ(wire[8], 0x05);
    }

    TEST(MuxCodec, H2muxStreamIdMask)
    {
        const auto wire = h2mux::build(h2mux::frame_type::data, 0x80000001u);
        h2mux::frame_header out{};
        EXPECT_EQ(h2mux::parse_header(wire, out), error::none);
        // 大端字节序：stream_id = 80 00 00 01 原样往返
        EXPECT_EQ(out.stream_id, 0x80000001u);
        EXPECT_EQ(wire[5], 0x80);
        EXPECT_EQ(wire[6], 0x00);
        EXPECT_EQ(wire[7], 0x00);
        EXPECT_EQ(wire[8], 0x01);
    }

    TEST(MuxCodec, OversizedRejected)
    {
        // 帧头 length 超过 h2mux 上限（16MB）→ bad_length
        const std::array<std::uint8_t, 9> wire{
            0x00, // type = data
            0x01, 0x00, 0x00, 0x01, // length = 0x01000001 > 16MB
            0x00, 0x00, 0x00, 0x01, // stream_id = 1
        };
        h2mux::frame_header out{};
        EXPECT_EQ(h2mux::parse_header(wire, out), error::bad_length);
    }

} // namespace
