/**
 * @file MuxCodecTest.cpp
 * @brief 三套多路复用帧编解码单测（新接口：纯函数 Build/ParseHeader）
 * @details 覆盖：Build→ParseHeader 往返、半包 need_more、坏版本、
 *          非法命令、超长帧、多字节字段字节序。
 */

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <common/Protocols/Mux/H2Mux/Codec.hpp>
#include <common/Protocols/Mux/Smux/Codec.hpp>
#include <common/Protocols/Mux/Yamux/Codec.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
    using namespace Preview::Mux;

    /// @brief 便捷转换：字符串 → 只读字节 span
    /// @param s 输入字符串
    /// @return 指向字符串缓冲的字节 span
    [[nodiscard]] inline auto Bytes(std::string_view s) -> std::span<const std::uint8_t>
    {
        return {reinterpret_cast<const std::uint8_t *>(s.data()), s.size()};
    }

    TEST(MuxCodec, SmuxRoundtrip)
    {
        const std::string payload = "smux payload";
        const auto wire = Smux::BuildPush(0x01020304, Bytes(payload));
        Smux::FrameHeader out{};
        EXPECT_EQ(Smux::ParseHeader(wire, out), Error::None);
        EXPECT_EQ(out.cmd, Smux::Command::Push);
        EXPECT_EQ(out.length, payload.size());
        EXPECT_EQ(out.StreamId, 0x01020304u);
        // 小端字节序：length = 0x000C，StreamId = 04 03 02 01
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
        Smux::FrameHeader out{};
        EXPECT_EQ(Smux::ParseHeader(short_data, out), Error::NeedMore);
    }

    TEST(MuxCodec, SmuxBadVersion)
    {
        // smux 版本错误（0x02 ≠ 0x01）
        {
            auto wire = Smux::BuildPush(1, Bytes(std::string_view("x")));
            wire[0] = 0x02;
            Smux::FrameHeader out{};
            EXPECT_EQ(Smux::ParseHeader(wire, out), Error::BadMagic);
        }
        // yamux 版本错误（0x01 ≠ 0x00）
        {
            auto wire = Yamux::BuildData(Yamux::Flags::None, 1, Bytes(std::string_view("x")));
            wire[0] = 0x01;
            Yamux::FrameHeader out{};
            EXPECT_EQ(Yamux::ParseHeader(wire, out), Error::BadMagic);
        }
        // smux 非法命令（cmd = 0x09）
        {
            auto wire = Smux::BuildPush(1, Bytes(std::string_view("x")));
            wire[1] = 0x09;
            Smux::FrameHeader out{};
            EXPECT_EQ(Smux::ParseHeader(wire, out), Error::BadMessage);
        }
        // yamux 非法类型（Type = 0x05）
        {
            auto wire = Yamux::BuildData(Yamux::Flags::None, 1, Bytes(std::string_view("x")));
            wire[1] = 0x05;
            Yamux::FrameHeader out{};
            EXPECT_EQ(Yamux::ParseHeader(wire, out), Error::BadMessage);
        }
    }

    TEST(MuxCodec, YamuxRoundtrip)
    {
        const std::string payload = "yamux payload";
        const auto wire = Yamux::BuildData(Yamux::Flags::Ack, 7, Bytes(payload));
        Yamux::FrameHeader out{};
        EXPECT_EQ(Yamux::ParseHeader(wire, out), Error::None);
        EXPECT_EQ(out.Type, Yamux::MessageType::Data);
        EXPECT_TRUE(Yamux::HasFlag(out.flag, Yamux::Flags::Ack));
        EXPECT_EQ(out.StreamId, 7u);
        EXPECT_EQ(out.length, payload.size());
        // 大端字节序：Flags = 00 02，StreamId = 00 00 00 07，length = 00 00 00 0D
        EXPECT_EQ(wire[2], 0x00);
        EXPECT_EQ(wire[3], 0x02);
        EXPECT_EQ(wire[4], 0x00);
        EXPECT_EQ(wire[7], 0x07);
        EXPECT_EQ(wire[8], 0x00);
        EXPECT_EQ(wire[11], static_cast<std::uint8_t>(payload.size()));
    }

    TEST(MuxCodec, YamuxWindowUpdate)
    {
        const auto wire = Yamux::BuildWinupd(Yamux::Flags::Syn, 3, 0x00040000u);
        Yamux::FrameHeader out{};
        EXPECT_EQ(Yamux::ParseHeader(wire, out), Error::None);
        EXPECT_EQ(out.Type, Yamux::MessageType::WindowUpdate);
        EXPECT_EQ(out.StreamId, 3u);
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
        const auto wire = H2Mux::BuildData(5, Bytes(payload));
        H2Mux::FrameHeader out{};
        EXPECT_EQ(H2Mux::ParseHeader(wire, out), Error::None);
        EXPECT_EQ(out.Type, H2Mux::FrameType::Data);
        EXPECT_EQ(out.length, payload.size());
        EXPECT_EQ(out.StreamId, 5u);
        // 大端字节序：length = 00 00 00 0B，StreamId = 00 00 00 05
        EXPECT_EQ(wire[1], 0x00);
        EXPECT_EQ(wire[4], static_cast<std::uint8_t>(payload.size()));
        EXPECT_EQ(wire[5], 0x00);
        EXPECT_EQ(wire[8], 0x05);
    }

    TEST(MuxCodec, H2muxStreamIdMask)
    {
        const auto wire = H2Mux::Build(H2Mux::FrameType::Data, 0x80000001u);
        H2Mux::FrameHeader out{};
        EXPECT_EQ(H2Mux::ParseHeader(wire, out), Error::None);
        // 大端字节序：StreamId = 80 00 00 01 原样往返
        EXPECT_EQ(out.StreamId, 0x80000001u);
        EXPECT_EQ(wire[5], 0x80);
        EXPECT_EQ(wire[6], 0x00);
        EXPECT_EQ(wire[7], 0x00);
        EXPECT_EQ(wire[8], 0x01);
    }

    TEST(MuxCodec, OversizedRejected)
    {
        // 帧头 length 超过 h2mux 上限（16MB）→ bad_length
        const std::array<std::uint8_t, 9> wire{
            0x00,                   // Type = Data
            0x01, 0x00, 0x00, 0x01, // length = 0x01000001 > 16MB
            0x00, 0x00, 0x00, 0x01, // StreamId = 1
        };
        H2Mux::FrameHeader out{};
        EXPECT_EQ(H2Mux::ParseHeader(wire, out), Error::BadLength);
    }

} // namespace
