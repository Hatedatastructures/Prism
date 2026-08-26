/**
 * @file YamuxCodecError.cpp
 * @brief yamux 帧格式错误路径与往返测试（测试库 Codec 层）
 * @details 覆盖：帧头长度边界（空/半帧 → need_more）、版本错误
 *          （非 0x00 → bad_magic）、未知类型（Type 越界 → bad_message）、
 *          类型边界（Data/winupd/ping/go_away 全合法）、流 ID 边界
 *          （0 / 0xFFFFFFFF）、长度边界（0 / 大值）、
 *          SYN/FIN/WinUpd/Ping 往返稳定。
 *          全部为纯函数同步测试，无协程无 I/O。
 */

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include <common/Protocols/Mux/Yamux/Codec.hpp>
#include <common/Protocols/Mux/Yamux/Types.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
    using namespace Preview::Mux;

    TEST(YamuxCodecError, ParseHeaderEmpty)
    {
        std::span<const std::uint8_t> Empty;
        Yamux::FrameHeader out{};
        EXPECT_EQ(Yamux::ParseHeader(Empty, out), Error::NeedMore);
    }

    TEST(YamuxCodecError, ParseHeaderTooShort)
    {
        // 帧头 12 字节，仅 4 字节（半帧）
        const std::array<std::uint8_t, 4> short_buf{0x00, 0x01, 0x00, 0x00};
        Yamux::FrameHeader out{};
        EXPECT_EQ(Yamux::ParseHeader(short_buf, out), Error::NeedMore);
    }

    TEST(YamuxCodecError, ParseHeaderBadVersion)
    {
        auto wire = Yamux::BuildSyn(1, std::span<const std::uint8_t>{});
        wire[0] = 0x01; // 非法版本（协议仅 0x00）
        Yamux::FrameHeader out{};
        EXPECT_EQ(Yamux::ParseHeader(wire, out), Error::BadMagic);
    }

    TEST(YamuxCodecError, ParseHeaderUnknownType)
    {
        auto wire = Yamux::BuildSyn(1, std::span<const std::uint8_t>{});
        wire[1] = 0x09; // 未知类型（合法区间 0..3）
        Yamux::FrameHeader out{};
        EXPECT_EQ(Yamux::ParseHeader(wire, out), Error::BadMessage);
    }

    TEST(YamuxCodecError, ParseHeaderTypeBoundary)
    {
        // 0..3 = Data/winupd/ping/go_away 全部合法
        for (int t = 0; t <= 3; ++t)
        {
            const Yamux::FrameHeader hdr{
                .Type = static_cast<Yamux::MessageType>(t), .flag = Yamux::Flags::None, .StreamId = 1};
            const auto wire = Yamux::Build(hdr);
            Yamux::FrameHeader out{};
            EXPECT_EQ(Yamux::ParseHeader(wire, out), Error::None) << "Type " << t << " 合法";
        }
        // 4（go_away 后第一个非法值）→ bad_message
        {
            const Yamux::FrameHeader hdr{
                .Type = static_cast<Yamux::MessageType>(4), .flag = Yamux::Flags::None, .StreamId = 1};
            const auto wire = Yamux::Build(hdr);
            Yamux::FrameHeader out{};
            EXPECT_EQ(Yamux::ParseHeader(wire, out), Error::BadMessage);
        }
    }

    TEST(YamuxCodecError, StreamIdBoundary)
    {
        // 0 与 0xFFFFFFFF 均可解析（yamux 无流 ID 保留位校验）
        for (const auto sid : {0u, 0xFFFFFFFFu})
        {
            const Yamux::FrameHeader hdr{.flag = Yamux::Flags::None, .StreamId = sid};
            const auto wire = Yamux::Build(hdr);
            Yamux::FrameHeader out{};
            EXPECT_EQ(Yamux::ParseHeader(wire, out), Error::None);
            EXPECT_EQ(out.StreamId, sid);
        }
    }

    TEST(YamuxCodecError, LengthBoundary)
    {
        // 帧头 length 字段 0 与 0xFFFFFFFF 往返（BuildHeader 不自动填）
        for (const auto len : {0u, 0xFFFFFFFFu})
        {
            Yamux::FrameHeader hdr{.Type = Yamux::MessageType::Data,
                                    .flag = Yamux::Flags::None,
                                    .StreamId = 1,
                                    .length = len};
            const auto wire = Yamux::BuildHeader(hdr);
            Yamux::FrameHeader out{};
            EXPECT_EQ(Yamux::ParseHeader(wire, out), Error::None);
            EXPECT_EQ(out.length, len);
        }
    }

    TEST(YamuxCodecError, SynFinRoundtrip)
    {
        const auto syn = Yamux::BuildSyn(7, std::span<const std::uint8_t>{});
        Yamux::FrameHeader out{};
        EXPECT_EQ(Yamux::ParseHeader(syn, out), Error::None);
        EXPECT_EQ(out.Type, Yamux::MessageType::Data);
        EXPECT_TRUE(Yamux::HasFlag(out.flag, Yamux::Flags::Syn));
        EXPECT_EQ(out.StreamId, 7u);

        const auto fin = Yamux::BuildFin(7);
        EXPECT_EQ(Yamux::ParseHeader(fin, out), Error::None);
        EXPECT_TRUE(Yamux::HasFlag(out.flag, Yamux::Flags::Fin));
        EXPECT_EQ(out.StreamId, 7u);
    }

    TEST(YamuxCodecError, PingAndWindowUpdateRoundtrip)
    {
        // ping（请求标志）
        auto ping = Yamux::Build(Yamux::FrameHeader{.Type = Yamux::MessageType::Ping,
                                                     .flag = Yamux::Flags::Syn,
                                                     .StreamId = 0,
                                                     .length = 4});
        Yamux::FrameHeader out{};
        EXPECT_EQ(Yamux::ParseHeader(ping, out), Error::None);
        EXPECT_EQ(out.Type, Yamux::MessageType::Ping);
        EXPECT_TRUE(Yamux::HasFlag(out.flag, Yamux::Flags::Syn));

        // window Update（ack 标志）
        const auto win = Yamux::Build(Yamux::FrameHeader{.Type = Yamux::MessageType::WindowUpdate,
                                                          .flag = Yamux::Flags::Ack,
                                                          .StreamId = 3,
                                                          .length = 4});
        EXPECT_EQ(Yamux::ParseHeader(win, out), Error::None);
        EXPECT_EQ(out.Type, Yamux::MessageType::WindowUpdate);
        EXPECT_EQ(out.StreamId, 3u);
        EXPECT_EQ(out.length, 4u);
    }

    TEST(YamuxCodecError, ParsePayloadAlwaysNone)
    {
        // yamux 负载无额外校验
        Yamux::FrameHeader hdr{};
        const std::array<std::uint8_t, 3> payload{1, 2, 3};
        EXPECT_EQ(Yamux::ParsePayload(hdr, payload), Error::None);
        const std::array<std::uint8_t, 0> Empty{};
        EXPECT_EQ(Yamux::ParsePayload(hdr, Empty), Error::None);
    }

} // namespace
