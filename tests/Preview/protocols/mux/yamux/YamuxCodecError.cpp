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

#include <Preview/Protocols/Mux/Yamux/Codec.hpp>
#include <Preview/Protocols/Mux/Yamux/Types.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Yamux = Preview::Mux::Yamux;
    using Error = Preview::Error;

    TEST(YamuxCodecError, ParseHeaderEmpty)
    {
        const std::span<const std::uint8_t> Empty;
        Yamux::FrameHeader Output{};
        EXPECT_EQ(Yamux::ParseHeader(Empty, Output), Error::NeedMore);
    }

    TEST(YamuxCodecError, ParseHeaderTooShort)
    {
        // 帧头 12 字节，仅 4 字节（半帧）
        const std::array<std::uint8_t, 4> ShortBuffer{0x00, 0x01, 0x00, 0x00};
        Yamux::FrameHeader Output{};
        EXPECT_EQ(Yamux::ParseHeader(ShortBuffer, Output), Error::NeedMore);
    }

    TEST(YamuxCodecError, ParseHeaderBadVersion)
    {
        auto Wire = Yamux::BuildSyn(1, std::span<const std::uint8_t>{});
        Wire[0] = 0x01; // 非法版本（协议仅 0x00）
        Yamux::FrameHeader Output{};
        EXPECT_EQ(Yamux::ParseHeader(Wire, Output), Error::BadMagic);
    }

    TEST(YamuxCodecError, ParseHeaderUnknownType)
    {
        auto Wire = Yamux::BuildSyn(1, std::span<const std::uint8_t>{});
        Wire[1] = 0x09; // 未知类型（合法区间 0..3）
        Yamux::FrameHeader Output{};
        EXPECT_EQ(Yamux::ParseHeader(Wire, Output), Error::BadMessage);
    }

    TEST(YamuxCodecError, ParseHeaderTypeBoundary)
    {
        // 0..3 = Data/winupd/ping/go_away 全部合法
        for (int TypeValue = 0; TypeValue <= 3; ++TypeValue)
        {
            const Yamux::FrameHeader hdr{
                .Type = static_cast<Yamux::MessageType>(TypeValue), .flag = Yamux::Flags::None, .StreamId = 1};
            const auto Wire = Yamux::Build(hdr);
            Yamux::FrameHeader Output{};
            EXPECT_EQ(Yamux::ParseHeader(Wire, Output), Error::None) << "Type " << TypeValue << " 合法";
        }
        // 4（go_away 后第一个非法值）→ bad_message
        {
            const Yamux::FrameHeader Header{
                .Type = static_cast<Yamux::MessageType>(4), .flag = Yamux::Flags::None, .StreamId = 1};
            const auto Wire = Yamux::Build(Header);
            Yamux::FrameHeader Output{};
            EXPECT_EQ(Yamux::ParseHeader(Wire, Output), Error::BadMessage);
        }
    }

    TEST(YamuxCodecError, StreamIdBoundary)
    {
        // 0 与 0xFFFFFFFF 均可解析（yamux 无流 ID 保留位校验）
        for (const auto StreamId : {0u, 0xFFFFFFFFu})
        {
            const Yamux::FrameHeader Header{.flag = Yamux::Flags::None, .StreamId = StreamId};
            const auto Wire = Yamux::Build(Header);
            Yamux::FrameHeader Output{};
            EXPECT_EQ(Yamux::ParseHeader(Wire, Output), Error::None);
            EXPECT_EQ(Output.StreamId, StreamId);
        }
    }

    TEST(YamuxCodecError, LengthBoundary)
    {
        // 帧头 length 字段 0 与 0xFFFFFFFF 往返（BuildHeader 不自动填）
        for (const auto Length : {0u, 0xFFFFFFFFu})
        {
            Yamux::FrameHeader Header{.Type = Yamux::MessageType::Data,
                                    .flag = Yamux::Flags::None,
                                    .StreamId = 1,
                                    .length = Length};
            const auto Wire = Yamux::BuildHeader(Header);
            Yamux::FrameHeader Output{};
            EXPECT_EQ(Yamux::ParseHeader(Wire, Output), Error::None);
            EXPECT_EQ(Output.length, Length);
        }
    }

    TEST(YamuxCodecError, SynFinRoundtrip)
    {
        const auto Syn = Yamux::BuildSyn(7, std::span<const std::uint8_t>{});
        Yamux::FrameHeader Output{};
        EXPECT_EQ(Yamux::ParseHeader(Syn, Output), Error::None);
        EXPECT_EQ(Output.Type, Yamux::MessageType::Data);
        EXPECT_TRUE(Yamux::HasFlag(Output.flag, Yamux::Flags::Syn));
        EXPECT_EQ(Output.StreamId, 7u);

        const auto Fin = Yamux::BuildFin(7);
        EXPECT_EQ(Yamux::ParseHeader(Fin, Output), Error::None);
        EXPECT_TRUE(Yamux::HasFlag(Output.flag, Yamux::Flags::Fin));
        EXPECT_EQ(Output.StreamId, 7u);
    }

    TEST(YamuxCodecError, RejectsConflictingDataFlags)
    {
        const auto Conflicting = Yamux::Build(
            Yamux::FrameHeader{.Type = Yamux::MessageType::Data,
                               .flag = static_cast<Yamux::Flags>(
                                   static_cast<std::uint16_t>(Yamux::Flags::Fin) |
                                   static_cast<std::uint16_t>(Yamux::Flags::Rst)),
                               .StreamId = 1});
        Yamux::FrameHeader Output{};
        EXPECT_EQ(Yamux::ParseHeader(Conflicting, Output), Error::BadMessage);

        const auto SynFin = Yamux::Build(
            Yamux::FrameHeader{.Type = Yamux::MessageType::Data,
                               .flag = static_cast<Yamux::Flags>(
                                   static_cast<std::uint16_t>(Yamux::Flags::Syn) |
                                   static_cast<std::uint16_t>(Yamux::Flags::Fin)),
                               .StreamId = 1});
        EXPECT_EQ(Yamux::ParseHeader(SynFin, Output), Error::BadMessage);
    }

    TEST(YamuxCodecError, PingAndWindowUpdateRoundtrip)
    {
        // ping（请求标志）
        const auto Ping = Yamux::Build(Yamux::FrameHeader{.Type = Yamux::MessageType::Ping,
                                                     .flag = Yamux::Flags::Syn,
                                                     .StreamId = 0,
                                                     .length = 4});
        Yamux::FrameHeader Output{};
        EXPECT_EQ(Yamux::ParseHeader(Ping, Output), Error::None);
        EXPECT_EQ(Output.Type, Yamux::MessageType::Ping);
        EXPECT_TRUE(Yamux::HasFlag(Output.flag, Yamux::Flags::Syn));

        // window Update（ack 标志）
        const auto Window = Yamux::Build(Yamux::FrameHeader{.Type = Yamux::MessageType::WindowUpdate,
                                                          .flag = Yamux::Flags::Ack,
                                                          .StreamId = 3,
                                                          .length = 4});
        EXPECT_EQ(Yamux::ParseHeader(Window, Output), Error::None);
        EXPECT_EQ(Output.Type, Yamux::MessageType::WindowUpdate);
        EXPECT_EQ(Output.StreamId, 3u);
        EXPECT_EQ(Output.length, 4u);
    }

    TEST(YamuxCodecError, ParsePayloadAlwaysNone)
    {
        // yamux 负载无额外校验
        Yamux::FrameHeader Header{};
        const std::array<std::uint8_t, 3> Payload{1, 2, 3};
        EXPECT_EQ(Yamux::ParsePayload(Header, Payload), Error::None);
        const std::array<std::uint8_t, 0> Empty{};
        EXPECT_EQ(Yamux::ParsePayload(Header, Empty), Error::None);
    }

} // namespace
