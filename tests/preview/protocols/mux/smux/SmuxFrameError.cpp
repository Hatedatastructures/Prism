/**
 * @file SmuxFrameError.cpp
 * @brief smux 帧格式错误路径与往返测试（Preview 测试库 Codec 层）
 * @details 覆盖：非法命令（未知 cmd 字节）、版本错误、长度边界
 *          （uint16 上限内 0 / 65535）、帧截断（半帧 → need_more）、
 *          流 ID 边界（0 会话级 / 0xFFFFFFFF 最大值）、
 *          SYN/FIN 往返稳定，以及 smux 协议特性映射：
 *          - 无标志位字段（cmd 为单字节枚举，不存在 SYN+FIN 冲突输入）
 *          - 无窗口字段（长度字段即其等价边界）
 *          - 无 RST 帧（Codec::BuildRst 以 FIN 近似）
 *          全部为纯函数同步测试，无协程无 I/O。
 */

#include <array>
#include <cstdint>
#include <span>

#include <common/Protocols/Mux/Smux/Codec.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
    using namespace Preview::Mux;

    TEST(SmuxFrameError, ParseHeaderEmpty)
    {
        std::span<const std::uint8_t> Empty;
        Smux::FrameHeader out{};
        EXPECT_EQ(Smux::ParseHeader(Empty, out), Error::NeedMore)
            << "ParseHeader: Empty -> need_more";
    }

    TEST(SmuxFrameError, ParseHeaderTooShort)
    {
        // 帧头 8 字节，仅 4 字节（半帧）
        const std::array<std::uint8_t, 4> short_buf{0x01, 0x02, 0x03, 0x04};
        Smux::FrameHeader out{};
        EXPECT_EQ(Smux::ParseHeader(short_buf, out), Error::NeedMore)
            << "ParseHeader: 4 Bytes -> need_more";
    }

    TEST(SmuxFrameError, ParseHeaderBadVersion)
    {
        auto wire = Smux::BuildSyn(1);
        wire[0] = 0x02; // 非法版本（协议仅 0x01）
        Smux::FrameHeader out{};
        EXPECT_EQ(Smux::ParseHeader(wire, out), Error::BadMagic)
            << "ParseHeader: version 0x02 -> bad_magic";
    }

    TEST(SmuxFrameError, ParseHeaderUnknownCommand)
    {
        auto wire = Smux::BuildSyn(1);
        wire[1] = 0x09; // 未知命令（合法区间 0..3）
        Smux::FrameHeader out{};
        EXPECT_EQ(Smux::ParseHeader(wire, out), Error::BadMessage)
            << "ParseHeader: cmd 0x09 -> bad_message";
    }

    TEST(SmuxFrameError, ParseHeaderCommandBoundary)
    {
        // 0..3 = syn/fin/Push/nop 全部合法
        for (int cmd = 0; cmd <= 3; ++cmd)
        {
            const Smux::FrameHeader hdr{.cmd = static_cast<Smux::Command>(cmd), .StreamId = 1};
            const auto wire = Smux::Build(hdr);
            Smux::FrameHeader out{};
            EXPECT_EQ(Smux::ParseHeader(wire, out), Error::None) << "cmd " << cmd << " 合法";
        }
        // 4（nop 之后第一个非法值）→ bad_message
        {
            const Smux::FrameHeader hdr{.cmd = static_cast<Smux::Command>(4), .StreamId = 1};
            const auto wire = Smux::Build(hdr);
            Smux::FrameHeader out{};
            EXPECT_EQ(Smux::ParseHeader(wire, out), Error::BadMessage)
                << "ParseHeader: cmd 4 -> bad_message";
        }
    }

    TEST(SmuxFrameError, LengthZeroAndMaxBoundary)
    {
        // 零长度帧合法（SYN/FIN/NOP 均为零负载）
        {
            const Smux::FrameHeader hdr{.cmd = Smux::Command::Push, .length = 0, .StreamId = 1};
            const auto wire = Smux::Build(hdr);
            Smux::FrameHeader out{};
            EXPECT_EQ(Smux::ParseHeader(wire, out), Error::None);
            EXPECT_EQ(out.length, 0u) << "length 0 合法";
        }
        // 65535 = uint16 字段上限 = max_frame_length，合法
        {
            const Smux::FrameHeader hdr{.cmd = Smux::Command::Push, .length = 65535, .StreamId = 1};
            const auto wire = Smux::Build(hdr);
            Smux::FrameHeader out{};
            EXPECT_EQ(Smux::ParseHeader(wire, out), Error::None);
            EXPECT_EQ(out.length, 65535u) << "length 65535 = 上限合法";
        }
        // 长度字段为无符号 uint16，不存在"负长度"输入；
        // 2 字节字段最大值即协议上限，ParseHeader 的越界分支不可达
    }

    TEST(SmuxFrameError, TruncatedPayloadNeedMore)
    {
        Parser<Smux::Codec> p;
        const std::array<std::uint8_t, 3> payload{0xAA, 0xBB, 0xCC};
        const auto Frame = Smux::BuildPush(7, payload);
        // 帧头 8 字节 + 负载前 2 字节（截断）→ need_more
        EXPECT_EQ(p.Put(std::span(Frame).first(10)), Error::NeedMore)
            << "半帧负载 -> need_more";
        // 补全剩余负载 → 解析完成
        EXPECT_EQ(p.Put(std::span(Frame).subspan(10)), Error::None);
        ASSERT_TRUE(p.Done()) << "补全后解析完成";
        EXPECT_EQ(p.Frame().cmd, Smux::Command::Push);
        EXPECT_EQ(p.Frame().length, 3u);
        EXPECT_EQ(p.Frame().StreamId, 7u);
    }

    TEST(SmuxFrameError, ParserRejectsBadHeader)
    {
        Parser<Smux::Codec> p;
        const std::array<std::uint8_t, 8> hdr{0x01, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
        EXPECT_EQ(p.Put(hdr), Error::BadMessage) << "Parser: 非法命令 -> bad_message";
        EXPECT_TRUE(p.Failed()) << "Parser: 状态进入 Failed";
        // Failed 后拒绝继续喂数据
        EXPECT_EQ(p.Put(hdr), Error::ProtocolError) << "Parser: Failed 后 -> protocol_error";
    }

    TEST(SmuxFrameError, StreamIdBoundary)
    {
        // Stream 0 = 会话级（nop 心跳），合法
        {
            const Smux::FrameHeader hdr{.cmd = Smux::Command::Nop, .StreamId = 0};
            const auto wire = Smux::Build(hdr);
            Smux::FrameHeader out{};
            EXPECT_EQ(Smux::ParseHeader(wire, out), Error::None);
            EXPECT_EQ(out.StreamId, 0u);
            EXPECT_TRUE(Smux::Codec::IsControl(out)) << "nop 为会话级控制帧";
        }
        // 最大值 0xFFFFFFFF 原样往返（小端序）
        {
            const Smux::FrameHeader hdr{.cmd = Smux::Command::Push, .length = 0,
                                         .StreamId = 0xFFFFFFFFu};
            const auto wire = Smux::Build(hdr);
            Smux::FrameHeader out{};
            EXPECT_EQ(Smux::ParseHeader(wire, out), Error::None);
            EXPECT_EQ(out.StreamId, 0xFFFFFFFFu);
            EXPECT_EQ(wire[4], 0xFF) << "小端：StreamId 低字节在前";
            EXPECT_EQ(wire[7], 0xFF) << "小端：StreamId 高字节在后";
        }
    }

    TEST(SmuxFrameError, RoundtripSyn)
    {
        const auto Frame = Smux::BuildSyn(42);
        Smux::FrameHeader out{};
        EXPECT_EQ(Smux::ParseHeader(Frame, out), Error::None);
        EXPECT_EQ(out.version, Smux::ProtocolVersion) << "roundtrip syn: version=1";
        EXPECT_EQ(out.cmd, Smux::Command::Syn) << "roundtrip syn: cmd=syn";
        EXPECT_EQ(out.length, 0u) << "roundtrip syn: length=0";
        EXPECT_EQ(out.StreamId, 42u) << "roundtrip syn: StreamId=42";
    }

    TEST(SmuxFrameError, FinAndRstApproximation)
    {
        const auto fin = Smux::BuildFin(9);
        Smux::FrameHeader out{};
        EXPECT_EQ(Smux::ParseHeader(fin, out), Error::None);
        EXPECT_EQ(out.cmd, Smux::Command::Fin) << "roundtrip fin: cmd=fin";
        EXPECT_EQ(out.StreamId, 9u) << "roundtrip fin: StreamId=9";
        // smux 无 RST 帧：Codec::BuildRst 以 FIN 近似（对端按半关处理）；
        // cmd 为单字节枚举，不存在 SYN+FIN / RST+数据 标志位冲突输入
        const auto rst = Smux::Codec::BuildRst(9);
        Smux::FrameHeader rout{};
        EXPECT_EQ(Smux::ParseHeader(rst, rout), Error::None);
        EXPECT_EQ(rout.cmd, Smux::Command::Fin) << "BuildRst 近似为 FIN 帧";
        EXPECT_EQ(rout.StreamId, 9u);
    }

    TEST(SmuxFrameError, EventMapping)
    {
        const Smux::FrameHeader syn{.cmd = Smux::Command::Syn, .StreamId = 1};
        EXPECT_EQ(Smux::Codec::FrameEvent(syn), StreamEvent::Open) << "syn -> Open";
        EXPECT_FALSE(Smux::Codec::IsControl(syn)) << "syn 非控制帧";

        const Smux::FrameHeader fin{.cmd = Smux::Command::Fin, .StreamId = 1};
        EXPECT_EQ(Smux::Codec::FrameEvent(fin), StreamEvent::Fin) << "fin -> fin";

        const Smux::FrameHeader Push{.cmd = Smux::Command::Push, .StreamId = 1};
        EXPECT_EQ(Smux::Codec::FrameEvent(Push), StreamEvent::Data) << "Push -> Data";

        const Smux::FrameHeader nop{.cmd = Smux::Command::Nop, .StreamId = 0};
        EXPECT_EQ(Smux::Codec::FrameEvent(nop), StreamEvent::Rst) << "nop -> rst（忽略）";
        EXPECT_TRUE(Smux::Codec::IsControl(nop)) << "nop 为会话级控制帧";
    }

} // namespace
