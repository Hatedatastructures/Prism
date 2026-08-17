/**
 * @file SmuxFrameError.cpp
 * @brief smux 帧格式错误路径与往返测试（preview 测试库 codec 层）
 * @details 覆盖：非法命令（未知 cmd 字节）、版本错误、长度边界
 *          （uint16 上限内 0 / 65535）、帧截断（半帧 → need_more）、
 *          流 ID 边界（0 会话级 / 0xFFFFFFFF 最大值）、
 *          SYN/FIN 往返稳定，以及 smux 协议特性映射：
 *          - 无标志位字段（cmd 为单字节枚举，不存在 SYN+FIN 冲突输入）
 *          - 无窗口字段（长度字段即其等价边界）
 *          - 无 RST 帧（codec::build_rst 以 FIN 近似）
 *          全部为纯函数同步测试，无协程无 I/O。
 */

#include <array>
#include <cstdint>
#include <span>

#include <common/protocols/mux/smux/codec.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace preview;
    using namespace preview::mux;

    TEST(SmuxFrameError, ParseHeaderEmpty)
    {
        std::span<const std::uint8_t> empty;
        smux::frame_header out{};
        EXPECT_EQ(smux::parse_header(empty, out), error::need_more)
            << "parse_header: empty -> need_more";
    }

    TEST(SmuxFrameError, ParseHeaderTooShort)
    {
        // 帧头 8 字节，仅 4 字节（半帧）
        const std::array<std::uint8_t, 4> short_buf{0x01, 0x02, 0x03, 0x04};
        smux::frame_header out{};
        EXPECT_EQ(smux::parse_header(short_buf, out), error::need_more)
            << "parse_header: 4 bytes -> need_more";
    }

    TEST(SmuxFrameError, ParseHeaderBadVersion)
    {
        auto wire = smux::build_syn(1);
        wire[0] = 0x02; // 非法版本（协议仅 0x01）
        smux::frame_header out{};
        EXPECT_EQ(smux::parse_header(wire, out), error::bad_magic)
            << "parse_header: version 0x02 -> bad_magic";
    }

    TEST(SmuxFrameError, ParseHeaderUnknownCommand)
    {
        auto wire = smux::build_syn(1);
        wire[1] = 0x09; // 未知命令（合法区间 0..3）
        smux::frame_header out{};
        EXPECT_EQ(smux::parse_header(wire, out), error::bad_message)
            << "parse_header: cmd 0x09 -> bad_message";
    }

    TEST(SmuxFrameError, ParseHeaderCommandBoundary)
    {
        // 0..3 = syn/fin/push/nop 全部合法
        for (int cmd = 0; cmd <= 3; ++cmd)
        {
            const smux::frame_header hdr{.cmd = static_cast<smux::command>(cmd), .stream_id = 1};
            const auto wire = smux::build(hdr);
            smux::frame_header out{};
            EXPECT_EQ(smux::parse_header(wire, out), error::none) << "cmd " << cmd << " 合法";
        }
        // 4（nop 之后第一个非法值）→ bad_message
        {
            const smux::frame_header hdr{.cmd = static_cast<smux::command>(4), .stream_id = 1};
            const auto wire = smux::build(hdr);
            smux::frame_header out{};
            EXPECT_EQ(smux::parse_header(wire, out), error::bad_message)
                << "parse_header: cmd 4 -> bad_message";
        }
    }

    TEST(SmuxFrameError, LengthZeroAndMaxBoundary)
    {
        // 零长度帧合法（SYN/FIN/NOP 均为零负载）
        {
            const smux::frame_header hdr{.cmd = smux::command::push, .length = 0, .stream_id = 1};
            const auto wire = smux::build(hdr);
            smux::frame_header out{};
            EXPECT_EQ(smux::parse_header(wire, out), error::none);
            EXPECT_EQ(out.length, 0u) << "length 0 合法";
        }
        // 65535 = uint16 字段上限 = max_frame_length，合法
        {
            const smux::frame_header hdr{.cmd = smux::command::push, .length = 65535, .stream_id = 1};
            const auto wire = smux::build(hdr);
            smux::frame_header out{};
            EXPECT_EQ(smux::parse_header(wire, out), error::none);
            EXPECT_EQ(out.length, 65535u) << "length 65535 = 上限合法";
        }
        // 长度字段为无符号 uint16，不存在"负长度"输入；
        // 2 字节字段最大值即协议上限，parse_header 的越界分支不可达
    }

    TEST(SmuxFrameError, TruncatedPayloadNeedMore)
    {
        parser<smux::codec> p;
        const std::array<std::uint8_t, 3> payload{0xAA, 0xBB, 0xCC};
        const auto frame = smux::build_push(7, payload);
        // 帧头 8 字节 + 负载前 2 字节（截断）→ need_more
        EXPECT_EQ(p.put(std::span(frame).first(10)), error::need_more)
            << "半帧负载 -> need_more";
        // 补全剩余负载 → 解析完成
        EXPECT_EQ(p.put(std::span(frame).subspan(10)), error::none);
        ASSERT_TRUE(p.done()) << "补全后解析完成";
        EXPECT_EQ(p.frame().cmd, smux::command::push);
        EXPECT_EQ(p.frame().length, 3u);
        EXPECT_EQ(p.frame().stream_id, 7u);
    }

    TEST(SmuxFrameError, ParserRejectsBadHeader)
    {
        parser<smux::codec> p;
        const std::array<std::uint8_t, 8> hdr{0x01, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
        EXPECT_EQ(p.put(hdr), error::bad_message) << "parser: 非法命令 -> bad_message";
        EXPECT_TRUE(p.failed()) << "parser: 状态进入 failed";
        // failed 后拒绝继续喂数据
        EXPECT_EQ(p.put(hdr), error::protocol_error) << "parser: failed 后 -> protocol_error";
    }

    TEST(SmuxFrameError, StreamIdBoundary)
    {
        // stream 0 = 会话级（nop 心跳），合法
        {
            const smux::frame_header hdr{.cmd = smux::command::nop, .stream_id = 0};
            const auto wire = smux::build(hdr);
            smux::frame_header out{};
            EXPECT_EQ(smux::parse_header(wire, out), error::none);
            EXPECT_EQ(out.stream_id, 0u);
            EXPECT_TRUE(smux::codec::is_control(out)) << "nop 为会话级控制帧";
        }
        // 最大值 0xFFFFFFFF 原样往返（小端序）
        {
            const smux::frame_header hdr{.cmd = smux::command::push, .length = 0,
                                         .stream_id = 0xFFFFFFFFu};
            const auto wire = smux::build(hdr);
            smux::frame_header out{};
            EXPECT_EQ(smux::parse_header(wire, out), error::none);
            EXPECT_EQ(out.stream_id, 0xFFFFFFFFu);
            EXPECT_EQ(wire[4], 0xFF) << "小端：stream_id 低字节在前";
            EXPECT_EQ(wire[7], 0xFF) << "小端：stream_id 高字节在后";
        }
    }

    TEST(SmuxFrameError, RoundtripSyn)
    {
        const auto frame = smux::build_syn(42);
        smux::frame_header out{};
        EXPECT_EQ(smux::parse_header(frame, out), error::none);
        EXPECT_EQ(out.version, smux::protocol_version) << "roundtrip syn: version=1";
        EXPECT_EQ(out.cmd, smux::command::syn) << "roundtrip syn: cmd=syn";
        EXPECT_EQ(out.length, 0u) << "roundtrip syn: length=0";
        EXPECT_EQ(out.stream_id, 42u) << "roundtrip syn: stream_id=42";
    }

    TEST(SmuxFrameError, FinAndRstApproximation)
    {
        const auto fin = smux::build_fin(9);
        smux::frame_header out{};
        EXPECT_EQ(smux::parse_header(fin, out), error::none);
        EXPECT_EQ(out.cmd, smux::command::fin) << "roundtrip fin: cmd=fin";
        EXPECT_EQ(out.stream_id, 9u) << "roundtrip fin: stream_id=9";
        // smux 无 RST 帧：codec::build_rst 以 FIN 近似（对端按半关处理）；
        // cmd 为单字节枚举，不存在 SYN+FIN / RST+数据 标志位冲突输入
        const auto rst = smux::codec::build_rst(9);
        smux::frame_header rout{};
        EXPECT_EQ(smux::parse_header(rst, rout), error::none);
        EXPECT_EQ(rout.cmd, smux::command::fin) << "build_rst 近似为 FIN 帧";
        EXPECT_EQ(rout.stream_id, 9u);
    }

    TEST(SmuxFrameError, EventMapping)
    {
        const smux::frame_header syn{.cmd = smux::command::syn, .stream_id = 1};
        EXPECT_EQ(smux::codec::frame_event(syn), stream_event::open) << "syn -> open";
        EXPECT_FALSE(smux::codec::is_control(syn)) << "syn 非控制帧";

        const smux::frame_header fin{.cmd = smux::command::fin, .stream_id = 1};
        EXPECT_EQ(smux::codec::frame_event(fin), stream_event::fin) << "fin -> fin";

        const smux::frame_header push{.cmd = smux::command::push, .stream_id = 1};
        EXPECT_EQ(smux::codec::frame_event(push), stream_event::data) << "push -> data";

        const smux::frame_header nop{.cmd = smux::command::nop, .stream_id = 0};
        EXPECT_EQ(smux::codec::frame_event(nop), stream_event::rst) << "nop -> rst（忽略）";
        EXPECT_TRUE(smux::codec::is_control(nop)) << "nop 为会话级控制帧";
    }

} // namespace
