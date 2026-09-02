/**
 * @file H2muxFrameError.cpp
 * @brief sing-mux（h2mux）帧格式错误路径与往返测试（Preview 测试库 Codec 层）
 * @details 覆盖：长度越界（>16MB → bad_length）、长度边界（0 / 16MB）、
 *          帧截断（半帧 → need_more）、流 ID 边界（0 会话级 / 0xFFFFFFFF）、
 *          窗口增量（0 / 手工大端 / 最大值）、未知类型字节（Codec 放行，
 *          会话层经 FrameEvent 映射为 rst 忽略）、DATA/CLOSE/PING 往返稳定。
 *          协议无标志位字段（Type 为单字节枚举，不存在 SYN+FIN / RST+数据
 *          冲突输入）。全部为纯函数同步测试，无协程无 I/O。
 */

#include <array>
#include <cstdint>
#include <span>

#include <preview/Protocols/Mux/H2Mux/Codec.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
    using namespace Preview::Mux;

    TEST(H2muxFrameError, ParseHeaderEmpty)
    {
        std::span<const std::uint8_t> Empty;
        H2Mux::FrameHeader out{};
        EXPECT_EQ(H2Mux::ParseHeader(Empty, out), Error::NeedMore)
            << "ParseHeader: Empty -> need_more";
    }

    TEST(H2muxFrameError, ParseHeaderTooShort)
    {
        // 帧头 9 字节，仅 5 字节（半帧）
        const std::array<std::uint8_t, 5> short_buf{0x00, 0x00, 0x00, 0x00, 0x00};
        H2Mux::FrameHeader out{};
        EXPECT_EQ(H2Mux::ParseHeader(short_buf, out), Error::NeedMore)
            << "ParseHeader: 5 Bytes -> need_more";
    }

    TEST(H2muxFrameError, LengthOverMaxRejected)
    {
        // length = 0x01000001 > 16MB 上限 → bad_length
        const std::array<std::uint8_t, 9> hdr{0x00, 0x01, 0x00, 0x00, 0x01,
                                              0x00, 0x00, 0x00, 0x01};
        H2Mux::FrameHeader out{};
        EXPECT_EQ(H2Mux::ParseHeader(hdr, out), Error::BadLength)
            << "ParseHeader: length 0x01000001 -> bad_length";
    }

    TEST(H2muxFrameError, LengthBoundaries)
    {
        // 零长度帧合法（CLOSE / 空 DATA）
        {
            const std::array<std::uint8_t, 9> hdr{0x00, 0x00, 0x00, 0x00, 0x00,
                                                  0x00, 0x00, 0x00, 0x01};
            H2Mux::FrameHeader out{};
            EXPECT_EQ(H2Mux::ParseHeader(hdr, out), Error::None);
            EXPECT_EQ(out.length, 0u) << "length 0 合法";
        }
        // 16MB（0x01000000）= 上限，合法
        {
            const std::array<std::uint8_t, 9> hdr{0x00, 0x01, 0x00, 0x00, 0x00,
                                                  0x00, 0x00, 0x00, 0x01};
            H2Mux::FrameHeader out{};
            EXPECT_EQ(H2Mux::ParseHeader(hdr, out), Error::None);
            EXPECT_EQ(out.length, 16u * 1024u * 1024u) << "length 16MB = 上限合法";
        }
        // 长度字段为无符号 uint32，不存在"负长度"输入
    }

    TEST(H2muxFrameError, TruncatedPayloadNeedMore)
    {
        Parser<H2Mux::Codec> p;
        const std::array<std::uint8_t, 3> payload{0xAA, 0xBB, 0xCC};
        const auto Frame = H2Mux::BuildData(5, payload);
        // 帧头 9 字节 + 负载前 1 字节（截断）→ need_more
        EXPECT_EQ(p.Put(std::span(Frame).first(10)), Error::NeedMore)
            << "半帧负载 -> need_more";
        // 补全剩余负载 → 解析完成
        EXPECT_EQ(p.Put(std::span(Frame).subspan(10)), Error::None);
        ASSERT_TRUE(p.Done()) << "补全后解析完成";
        EXPECT_EQ(p.Frame().Type, H2Mux::FrameType::Data);
        EXPECT_EQ(p.Frame().length, 3u);
        EXPECT_EQ(p.Frame().StreamId, 5u);
    }

    TEST(H2muxFrameError, ParserRejectsBadLength)
    {
        Parser<H2Mux::Codec> p;
        const std::array<std::uint8_t, 9> hdr{0x00, 0x01, 0x00, 0x00, 0x01,
                                              0x00, 0x00, 0x00, 0x01};
        EXPECT_EQ(p.Put(hdr), Error::BadLength) << "Parser: 超长 -> bad_length";
        EXPECT_TRUE(p.Failed()) << "Parser: 状态进入 Failed";
        // Failed 后拒绝继续喂数据
        EXPECT_EQ(p.Put(hdr), Error::ProtocolError) << "Parser: Failed 后 -> protocol_error";
    }

    TEST(H2muxFrameError, UnknownTypeAccepted)
    {
        // 未知类型字节（0xFF）：Codec 层不校验，解析成功（兼容未来扩展）
        auto wire = H2Mux::Build(static_cast<H2Mux::FrameType>(0xFF), 1);
        H2Mux::FrameHeader out{};
        EXPECT_EQ(H2Mux::ParseHeader(wire, out), Error::None);
        EXPECT_EQ(out.Type, static_cast<H2Mux::FrameType>(0xFF));
        // 语义拒绝发生在会话层：未知类型 → rst 事件 → 忽略
        EXPECT_EQ(H2Mux::Codec::FrameEvent(out), StreamEvent::Rst) << "未知类型 -> rst";
        EXPECT_TRUE(H2Mux::Codec::IsControl(out)) << "未知类型视为会话级控制帧";
    }

    TEST(H2muxFrameError, StreamIdBoundary)
    {
        // Stream 0 = 会话级（ping/window_update 使用），合法
        {
            auto wire = H2Mux::Build(H2Mux::FrameType::WindowUpdate, 0);
            H2Mux::FrameHeader out{};
            EXPECT_EQ(H2Mux::ParseHeader(wire, out), Error::None);
            EXPECT_EQ(out.StreamId, 0u);
        }
        // 最大值 0xFFFFFFFF 原样往返（大端序）
        {
            auto wire = H2Mux::Build(H2Mux::FrameType::Data, 0xFFFFFFFFu);
            H2Mux::FrameHeader out{};
            EXPECT_EQ(H2Mux::ParseHeader(wire, out), Error::None);
            EXPECT_EQ(out.StreamId, 0xFFFFFFFFu);
            EXPECT_EQ(wire[5], 0xFF) << "大端：StreamId 高字节在前";
            EXPECT_EQ(wire[8], 0xFF) << "大端：StreamId 低字节在后";
        }
    }

    TEST(H2muxFrameError, SessionStreamControl)
    {
        // 会话级控制帧（window_update）使用 Stream 0，映射为 rst 忽略
        auto wu = H2Mux::Build(H2Mux::FrameType::WindowUpdate, 0);
        H2Mux::FrameHeader out{};
        EXPECT_EQ(H2Mux::ParseHeader(wu, out), Error::None);
        EXPECT_TRUE(H2Mux::Codec::IsControl(out)) << "window_update 为控制帧";
        EXPECT_EQ(H2Mux::Codec::FrameEvent(out), StreamEvent::Rst);
        // DATA 帧挂在 Stream 0 上为语义非法（sing-mux 规范），Codec 层
        // 放行并映射为 Data 事件，由会话层负责拒绝
        auto data0 = H2Mux::Build(H2Mux::FrameType::Data, 0);
        H2Mux::FrameHeader dout{};
        EXPECT_EQ(H2Mux::ParseHeader(data0, dout), Error::None);
        EXPECT_EQ(dout.StreamId, 0u);
        EXPECT_EQ(H2Mux::Codec::FrameEvent(dout), StreamEvent::Data);
        EXPECT_FALSE(H2Mux::Codec::IsControl(dout)) << "DATA 帧非控制帧";
    }

    TEST(H2muxFrameError, WindowUpdateDelta)
    {
        // WindowUpdate 帧包含 9 字节帧头和 4 字节大端 delta 负载。
        {
            auto wu = H2Mux::BuildWinupd(5, 0);
            H2Mux::FrameHeader out{};
            EXPECT_EQ(H2Mux::ParseHeader(wu, out), Error::None);
            EXPECT_EQ(out.Type, H2Mux::FrameType::WindowUpdate);
            EXPECT_EQ(out.length, 4u) << "length 字段声明 4 字节负载";
            EXPECT_EQ(out.StreamId, 5u);
            EXPECT_EQ(wu.size(), 13u);
            EXPECT_EQ(wu[9], 0u);
            EXPECT_EQ(wu[12], 0u);
        }
        // 手工构造大端 delta = 100（wire 规范：4 字节大端增量）
        {
            const std::array<std::uint8_t, 13> wu{0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05,
                                                  0x00, 0x00, 0x00, 0x64};
            H2Mux::FrameHeader out{};
            EXPECT_EQ(H2Mux::ParseHeader(wu, out), Error::None);
            EXPECT_EQ(out.length, 4u) << "window_update 负载 4 字节";
            EXPECT_EQ(out.StreamId, 5u);
            const auto delta = static_cast<std::uint32_t>(wu[9]) << 24 |
                               static_cast<std::uint32_t>(wu[10]) << 16 |
                               static_cast<std::uint32_t>(wu[11]) << 8 | static_cast<std::uint32_t>(wu[12]);
            EXPECT_EQ(delta, 100u) << "大端 delta = 100";
        }
        // delta 最大值 0xFFFFFFFF（uint32 全 1）：wire 解析不受限
        {
            const std::array<std::uint8_t, 13> wu{0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
                                                  0xFF, 0xFF, 0xFF, 0xFF};
            H2Mux::FrameHeader out{};
            EXPECT_EQ(H2Mux::ParseHeader(wu, out), Error::None);
            EXPECT_EQ(H2Mux::Codec::ParsePayload(out, std::span(wu).subspan(9)), Error::None)
                << "最大 delta 负载可解析";
        }
        // @note BuildPing 的返回数组不含 delta 负载（仅帧头），
        //       实际窗口增量应按 wire 规范手工构造 BE 负载（见上）
    }

    TEST(H2muxFrameError, RoundtripData)
    {
        const std::array<std::uint8_t, 4> payload{0xDE, 0xAD, 0xBE, 0xEF};
        auto wire = H2Mux::BuildData(7, payload);
        H2Mux::FrameHeader out{};
        EXPECT_EQ(H2Mux::ParseHeader(wire, out), Error::None);
        EXPECT_EQ(out.Type, H2Mux::FrameType::Data) << "roundtrip Data: Type=Data";
        EXPECT_EQ(out.length, 4u) << "roundtrip Data: length=4";
        EXPECT_EQ(out.StreamId, 7u) << "roundtrip Data: StreamId=7";
        // 负载原样保留
        EXPECT_EQ(wire[9], 0xDE);
        EXPECT_EQ(wire[10], 0xAD);
        EXPECT_EQ(wire[11], 0xBE);
        EXPECT_EQ(wire[12], 0xEF);
    }

    TEST(H2muxFrameError, RoundtripCloseAndPing)
    {
        // CLOSE 帧：Stream 3，零负载
        {
            auto Close = H2Mux::BuildClose(3);
            H2Mux::FrameHeader out{};
            EXPECT_EQ(H2Mux::ParseHeader(Close, out), Error::None);
            EXPECT_EQ(out.Type, H2Mux::FrameType::Close) << "roundtrip Close: Type=Close";
            EXPECT_EQ(out.StreamId, 3u) << "roundtrip Close: StreamId=3";
            EXPECT_EQ(out.length, 0u) << "roundtrip Close: length=0";
            EXPECT_EQ(H2Mux::Codec::FrameEvent(out), StreamEvent::Fin) << "Close -> fin";
        }
        // PING 帧：Stream 0，负载 = PingId 大端
        {
            auto ping = H2Mux::BuildPing(0x3039);
            H2Mux::FrameHeader out{};
            EXPECT_EQ(H2Mux::ParseHeader(ping, out), Error::None);
            EXPECT_EQ(out.Type, H2Mux::FrameType::Ping) << "roundtrip ping: Type=ping";
            EXPECT_EQ(out.StreamId, 0u) << "roundtrip ping: StreamId=0";
            EXPECT_EQ(out.length, 4u) << "roundtrip ping: length=4";
            EXPECT_EQ(ping[9], 0x00) << "PingId 大端序（高字节在前）";
            EXPECT_EQ(ping[10], 0x00);
            EXPECT_EQ(ping[11], 0x30);
            EXPECT_EQ(ping[12], 0x39) << "PingId 大端低字节";
        }
    }

} // namespace
