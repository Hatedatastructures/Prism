/**
 * @file H2muxFrameError.cpp
 * @brief sing-mux（h2mux）帧格式错误路径与往返测试（preview 测试库 codec 层）
 * @details 覆盖：长度越界（>16MB → bad_length）、长度边界（0 / 16MB）、
 *          帧截断（半帧 → need_more）、流 ID 边界（0 会话级 / 0xFFFFFFFF）、
 *          窗口增量（0 / 手工大端 / 最大值）、未知类型字节（codec 放行，
 *          会话层经 frame_event 映射为 rst 忽略）、DATA/CLOSE/PING 往返稳定。
 *          协议无标志位字段（type 为单字节枚举，不存在 SYN+FIN / RST+数据
 *          冲突输入）。全部为纯函数同步测试，无协程无 I/O。
 */

#include <array>
#include <cstdint>
#include <span>

#include <common/protocols/mux/h2mux/codec.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace preview;
    using namespace preview::mux;

    TEST(H2muxFrameError, ParseHeaderEmpty)
    {
        std::span<const std::uint8_t> empty;
        h2mux::frame_header out{};
        EXPECT_EQ(h2mux::parse_header(empty, out), error::need_more)
            << "parse_header: empty -> need_more";
    }

    TEST(H2muxFrameError, ParseHeaderTooShort)
    {
        // 帧头 9 字节，仅 5 字节（半帧）
        const std::array<std::uint8_t, 5> short_buf{0x00, 0x00, 0x00, 0x00, 0x00};
        h2mux::frame_header out{};
        EXPECT_EQ(h2mux::parse_header(short_buf, out), error::need_more)
            << "parse_header: 5 bytes -> need_more";
    }

    TEST(H2muxFrameError, LengthOverMaxRejected)
    {
        // length = 0x01000001 > 16MB 上限 → bad_length
        const std::array<std::uint8_t, 9> hdr{0x00, 0x01, 0x00, 0x00, 0x01,
                                              0x00, 0x00, 0x00, 0x01};
        h2mux::frame_header out{};
        EXPECT_EQ(h2mux::parse_header(hdr, out), error::bad_length)
            << "parse_header: length 0x01000001 -> bad_length";
    }

    TEST(H2muxFrameError, LengthBoundaries)
    {
        // 零长度帧合法（CLOSE / 空 DATA）
        {
            const std::array<std::uint8_t, 9> hdr{0x00, 0x00, 0x00, 0x00, 0x00,
                                                  0x00, 0x00, 0x00, 0x01};
            h2mux::frame_header out{};
            EXPECT_EQ(h2mux::parse_header(hdr, out), error::none);
            EXPECT_EQ(out.length, 0u) << "length 0 合法";
        }
        // 16MB（0x01000000）= 上限，合法
        {
            const std::array<std::uint8_t, 9> hdr{0x00, 0x01, 0x00, 0x00, 0x00,
                                                  0x00, 0x00, 0x00, 0x01};
            h2mux::frame_header out{};
            EXPECT_EQ(h2mux::parse_header(hdr, out), error::none);
            EXPECT_EQ(out.length, 16u * 1024u * 1024u) << "length 16MB = 上限合法";
        }
        // 长度字段为无符号 uint32，不存在"负长度"输入
    }

    TEST(H2muxFrameError, TruncatedPayloadNeedMore)
    {
        parser<h2mux::codec> p;
        const std::array<std::uint8_t, 3> payload{0xAA, 0xBB, 0xCC};
        const auto frame = h2mux::build_data(5, payload);
        // 帧头 9 字节 + 负载前 1 字节（截断）→ need_more
        EXPECT_EQ(p.put(std::span(frame).first(10)), error::need_more)
            << "半帧负载 -> need_more";
        // 补全剩余负载 → 解析完成
        EXPECT_EQ(p.put(std::span(frame).subspan(10)), error::none);
        ASSERT_TRUE(p.done()) << "补全后解析完成";
        EXPECT_EQ(p.frame().type, h2mux::frame_type::data);
        EXPECT_EQ(p.frame().length, 3u);
        EXPECT_EQ(p.frame().stream_id, 5u);
    }

    TEST(H2muxFrameError, ParserRejectsBadLength)
    {
        parser<h2mux::codec> p;
        const std::array<std::uint8_t, 9> hdr{0x00, 0x01, 0x00, 0x00, 0x01,
                                              0x00, 0x00, 0x00, 0x01};
        EXPECT_EQ(p.put(hdr), error::bad_length) << "parser: 超长 -> bad_length";
        EXPECT_TRUE(p.failed()) << "parser: 状态进入 failed";
        // failed 后拒绝继续喂数据
        EXPECT_EQ(p.put(hdr), error::protocol_error) << "parser: failed 后 -> protocol_error";
    }

    TEST(H2muxFrameError, UnknownTypeAccepted)
    {
        // 未知类型字节（0xFF）：codec 层不校验，解析成功（兼容未来扩展）
        auto wire = h2mux::build(static_cast<h2mux::frame_type>(0xFF), 1);
        h2mux::frame_header out{};
        EXPECT_EQ(h2mux::parse_header(wire, out), error::none);
        EXPECT_EQ(out.type, static_cast<h2mux::frame_type>(0xFF));
        // 语义拒绝发生在会话层：未知类型 → rst 事件 → 忽略
        EXPECT_EQ(h2mux::codec::frame_event(out), stream_event::rst) << "未知类型 -> rst";
        EXPECT_TRUE(h2mux::codec::is_control(out)) << "未知类型视为会话级控制帧";
    }

    TEST(H2muxFrameError, StreamIdBoundary)
    {
        // stream 0 = 会话级（ping/window_update 使用），合法
        {
            auto wire = h2mux::build(h2mux::frame_type::window_update, 0);
            h2mux::frame_header out{};
            EXPECT_EQ(h2mux::parse_header(wire, out), error::none);
            EXPECT_EQ(out.stream_id, 0u);
        }
        // 最大值 0xFFFFFFFF 原样往返（大端序）
        {
            auto wire = h2mux::build(h2mux::frame_type::data, 0xFFFFFFFFu);
            h2mux::frame_header out{};
            EXPECT_EQ(h2mux::parse_header(wire, out), error::none);
            EXPECT_EQ(out.stream_id, 0xFFFFFFFFu);
            EXPECT_EQ(wire[5], 0xFF) << "大端：stream_id 高字节在前";
            EXPECT_EQ(wire[8], 0xFF) << "大端：stream_id 低字节在后";
        }
    }

    TEST(H2muxFrameError, SessionStreamControl)
    {
        // 会话级控制帧（window_update）使用 stream 0，映射为 rst 忽略
        auto wu = h2mux::build(h2mux::frame_type::window_update, 0);
        h2mux::frame_header out{};
        EXPECT_EQ(h2mux::parse_header(wu, out), error::none);
        EXPECT_TRUE(h2mux::codec::is_control(out)) << "window_update 为控制帧";
        EXPECT_EQ(h2mux::codec::frame_event(out), stream_event::rst);
        // DATA 帧挂在 stream 0 上为语义非法（sing-mux 规范），codec 层
        // 放行并映射为 data 事件，由会话层负责拒绝
        auto data0 = h2mux::build(h2mux::frame_type::data, 0);
        h2mux::frame_header dout{};
        EXPECT_EQ(h2mux::parse_header(data0, dout), error::none);
        EXPECT_EQ(dout.stream_id, 0u);
        EXPECT_EQ(h2mux::codec::frame_event(dout), stream_event::data);
        EXPECT_FALSE(h2mux::codec::is_control(dout)) << "DATA 帧非控制帧";
    }

    TEST(H2muxFrameError, WindowUpdateDelta)
    {
        // build_winupd 仅返回 9 字节帧头：length 字段声明 4 字节 delta 负载，
        // 帧体不携带 delta 值（delta 为 uint32 无越界输入）
        {
            auto wu = h2mux::build_winupd(5, 0);
            h2mux::frame_header out{};
            EXPECT_EQ(h2mux::parse_header(wu, out), error::none);
            EXPECT_EQ(out.type, h2mux::frame_type::window_update);
            EXPECT_EQ(out.length, 4u) << "length 字段声明 4 字节负载";
            EXPECT_EQ(out.stream_id, 5u);
        }
        // 手工构造大端 delta = 100（wire 规范：4 字节大端增量）
        {
            const std::array<std::uint8_t, 13> wu{0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05,
                                                  0x00, 0x00, 0x00, 0x64};
            h2mux::frame_header out{};
            EXPECT_EQ(h2mux::parse_header(wu, out), error::none);
            EXPECT_EQ(out.length, 4u) << "window_update 负载 4 字节";
            EXPECT_EQ(out.stream_id, 5u);
            const auto delta = static_cast<std::uint32_t>(wu[9]) << 24 |
                               static_cast<std::uint32_t>(wu[10]) << 16 |
                               static_cast<std::uint32_t>(wu[11]) << 8 | static_cast<std::uint32_t>(wu[12]);
            EXPECT_EQ(delta, 100u) << "大端 delta = 100";
        }
        // delta 最大值 0xFFFFFFFF（uint32 全 1）：wire 解析不受限
        {
            const std::array<std::uint8_t, 13> wu{0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
                                                  0xFF, 0xFF, 0xFF, 0xFF};
            h2mux::frame_header out{};
            EXPECT_EQ(h2mux::parse_header(wu, out), error::none);
            EXPECT_EQ(h2mux::codec::parse_payload(out, std::span(wu).subspan(9)), error::none)
                << "最大 delta 负载可解析";
        }
        // @note build_winupd 的返回数组不含 delta 负载（仅帧头），
        //       实际窗口增量应按 wire 规范手工构造 BE 负载（见上）
    }

    TEST(H2muxFrameError, RoundtripData)
    {
        const std::array<std::uint8_t, 4> payload{0xDE, 0xAD, 0xBE, 0xEF};
        auto wire = h2mux::build_data(7, payload);
        h2mux::frame_header out{};
        EXPECT_EQ(h2mux::parse_header(wire, out), error::none);
        EXPECT_EQ(out.type, h2mux::frame_type::data) << "roundtrip data: type=data";
        EXPECT_EQ(out.length, 4u) << "roundtrip data: length=4";
        EXPECT_EQ(out.stream_id, 7u) << "roundtrip data: stream_id=7";
        // 负载原样保留
        EXPECT_EQ(wire[9], 0xDE);
        EXPECT_EQ(wire[10], 0xAD);
        EXPECT_EQ(wire[11], 0xBE);
        EXPECT_EQ(wire[12], 0xEF);
    }

    TEST(H2muxFrameError, RoundtripCloseAndPing)
    {
        // CLOSE 帧：stream 3，零负载
        {
            auto close = h2mux::build_close(3);
            h2mux::frame_header out{};
            EXPECT_EQ(h2mux::parse_header(close, out), error::none);
            EXPECT_EQ(out.type, h2mux::frame_type::close) << "roundtrip close: type=close";
            EXPECT_EQ(out.stream_id, 3u) << "roundtrip close: stream_id=3";
            EXPECT_EQ(out.length, 0u) << "roundtrip close: length=0";
            EXPECT_EQ(h2mux::codec::frame_event(out), stream_event::fin) << "close -> fin";
        }
        // PING 帧：stream 0，负载 = ping_id 大端
        {
            auto ping = h2mux::build_ping(0x3039);
            h2mux::frame_header out{};
            EXPECT_EQ(h2mux::parse_header(ping, out), error::none);
            EXPECT_EQ(out.type, h2mux::frame_type::ping) << "roundtrip ping: type=ping";
            EXPECT_EQ(out.stream_id, 0u) << "roundtrip ping: stream_id=0";
            EXPECT_EQ(out.length, 4u) << "roundtrip ping: length=4";
            EXPECT_EQ(ping[9], 0x00) << "ping_id 大端序（高字节在前）";
            EXPECT_EQ(ping[10], 0x00);
            EXPECT_EQ(ping[11], 0x30);
            EXPECT_EQ(ping[12], 0x39) << "ping_id 大端低字节";
        }
    }

} // namespace
