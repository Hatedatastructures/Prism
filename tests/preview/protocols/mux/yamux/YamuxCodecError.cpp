/**
 * @file YamuxCodecError.cpp
 * @brief yamux 帧格式错误路径与往返测试（测试库 codec 层）
 * @details 覆盖：帧头长度边界（空/半帧 → need_more）、版本错误
 *          （非 0x00 → bad_magic）、未知类型（type 越界 → bad_message）、
 *          类型边界（data/winupd/ping/go_away 全合法）、流 ID 边界
 *          （0 / 0xFFFFFFFF）、长度边界（0 / 大值）、
 *          SYN/FIN/WinUpd/Ping 往返稳定。
 *          全部为纯函数同步测试，无协程无 I/O。
 */

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include <common/protocols/mux/yamux/codec.hpp>
#include <common/protocols/mux/yamux/types.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace preview;
    using namespace preview::mux;

    TEST(YamuxCodecError, ParseHeaderEmpty)
    {
        std::span<const std::uint8_t> empty;
        yamux::frame_header out{};
        EXPECT_EQ(yamux::parse_header(empty, out), error::need_more);
    }

    TEST(YamuxCodecError, ParseHeaderTooShort)
    {
        // 帧头 12 字节，仅 4 字节（半帧）
        const std::array<std::uint8_t, 4> short_buf{0x00, 0x01, 0x00, 0x00};
        yamux::frame_header out{};
        EXPECT_EQ(yamux::parse_header(short_buf, out), error::need_more);
    }

    TEST(YamuxCodecError, ParseHeaderBadVersion)
    {
        auto wire = yamux::build_syn(1, std::span<const std::uint8_t>{});
        wire[0] = 0x01; // 非法版本（协议仅 0x00）
        yamux::frame_header out{};
        EXPECT_EQ(yamux::parse_header(wire, out), error::bad_magic);
    }

    TEST(YamuxCodecError, ParseHeaderUnknownType)
    {
        auto wire = yamux::build_syn(1, std::span<const std::uint8_t>{});
        wire[1] = 0x09; // 未知类型（合法区间 0..3）
        yamux::frame_header out{};
        EXPECT_EQ(yamux::parse_header(wire, out), error::bad_message);
    }

    TEST(YamuxCodecError, ParseHeaderTypeBoundary)
    {
        // 0..3 = data/winupd/ping/go_away 全部合法
        for (int t = 0; t <= 3; ++t)
        {
            const yamux::frame_header hdr{
                .type = static_cast<yamux::message_type>(t), .flag = yamux::flags::none, .stream_id = 1};
            const auto wire = yamux::build(hdr);
            yamux::frame_header out{};
            EXPECT_EQ(yamux::parse_header(wire, out), error::none) << "type " << t << " 合法";
        }
        // 4（go_away 后第一个非法值）→ bad_message
        {
            const yamux::frame_header hdr{
                .type = static_cast<yamux::message_type>(4), .flag = yamux::flags::none, .stream_id = 1};
            const auto wire = yamux::build(hdr);
            yamux::frame_header out{};
            EXPECT_EQ(yamux::parse_header(wire, out), error::bad_message);
        }
    }

    TEST(YamuxCodecError, StreamIdBoundary)
    {
        // 0 与 0xFFFFFFFF 均可解析（yamux 无流 ID 保留位校验）
        for (const auto sid : {0u, 0xFFFFFFFFu})
        {
            const yamux::frame_header hdr{.flag = yamux::flags::none, .stream_id = sid};
            const auto wire = yamux::build(hdr);
            yamux::frame_header out{};
            EXPECT_EQ(yamux::parse_header(wire, out), error::none);
            EXPECT_EQ(out.stream_id, sid);
        }
    }

    TEST(YamuxCodecError, LengthBoundary)
    {
        // 帧头 length 字段 0 与 0xFFFFFFFF 往返（build_header 不自动填）
        for (const auto len : {0u, 0xFFFFFFFFu})
        {
            yamux::frame_header hdr{.type = yamux::message_type::data,
                                    .flag = yamux::flags::none,
                                    .stream_id = 1,
                                    .length = len};
            const auto wire = yamux::build_header(hdr);
            yamux::frame_header out{};
            EXPECT_EQ(yamux::parse_header(wire, out), error::none);
            EXPECT_EQ(out.length, len);
        }
    }

    TEST(YamuxCodecError, SynFinRoundtrip)
    {
        const auto syn = yamux::build_syn(7, std::span<const std::uint8_t>{});
        yamux::frame_header out{};
        EXPECT_EQ(yamux::parse_header(syn, out), error::none);
        EXPECT_EQ(out.type, yamux::message_type::data);
        EXPECT_TRUE(yamux::has_flag(out.flag, yamux::flags::syn));
        EXPECT_EQ(out.stream_id, 7u);

        const auto fin = yamux::build_fin(7);
        EXPECT_EQ(yamux::parse_header(fin, out), error::none);
        EXPECT_TRUE(yamux::has_flag(out.flag, yamux::flags::fin));
        EXPECT_EQ(out.stream_id, 7u);
    }

    TEST(YamuxCodecError, PingAndWindowUpdateRoundtrip)
    {
        // ping（请求标志）
        auto ping = yamux::build(yamux::frame_header{.type = yamux::message_type::ping,
                                                     .flag = yamux::flags::syn,
                                                     .stream_id = 0,
                                                     .length = 4});
        yamux::frame_header out{};
        EXPECT_EQ(yamux::parse_header(ping, out), error::none);
        EXPECT_EQ(out.type, yamux::message_type::ping);
        EXPECT_TRUE(yamux::has_flag(out.flag, yamux::flags::syn));

        // window update（ack 标志）
        const auto win = yamux::build(yamux::frame_header{.type = yamux::message_type::window_update,
                                                          .flag = yamux::flags::ack,
                                                          .stream_id = 3,
                                                          .length = 4});
        EXPECT_EQ(yamux::parse_header(win, out), error::none);
        EXPECT_EQ(out.type, yamux::message_type::window_update);
        EXPECT_EQ(out.stream_id, 3u);
        EXPECT_EQ(out.length, 4u);
    }

    TEST(YamuxCodecError, ParsePayloadAlwaysNone)
    {
        // yamux 负载无额外校验
        yamux::frame_header hdr{};
        const std::array<std::uint8_t, 3> payload{1, 2, 3};
        EXPECT_EQ(yamux::parse_payload(hdr, payload), error::none);
        const std::array<std::uint8_t, 0> empty{};
        EXPECT_EQ(yamux::parse_payload(hdr, empty), error::none);
    }

} // namespace
