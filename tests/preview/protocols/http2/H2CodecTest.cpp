/**
 * @file H2CodecTest.cpp
 * @brief HTTP/2 自包含实现测试（T2-6）
 * @details 覆盖：
 *          - 帧头编解码（长度/类型/标志/流 ID 边界）
 *          - 帧载荷编解码（SETTINGS/WINDOW_UPDATE/RST/GOAWAY）
 *          - HPACK 静态表索引/字面量编解码
 *          - 会话状态机（feed/collect 往返、流生命周期、坏帧拒绝）
 */

#include <common/protocols/http2/codec.hpp>
#include <common/protocols/http2/frame.hpp>
#include <common/protocols/http2/impl.hpp>
#include <common/protocols/http2/session.hpp>

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

namespace
{
    namespace h2 = preview::http2;
    namespace net = boost::asio;
    using h2::frame_header;
    using h2::frame_type;
    using preview::http2::header;
    using preview::http2::header_list;

    // ── 帧头编解码 ──

    TEST(H2Frame, HeaderEncodeDecode)
    {
        std::vector<std::byte> payload(100, std::byte{0xAB});
        auto frame = h2::build_frame(frame_type::data, h2::flag_end_stream, 5, payload);
        ASSERT_EQ(frame.size(), h2::frame_header_size + 100);

        const auto h = h2::parse_frame_header(frame);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->length, 100u);
        EXPECT_EQ(h->type, frame_type::data);
        EXPECT_EQ(h->flags, h2::flag_end_stream);
        EXPECT_EQ(h->stream_id, 5u);
    }

    TEST(H2Frame, StreamIdBoundary)
    {
        // 31 位上限 0x7FFFFFFF
        auto frame = h2::build_frame(frame_type::data, 0, 0x7FFFFFFF, {});
        const auto h = h2::parse_frame_header(frame);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->stream_id, 0x7FFFFFFFu);
    }

    TEST(H2Frame, TruncatedHeader)
    {
        std::vector<std::byte> short_frame(5, std::byte{0});
        EXPECT_FALSE(h2::parse_frame_header(short_frame).has_value());
    }

    TEST(H2Frame, SettingsRoundTrip)
    {
        std::vector<h2::settings_entry> entries = {
            {h2::settings_max_concurrent_streams, 100},
            {h2::settings_initial_window_size, 65535},
            {h2::settings_enable_push, 0},
        };
        auto encoded = h2::encode_settings(entries);
        auto decoded = h2::decode_settings(encoded);
        ASSERT_TRUE(decoded.has_value());
        ASSERT_EQ(decoded->size(), 3u);
        EXPECT_EQ((*decoded)[0].id, h2::settings_max_concurrent_streams);
        EXPECT_EQ((*decoded)[0].value, 100u);
        EXPECT_EQ((*decoded)[1].id, h2::settings_initial_window_size);
        EXPECT_EQ((*decoded)[2].value, 0u);
    }

    TEST(H2Frame, SettingsBadLength)
    {
        std::vector<std::byte> bad(7, std::byte{0});
        EXPECT_FALSE(h2::decode_settings(bad).has_value());
    }

    TEST(H2Frame, WindowUpdateAndRst)
    {
        auto wu = h2::encode_window_update(12345);
        EXPECT_EQ(h2::decode_u31(wu), 12345u);
        auto rst = h2::encode_rst_stream(h2::error_cancel);
        EXPECT_EQ(h2::decode_u31(rst), h2::error_cancel);
    }

    TEST(H2Frame, GoawayEncode)
    {
        h2::goaway_params params;
        params.last_stream_id = 7;
        params.error_code = h2::error_no_error;
        std::vector<std::byte> debug{std::byte{1}, std::byte{2}};
        params.debug = debug;
        auto encoded = h2::encode_goaway(params);
        ASSERT_EQ(encoded.size(), 10u);
        EXPECT_EQ(h2::decode_u31(std::span<const std::byte>(encoded.data(), 4)), 7u);
        EXPECT_EQ(h2::decode_u31(std::span<const std::byte>(encoded.data() + 4, 4)), h2::error_no_error);
    }

    // ── HPACK ──

    TEST(H2Hpack, StaticIndexLiteral)
    {
        h2::hpack_encoder encoder;
        h2::hpack_decoder decoder;

        header_list headers = {
            {":method", "GET"},   // 静态表索引 2
            {":path", "/"},       // 静态表索引 4
            {":authority", "example.com"}, // 名引用 1 + 值字面量
            {"custom-header", "custom-value"}, // 新名字面量
        };
        auto block = encoder.encode(headers);
        auto decoded = decoder.decode(block);
        ASSERT_TRUE(decoded.has_value());
        ASSERT_EQ(decoded->size(), 4u);
        EXPECT_EQ((*decoded)[0].name, ":method");
        EXPECT_EQ((*decoded)[0].value, "GET");
        EXPECT_EQ((*decoded)[1].name, ":path");
        EXPECT_EQ((*decoded)[1].value, "/");
        EXPECT_EQ((*decoded)[2].name, ":authority");
        EXPECT_EQ((*decoded)[2].value, "example.com");
        EXPECT_EQ((*decoded)[3].name, "custom-header");
        EXPECT_EQ((*decoded)[3].value, "custom-value");
    }

    TEST(H2Hpack, StaticTableLookup)
    {
        EXPECT_EQ(h2::lookup_static(":method", "GET"), 2u);
        EXPECT_EQ(h2::lookup_static(":status", "200"), 8u);
        EXPECT_EQ(h2::lookup_static(":method", "PUT"), 0u); // 值不匹配
        EXPECT_EQ(h2::lookup_static_name(":authority"), 1u);
        EXPECT_EQ(h2::lookup_static_name("unknown"), 0u);
    }

    TEST(H2Hpack, IntegerCodec)
    {
        std::vector<std::byte> out;
        h2::encode_int(10, 7, 0x80, out);
        std::size_t off = 0;
        EXPECT_EQ(h2::decode_int(out, 7, off), 10u);

        out.clear();
        h2::encode_int(200, 7, 0x80, out); // 需多字节
        off = 0;
        EXPECT_EQ(h2::decode_int(out, 7, off), 200u);

        out.clear();
        h2::encode_int(16384, 6, 0x40, out);
        off = 0;
        EXPECT_EQ(h2::decode_int(out, 6, off), 16384u);
    }

    // ── 会话状态机 ──

    TEST(H2Session, FeedCollectRoundTrip)
    {
        net::io_context ioc;
        auto client = std::make_shared<h2::session_impl>(ioc.get_executor(), false);
        auto server = std::make_shared<h2::session_impl>(ioc.get_executor(), true);

        // 客户端 SETTINGS + 开流 + 数据
        client->send_settings();
        const int stream_id = client->open_stream({{":method", "GET"}, {":path", "/"}}, false);
        EXPECT_GT(stream_id, 0);
        client->submit_data(stream_id, std::span<const std::byte>(), false); // 空数据
        const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        client->submit_data(stream_id, payload, true);

        // 收集客户端输出 → 投喂服务端
        std::vector<std::byte> wire;
        client->collect(wire);
        ASSERT_FALSE(wire.empty());

        int headers_seen = 0;
        int data_seen = 0;
        int closed_seen = 0;
        server->on_headers = [&](std::int32_t id, const header_list &hdrs, bool end_stream)
        {
            headers_seen = id;
            EXPECT_FALSE(end_stream);
            EXPECT_EQ(hdrs.size(), 2u);
        };
        server->on_data = [&](std::int32_t id, std::span<const std::byte> data) { data_seen += static_cast<int>(data.size()); };
        server->on_stream_close = [&](std::int32_t id, std::uint32_t ec) { closed_seen = id; EXPECT_EQ(ec, h2::error_no_error); };

        std::error_code ec;
        EXPECT_TRUE(server->feed(wire, ec));
        EXPECT_EQ(headers_seen, stream_id);
        EXPECT_EQ(data_seen, 3);
        EXPECT_EQ(closed_seen, stream_id);
    }

    TEST(H2Session, SettingsAckAutoReply)
    {
        net::io_context ioc;
        auto server = std::make_shared<h2::session_impl>(ioc.get_executor(), true);

        std::vector<h2::settings_entry> entries = {{h2::settings_max_concurrent_streams, 10}};
        auto payload = h2::encode_settings(entries);
        auto frame = h2::build_frame(frame_type::settings, 0, 0, payload);

        int settings_seen = 0;
        server->on_settings = [&](const std::vector<h2::settings_entry> &e) { settings_seen = static_cast<int>(e.size()); };
        std::error_code ec;
        EXPECT_TRUE(server->feed(frame, ec));
        EXPECT_EQ(settings_seen, 1);

        // ACK 帧入队
        std::vector<std::byte> out;
        server->collect(out);
        ASSERT_GE(out.size(), h2::frame_header_size);
        const auto h = h2::parse_frame_header(out);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->type, frame_type::settings);
        EXPECT_EQ(h->flags, h2::flag_ack);
    }

    TEST(H2Session, BadFrameRejected)
    {
        net::io_context ioc;
        auto server = std::make_shared<h2::session_impl>(ioc.get_executor(), true);

        // 流 0 上发 DATA → 协议错误
        std::vector<std::byte> payload(10, std::byte{0});
        auto bad = h2::build_frame(frame_type::data, 0, 0, payload);
        std::error_code ec;
        EXPECT_FALSE(server->feed(bad, ec));
        EXPECT_EQ(ec, preview::make_error_code(preview::error::protocol_error));
    }

    TEST(H2Session, ContinuationRejected)
    {
        net::io_context ioc;
        auto server = std::make_shared<h2::session_impl>(ioc.get_executor(), true);
        auto bad = h2::build_frame(frame_type::continuation, 0, 1, {});
        std::error_code ec;
        EXPECT_FALSE(server->feed(bad, ec));
    }

    TEST(H2Session, PingPong)
    {
        net::io_context ioc;
        auto server = std::make_shared<h2::session_impl>(ioc.get_executor(), true);
        std::array<std::byte, 8> opaque{};
        auto ping = h2::build_frame(frame_type::ping, 0, 0, opaque);
        std::error_code ec;
        EXPECT_TRUE(server->feed(ping, ec));
        std::vector<std::byte> out;
        server->collect(out);
        ASSERT_GE(out.size(), h2::frame_header_size);
        const auto h = h2::parse_frame_header(out);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->type, frame_type::ping);
        EXPECT_EQ(h->flags, h2::flag_ack);
    }
} // namespace
