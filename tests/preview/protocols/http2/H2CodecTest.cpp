/**
 * @file H2CodecTest.cpp
 * @brief HTTP/2 自包含实现测试（T2-6）
 * @details 覆盖：
 *          - 帧头编解码（长度/类型/标志/流 ID 边界）
 *          - 帧载荷编解码（SETTINGS/WINDOW_UPDATE/RST/GOAWAY）
 *          - HPACK 静态表索引/字面量编解码
 *          - 会话状态机（Feed/Collect 往返、流生命周期、坏帧拒绝）
 */

#include <common/Protocols/Http2/Codec.hpp>
#include <common/Protocols/Http2/Frame.hpp>
#include <common/Protocols/Http2/Impl.hpp>
#include <common/Protocols/Http2/Session.hpp>

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

namespace
{
    namespace h2 = std::Http2;
    namespace net = boost::asio;
    using h2::FrameHeader;
    using h2::FrameType;
    using std::Http2::Header;
    using std::Http2::HeaderList;

    // ── 帧头编解码 ──

    TEST(H2Frame, HeaderEncodeDecode)
    {
        std::vector<std::byte> payload(100, std::byte{0xAB});
        auto Frame = h2::BuildFrame(FrameType::Data, h2::flag_end_stream, 5, payload);
        ASSERT_EQ(Frame.size(), h2::frame_header_size + 100);

        const auto h = h2::ParseFrameHeader(Frame);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->length, 100u);
        EXPECT_EQ(h->Type, FrameType::Data);
        EXPECT_EQ(h->Flags, h2::flag_end_stream);
        EXPECT_EQ(h->StreamId, 5u);
    }

    TEST(H2Frame, StreamIdBoundary)
    {
        // 31 位上限 0x7FFFFFFF
        auto Frame = h2::BuildFrame(FrameType::Data, 0, 0x7FFFFFFF, {});
        const auto h = h2::ParseFrameHeader(Frame);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->StreamId, 0x7FFFFFFFu);
    }

    TEST(H2Frame, TruncatedHeader)
    {
        std::vector<std::byte> short_frame(5, std::byte{0});
        EXPECT_FALSE(h2::ParseFrameHeader(short_frame).has_value());
    }

    TEST(H2Frame, SettingsRoundTrip)
    {
        std::vector<h2::SettingsEntry> entries = {
            {h2::settings_max_concurrent_streams, 100},
            {h2::settings_initial_window_size, 65535},
            {h2::settings_enable_push, 0},
        };
        auto encoded = h2::EncodeSettings(entries);
        auto decoded = h2::DecodeSettings(encoded);
        ASSERT_TRUE(decoded.has_value());
        ASSERT_EQ(decoded->size(), 3u);
        EXPECT_EQ((*decoded)[0].Id, h2::settings_max_concurrent_streams);
        EXPECT_EQ((*decoded)[0].value, 100u);
        EXPECT_EQ((*decoded)[1].Id, h2::settings_initial_window_size);
        EXPECT_EQ((*decoded)[2].value, 0u);
    }

    TEST(H2Frame, SettingsBadLength)
    {
        std::vector<std::byte> bad(7, std::byte{0});
        EXPECT_FALSE(h2::DecodeSettings(bad).has_value());
    }

    TEST(H2Frame, WindowUpdateAndRst)
    {
        auto wu = h2::EncodeWindowUpdate(12345);
        EXPECT_EQ(h2::DecodeU31(wu), 12345u);
        auto rst = h2::EncodeRstStream(h2::error_cancel);
        EXPECT_EQ(h2::DecodeU31(rst), h2::error_cancel);
    }

    TEST(H2Frame, GoawayEncode)
    {
        h2::GoawayParams params;
        params.LastStreamId = 7;
        params.ErrorCode = h2::error_no_error;
        std::vector<std::byte> Debug{std::byte{1}, std::byte{2}};
        params.Debug = Debug;
        auto encoded = h2::EncodeGoaway(params);
        ASSERT_EQ(encoded.size(), 10u);
        EXPECT_EQ(h2::DecodeU31(std::span<const std::byte>(encoded.data(), 4)), 7u);
        EXPECT_EQ(h2::DecodeU31(std::span<const std::byte>(encoded.data() + 4, 4)), h2::error_no_error);
    }

    // ── HPACK ──

    TEST(H2Hpack, StaticIndexLiteral)
    {
        h2::HpackEncoder encoder;
        h2::HpackDecoder decoded;

        HeaderList headers = {
            {":Method", "GET"},   // 静态表索引 2
            {":Path", "/"},       // 静态表索引 4
            {":authority", "example.com"}, // 名引用 1 + 值字面量
            {"custom-Header", "custom-value"}, // 新名字面量
        };
        auto block = encoder.Encode(headers);
        auto decoded = decoded.Decode(block);
        ASSERT_TRUE(decoded.has_value());
        ASSERT_EQ(decoded->size(), 4u);
        EXPECT_EQ((*decoded)[0].Name, ":Method");
        EXPECT_EQ((*decoded)[0].value, "GET");
        EXPECT_EQ((*decoded)[1].Name, ":Path");
        EXPECT_EQ((*decoded)[1].value, "/");
        EXPECT_EQ((*decoded)[2].Name, ":authority");
        EXPECT_EQ((*decoded)[2].value, "example.com");
        EXPECT_EQ((*decoded)[3].Name, "custom-Header");
        EXPECT_EQ((*decoded)[3].value, "custom-value");
    }

    TEST(H2Hpack, StaticTableLookup)
    {
        EXPECT_EQ(h2::LookupStatic(":Method", "GET"), 2u);
        EXPECT_EQ(h2::LookupStatic(":status", "200"), 8u);
        EXPECT_EQ(h2::LookupStatic(":Method", "PUT"), 0u); // 值不匹配
        EXPECT_EQ(h2::LookupStaticName(":authority"), 1u);
        EXPECT_EQ(h2::LookupStaticName("unknown"), 0u);
    }

    TEST(H2Hpack, IntegerCodec)
    {
        std::vector<std::byte> out;
        h2::EncodeInt(10, 7, 0x80, out);
        std::size_t off = 0;
        EXPECT_EQ(h2::DecodeInt(out, 7, off), 10u);

        out.clear();
        h2::EncodeInt(200, 7, 0x80, out); // 需多字节
        off = 0;
        EXPECT_EQ(h2::DecodeInt(out, 7, off), 200u);

        out.clear();
        h2::EncodeInt(16384, 6, 0x40, out);
        off = 0;
        EXPECT_EQ(h2::DecodeInt(out, 6, off), 16384u);
    }

    // ── 会话状态机 ──

    TEST(H2Session, FeedCollectRoundTrip)
    {
        net::io_context ioc;
        auto Client = std::make_shared<h2::SessionImpl>(ioc.get_executor(), false);
        auto Server = std::make_shared<h2::SessionImpl>(ioc.get_executor(), true);

        // 客户端 SETTINGS + 开流 + 数据
        Client->SendSettings();
        const int StreamId = Client->OpenStream({{":Method", "GET"}, {":Path", "/"}}, false);
        EXPECT_GT(StreamId, 0);
        Client->SubmitData(StreamId, std::span<const std::byte>(), false); // 空数据
        const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        Client->SubmitData(StreamId, payload, true);

        // 收集客户端输出 → 投喂服务端
        std::vector<std::byte> wire;
        Client->Collect(wire);
        ASSERT_FALSE(wire.empty());

        int headers_seen = 0;
        int data_seen = 0;
        int closed_seen = 0;
        Server->on_headers = [&](std::int32_t Id, const HeaderList &hdrs, bool end_stream)
        {
            headers_seen = Id;
            EXPECT_FALSE(end_stream);
            EXPECT_EQ(hdrs.size(), 2u);
        };
        Server->on_data = [&](std::int32_t Id, std::span<const std::byte> Data) { data_seen += static_cast<int>(Data.size()); };
        Server->on_stream_close = [&](std::int32_t Id, std::uint32_t ec) { closed_seen = Id; EXPECT_EQ(ec, h2::error_no_error); };

        std::error_code ec;
        EXPECT_TRUE(Server->Feed(wire, ec));
        EXPECT_EQ(headers_seen, StreamId);
        EXPECT_EQ(data_seen, 3);
        EXPECT_EQ(closed_seen, StreamId);
    }

    TEST(H2Session, SettingsAckAutoReply)
    {
        net::io_context ioc;
        auto Server = std::make_shared<h2::SessionImpl>(ioc.get_executor(), true);

        std::vector<h2::SettingsEntry> entries = {{h2::settings_max_concurrent_streams, 10}};
        auto payload = h2::EncodeSettings(entries);
        auto Frame = h2::BuildFrame(FrameType::settings, 0, 0, payload);

        int settings_seen = 0;
        Server->on_settings = [&](const std::vector<h2::SettingsEntry> &e) { settings_seen = static_cast<int>(e.size()); };
        std::error_code ec;
        EXPECT_TRUE(Server->Feed(Frame, ec));
        EXPECT_EQ(settings_seen, 1);

        // ACK 帧入队
        std::vector<std::byte> out;
        Server->Collect(out);
        ASSERT_GE(out.size(), h2::frame_header_size);
        const auto h = h2::ParseFrameHeader(out);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->Type, FrameType::settings);
        EXPECT_EQ(h->Flags, h2::flag_ack);
    }

    TEST(H2Session, BadFrameRejected)
    {
        net::io_context ioc;
        auto Server = std::make_shared<h2::SessionImpl>(ioc.get_executor(), true);

        // 流 0 上发 DATA → 协议错误
        std::vector<std::byte> payload(10, std::byte{0});
        auto bad = h2::BuildFrame(FrameType::Data, 0, 0, payload);
        std::error_code ec;
        EXPECT_FALSE(Server->Feed(bad, ec));
        EXPECT_EQ(ec, std::make_error_code(std::Error::protocol_error));
    }

    TEST(H2Session, ContinuationRejected)
    {
        net::io_context ioc;
        auto Server = std::make_shared<h2::SessionImpl>(ioc.get_executor(), true);
        auto bad = h2::BuildFrame(FrameType::continuation, 0, 1, {});
        std::error_code ec;
        EXPECT_FALSE(Server->Feed(bad, ec));
    }

    TEST(H2Session, PingPong)
    {
        net::io_context ioc;
        auto Server = std::make_shared<h2::SessionImpl>(ioc.get_executor(), true);
        std::array<std::byte, 8> opaque{};
        auto ping = h2::BuildFrame(FrameType::ping, 0, 0, opaque);
        std::error_code ec;
        EXPECT_TRUE(Server->Feed(ping, ec));
        std::vector<std::byte> out;
        Server->Collect(out);
        ASSERT_GE(out.size(), h2::frame_header_size);
        const auto h = h2::ParseFrameHeader(out);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->Type, FrameType::ping);
        EXPECT_EQ(h->Flags, h2::flag_ack);
    }
} // namespace
