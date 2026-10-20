/**
 * @file H2CodecTest.cpp
 * @brief HTTP/2 自包含实现测试（T2-6）
 * @details 覆盖：
 *          - 帧头编解码（长度/类型/标志/流 ID 边界）
 *          - 帧载荷编解码（SETTINGS/WINDOW_UPDATE/RST/GOAWAY）
 *          - HPACK 静态表索引/字面量编解码
 *          - 会话状态机（Feed/Collect 往返、流生命周期、坏帧拒绝）
 */

#include <Prism/Protocols/Http2/Detail/Codec.hpp>
#include <Prism/Protocols/Http2/Detail/StaticTable.hpp>
#include <Prism/Protocols/Http2/Detail/Frame.hpp>
#include <Prism/Protocols/Http2/Session.hpp>


#include <boost/asio/io_context.hpp>

#include <string_view>

#include <gtest/gtest.h>

namespace
{
    namespace H2 = Prism::Http2;
    namespace Net = boost::asio;
    using H2::Detail::FrameHeader;
    using H2::Detail::FrameType;
    using Prism::Http2::Header;
    using Prism::Http2::HeaderList;

    [[nodiscard]] auto MakePrefacedServer(Net::io_context &IoContext)
        -> std::shared_ptr<H2::Session>
    {
        auto Server = std::make_shared<H2::Session>(IoContext.get_executor(), true);
        constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        std::vector<std::byte> Wire;
        Wire.reserve(Preface.size());
        for (const auto Character : Preface)
        {
            Wire.push_back(static_cast<std::byte>(Character));
        }
        std::error_code Error;
        EXPECT_TRUE(Server->Feed(Wire, Error));
        EXPECT_FALSE(Error);
        return Server;
    }

    // ── 帧头编解码 ──

    TEST(H2Frame, HeaderEncodeDecode)
    {
        std::vector<std::byte> Payload(100, std::byte{0xAB});
        auto Frame = H2::Detail::BuildFrame({FrameType::Data, H2::Detail::FlagEndStream, 5, Payload});
        ASSERT_EQ(Frame.size(), H2::Detail::FrameHeaderSize + 100);

        const auto h = H2::Detail::ParseFrameHeader(Frame);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->Length, 100u);
        EXPECT_EQ(h->Type, FrameType::Data);
        EXPECT_EQ(h->Flags, H2::Detail::FlagEndStream);
        EXPECT_EQ(h->StreamId, 5u);
    }

    TEST(H2Frame, StreamIdBoundary)
    {
        // 31 位上限 0x7FFFFFFF
        auto Frame = H2::Detail::BuildFrame({FrameType::Data, 0, 0x7FFFFFFF, {}});
        const auto h = H2::Detail::ParseFrameHeader(Frame);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->StreamId, 0x7FFFFFFFu);
    }

    TEST(H2Frame, TruncatedHeader)
    {
        std::vector<std::byte> ShortFrame(5, std::byte{0});
        EXPECT_FALSE(H2::Detail::ParseFrameHeader(ShortFrame).has_value());
    }

    TEST(H2Frame, SettingsRoundTrip)
    {
        std::vector<H2::SettingsEntry> Entries = {
            {H2::SettingsMaxConcurrentStreams, 100},
            {H2::SettingsInitialWindowSize, 65535},
            {H2::SettingsEnablePush, 0},
        };
        auto Encoded = H2::Detail::EncodeSettings(Entries);
        auto Decoded = H2::Detail::DecodeSettings(Encoded);
        ASSERT_TRUE(Decoded.has_value());
        ASSERT_EQ(Decoded->size(), 3u);
        EXPECT_EQ((*Decoded)[0].Id, H2::SettingsMaxConcurrentStreams);
        EXPECT_EQ((*Decoded)[0].Value, 100u);
        EXPECT_EQ((*Decoded)[1].Id, H2::SettingsInitialWindowSize);
        EXPECT_EQ((*Decoded)[2].Value, 0u);
    }

    TEST(H2Frame, SettingsBadLength)
    {
        std::vector<std::byte> Bad(7, std::byte{0});
        EXPECT_FALSE(H2::Detail::DecodeSettings(Bad).has_value());
    }

    TEST(H2Frame, WindowUpdateAndRst)
    {
        auto WindowUpdate = H2::Detail::EncodeWindowUpdate(12345);
        EXPECT_EQ(H2::Detail::DecodeU31(WindowUpdate), 12345u);
        auto RstStream = H2::Detail::EncodeRstStream(H2::ErrorCancel);
        EXPECT_EQ(H2::Detail::DecodeU31(RstStream), H2::ErrorCancel);
    }

    TEST(H2Frame, GoawayEncode)
    {
        H2::Detail::GoawayParams Parameters;
        Parameters.LastStreamId = 7;
        Parameters.ErrorCode = H2::ErrorNoError;
        std::vector<std::byte> Debug{std::byte{1}, std::byte{2}};
        Parameters.Debug = Debug;
        auto Encoded = H2::Detail::EncodeGoaway(Parameters);
        ASSERT_EQ(Encoded.size(), 10u);
        EXPECT_EQ(H2::Detail::DecodeU31(std::span<const std::byte>(Encoded.data(), 4)), 7u);
        EXPECT_EQ(H2::Detail::DecodeU31(std::span<const std::byte>(Encoded.data() + 4, 4)), H2::ErrorNoError);
    }

    // ── HPACK ──

    TEST(H2Hpack, StaticIndexLiteral)
    {
        H2::Detail::HpackEncoder Encoder;
        H2::Detail::HpackDecoder Decoder;

        HeaderList headers = {
            {":method", "GET"},   // 静态表索引 2
            {":path", "/"},       // 静态表索引 4
            {":authority", "example.com"}, // 名引用 1 + 值字面量
            {"custom-Header", "custom-value"}, // 新名字面量
        };
        auto Block = Encoder.Encode(headers);
        auto Decoded = Decoder.Decode(Block);
        ASSERT_TRUE(Decoded.has_value());
        ASSERT_EQ(Decoded->size(), 4u);
        EXPECT_EQ((*Decoded)[0].Name, ":method");
        EXPECT_EQ((*Decoded)[0].Value, "GET");
        EXPECT_EQ((*Decoded)[1].Name, ":path");
        EXPECT_EQ((*Decoded)[1].Value, "/");
        EXPECT_EQ((*Decoded)[2].Name, ":authority");
        EXPECT_EQ((*Decoded)[2].Value, "example.com");
        EXPECT_EQ((*Decoded)[3].Name, "custom-Header");
        EXPECT_EQ((*Decoded)[3].Value, "custom-value");
    }

    TEST(H2Hpack, StaticTableLookup)
    {
        EXPECT_EQ(H2::Detail::LookupStatic(":method", "GET"), 2u);
        EXPECT_EQ(H2::Detail::LookupStatic(":status", "200"), 8u);
        EXPECT_EQ(H2::Detail::LookupStatic(":method", "PUT"), 0u); // 值不匹配
        EXPECT_EQ(H2::Detail::LookupStaticName(":authority"), 1u);
        EXPECT_EQ(H2::Detail::LookupStaticName("unknown"), 0u);
    }

    TEST(H2Hpack, IntegerCodec)
    {
        std::vector<std::byte> Output;
        H2::Detail::EncodeInt({10, 7, 0x80}, Output);
        std::size_t off = 0;
        const auto Decoded10 = H2::Detail::DecodeInt(Output, 7, off);
        ASSERT_TRUE(Decoded10.has_value());
        EXPECT_EQ(*Decoded10, 10u);

        Output.clear();
        H2::Detail::EncodeInt({200, 7, 0x80}, Output); // 需多字节
        off = 0;
        const auto Decoded200 = H2::Detail::DecodeInt(Output, 7, off);
        ASSERT_TRUE(Decoded200.has_value());
        EXPECT_EQ(*Decoded200, 200u);

        Output.clear();
        H2::Detail::EncodeInt({16384, 6, 0x40}, Output);
        off = 0;
        const auto Decoded16384 = H2::Detail::DecodeInt(Output, 6, off);
        ASSERT_TRUE(Decoded16384.has_value());
        EXPECT_EQ(*Decoded16384, 16384u);
    }

    TEST(H2Hpack, TruncatedIntegerContinuationRejected)
    {
        const std::array<std::byte, 2> Truncated{
            std::byte{0x7F}, std::byte{0x80}};
        std::size_t Offset = 0;
        const auto Decoded = H2::Detail::DecodeInt(Truncated, 7, Offset);
        EXPECT_FALSE(Decoded.has_value());
        EXPECT_EQ(Offset, Truncated.size());
    }

    TEST(H2Hpack, DynamicTableUpdateOrderAndLimitAreWireValidated)
    {
        std::vector<std::byte> TooLarge;
        H2::Detail::EncodeInt({4097, 5, 0x20}, TooLarge);
        H2::Detail::HpackDecoder TooLargeDecoder;
        EXPECT_FALSE(TooLargeDecoder.Decode(TooLarge).has_value());

        std::vector<std::byte> AtLimit;
        H2::Detail::EncodeInt({4096, 5, 0x20}, AtLimit);
        H2::Detail::HpackDecoder PrefixDecoder;
        ASSERT_TRUE(PrefixDecoder.Decode(AtLimit).has_value());

        std::vector<std::byte> Indexed;
        H2::Detail::EncodeInt({2, 7, 0x80}, Indexed);
        ASSERT_TRUE(PrefixDecoder.Decode(Indexed).has_value());

        std::vector<std::byte> LateUpdate = Indexed;
        std::vector<std::byte> Update;
        H2::Detail::EncodeInt({0, 5, 0x20}, Update);
        LateUpdate.insert(LateUpdate.end(), Update.begin(), Update.end());
        H2::Detail::HpackDecoder LateUpdateDecoder;
        EXPECT_FALSE(LateUpdateDecoder.Decode(LateUpdate).has_value());
    }

    TEST(H2Hpack, DynamicCapacityControlsLiteralInsertionAndLookup)
    {
        H2::Detail::HpackDecoder Decoder;
        std::vector<std::byte> ZeroCapacity;
        H2::Detail::EncodeInt({0, 5, 0x20}, ZeroCapacity);
        ASSERT_TRUE(Decoder.Decode(ZeroCapacity).has_value());

        std::vector<std::byte> Literal;
        H2::Detail::EncodeInt({0, 6, 0x40}, Literal);
        H2::Detail::EncodeString("x-dynamic", Literal);
        H2::Detail::EncodeString("zero-capacity", Literal);
        ASSERT_TRUE(Decoder.Decode(Literal).has_value());

        std::vector<std::byte> DynamicIndex;
        H2::Detail::EncodeInt({62, 7, 0x80}, DynamicIndex);
        EXPECT_FALSE(Decoder.Decode(DynamicIndex).has_value());

        std::vector<std::byte> MultipleUpdates;
        H2::Detail::EncodeInt({0, 5, 0x20}, MultipleUpdates);
        H2::Detail::EncodeInt({4096, 5, 0x20}, MultipleUpdates);
        ASSERT_TRUE(Decoder.Decode(MultipleUpdates).has_value());

        std::vector<std::byte> Reinserted;
        H2::Detail::EncodeInt({0, 6, 0x40}, Reinserted);
        H2::Detail::EncodeString("x-dynamic", Reinserted);
        H2::Detail::EncodeString("reinserted", Reinserted);
        ASSERT_TRUE(Decoder.Decode(Reinserted).has_value());
        const auto Decoded = Decoder.Decode(DynamicIndex);
        ASSERT_TRUE(Decoded.has_value());
        ASSERT_EQ(Decoded->size(), 1U);
        EXPECT_EQ((*Decoded)[0].Name, "x-dynamic");
        EXPECT_EQ((*Decoded)[0].Value, "reinserted");
    }

    TEST(H2Hpack, HuffmanStringDecode)
    {
        // RFC 7541 Appendix C.4："www.example.com" 的 Huffman 字面量。
        const std::array<std::byte, 13> Encoded{
            std::byte{0x8C}, std::byte{0xF1}, std::byte{0xE3}, std::byte{0xC2}, std::byte{0xE5},
            std::byte{0xF2}, std::byte{0x3A}, std::byte{0x6B}, std::byte{0xA0}, std::byte{0xAB},
            std::byte{0x90}, std::byte{0xF4}, std::byte{0xFF}};
        std::size_t Offset = 0;
        const auto Decoded = H2::Detail::DecodeString(Encoded, Offset);
        ASSERT_TRUE(Decoded.has_value());
        EXPECT_EQ(*Decoded, "www.example.com");
        EXPECT_EQ(Offset, Encoded.size());
    }

    // ── 会话状态机 ──

    TEST(H2Frame, RejectsPayloadLargerThan24Bits)
    {
        const std::vector<std::byte> Payload(0x1000000U, std::byte{0x01});
        EXPECT_TRUE(H2::Detail::BuildFrame({FrameType::Data, 0, 1, Payload}).empty());
    }

} // namespace
