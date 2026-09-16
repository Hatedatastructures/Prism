/**
 * @file H2CodecTest.cpp
 * @brief HTTP/2 自包含实现测试（T2-6）
 * @details 覆盖：
 *          - 帧头编解码（长度/类型/标志/流 ID 边界）
 *          - 帧载荷编解码（SETTINGS/WINDOW_UPDATE/RST/GOAWAY）
 *          - HPACK 静态表索引/字面量编解码
 *          - 会话状态机（Feed/Collect 往返、流生命周期、坏帧拒绝）
 */

#include <Preview/Protocols/Http2/Codec.hpp>
#include <Preview/Protocols/Http2/Frame.hpp>
#include <Preview/Protocols/Http2/Impl.hpp>
#include <Preview/Protocols/Http2/Session.hpp>

#include <boost/asio/io_context.hpp>

#include <string_view>

#include <gtest/gtest.h>

namespace
{
    namespace H2 = Preview::Http2;
    namespace Net = boost::asio;
    using H2::FrameHeader;
    using H2::FrameType;
    using Preview::Http2::Header;
    using Preview::Http2::HeaderList;

    // ── 帧头编解码 ──

    TEST(H2Frame, HeaderEncodeDecode)
    {
        std::vector<std::byte> Payload(100, std::byte{0xAB});
        auto Frame = H2::BuildFrame({FrameType::Data, H2::FlagEndStream, 5, Payload});
        ASSERT_EQ(Frame.size(), H2::FrameHeaderSize + 100);

        const auto h = H2::ParseFrameHeader(Frame);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->length, 100u);
        EXPECT_EQ(h->Type, FrameType::Data);
        EXPECT_EQ(h->Flags, H2::FlagEndStream);
        EXPECT_EQ(h->StreamId, 5u);
    }

    TEST(H2Frame, StreamIdBoundary)
    {
        // 31 位上限 0x7FFFFFFF
        auto Frame = H2::BuildFrame({FrameType::Data, 0, 0x7FFFFFFF, {}});
        const auto h = H2::ParseFrameHeader(Frame);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->StreamId, 0x7FFFFFFFu);
    }

    TEST(H2Frame, TruncatedHeader)
    {
        std::vector<std::byte> ShortFrame(5, std::byte{0});
        EXPECT_FALSE(H2::ParseFrameHeader(ShortFrame).has_value());
    }

    TEST(H2Frame, SettingsRoundTrip)
    {
        std::vector<H2::SettingsEntry> Entries = {
            {H2::SettingsMaxConcurrentStreams, 100},
            {H2::SettingsInitialWindowSize, 65535},
            {H2::SettingsEnablePush, 0},
        };
        auto Encoded = H2::EncodeSettings(Entries);
        auto Decoded = H2::DecodeSettings(Encoded);
        ASSERT_TRUE(Decoded.has_value());
        ASSERT_EQ(Decoded->size(), 3u);
        EXPECT_EQ((*Decoded)[0].Id, H2::SettingsMaxConcurrentStreams);
        EXPECT_EQ((*Decoded)[0].value, 100u);
        EXPECT_EQ((*Decoded)[1].Id, H2::SettingsInitialWindowSize);
        EXPECT_EQ((*Decoded)[2].value, 0u);
    }

    TEST(H2Frame, SettingsBadLength)
    {
        std::vector<std::byte> Bad(7, std::byte{0});
        EXPECT_FALSE(H2::DecodeSettings(Bad).has_value());
    }

    TEST(H2Frame, WindowUpdateAndRst)
    {
        auto WindowUpdate = H2::EncodeWindowUpdate(12345);
        EXPECT_EQ(H2::DecodeU31(WindowUpdate), 12345u);
        auto RstStream = H2::EncodeRstStream(H2::ErrorCancel);
        EXPECT_EQ(H2::DecodeU31(RstStream), H2::ErrorCancel);
    }

    TEST(H2Frame, GoawayEncode)
    {
        H2::GoawayParams Parameters;
        Parameters.LastStreamId = 7;
        Parameters.ErrorCode = H2::ErrorNoError;
        std::vector<std::byte> Debug{std::byte{1}, std::byte{2}};
        Parameters.Debug = Debug;
        auto Encoded = H2::EncodeGoaway(Parameters);
        ASSERT_EQ(Encoded.size(), 10u);
        EXPECT_EQ(H2::DecodeU31(std::span<const std::byte>(Encoded.data(), 4)), 7u);
        EXPECT_EQ(H2::DecodeU31(std::span<const std::byte>(Encoded.data() + 4, 4)), H2::ErrorNoError);
    }

    // ── HPACK ──

    TEST(H2Hpack, StaticIndexLiteral)
    {
        H2::HpackEncoder Encoder;
        H2::HpackDecoder Decoder;

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
        EXPECT_EQ((*Decoded)[0].value, "GET");
        EXPECT_EQ((*Decoded)[1].Name, ":path");
        EXPECT_EQ((*Decoded)[1].value, "/");
        EXPECT_EQ((*Decoded)[2].Name, ":authority");
        EXPECT_EQ((*Decoded)[2].value, "example.com");
        EXPECT_EQ((*Decoded)[3].Name, "custom-Header");
        EXPECT_EQ((*Decoded)[3].value, "custom-value");
    }

    TEST(H2Hpack, StaticTableLookup)
    {
        EXPECT_EQ(H2::LookupStatic(":method", "GET"), 2u);
        EXPECT_EQ(H2::LookupStatic(":status", "200"), 8u);
        EXPECT_EQ(H2::LookupStatic(":method", "PUT"), 0u); // 值不匹配
        EXPECT_EQ(H2::LookupStaticName(":authority"), 1u);
        EXPECT_EQ(H2::LookupStaticName("unknown"), 0u);
    }

    TEST(H2Hpack, IntegerCodec)
    {
        std::vector<std::byte> Output;
        H2::EncodeInt(10, 7, 0x80, Output);
        std::size_t off = 0;
        const auto Decoded10 = H2::DecodeInt(Output, 7, off);
        ASSERT_TRUE(Decoded10.has_value());
        EXPECT_EQ(*Decoded10, 10u);

        Output.clear();
        H2::EncodeInt(200, 7, 0x80, Output); // 需多字节
        off = 0;
        const auto Decoded200 = H2::DecodeInt(Output, 7, off);
        ASSERT_TRUE(Decoded200.has_value());
        EXPECT_EQ(*Decoded200, 200u);

        Output.clear();
        H2::EncodeInt(16384, 6, 0x40, Output);
        off = 0;
        const auto Decoded16384 = H2::DecodeInt(Output, 6, off);
        ASSERT_TRUE(Decoded16384.has_value());
        EXPECT_EQ(*Decoded16384, 16384u);
    }

    TEST(H2Hpack, TruncatedIntegerContinuationRejected)
    {
        const std::array<std::byte, 2> Truncated{
            std::byte{0x7F}, std::byte{0x80}};
        std::size_t Offset = 0;
        const auto Decoded = H2::DecodeInt(Truncated, 7, Offset);
        EXPECT_FALSE(Decoded.has_value());
        EXPECT_EQ(Offset, Truncated.size());
    }

    TEST(H2Hpack, HuffmanStringDecode)
    {
        // RFC 7541 Appendix C.4："www.example.com" 的 Huffman 字面量。
        const std::array<std::byte, 13> Encoded{
            std::byte{0x8C}, std::byte{0xF1}, std::byte{0xE3}, std::byte{0xC2}, std::byte{0xE5},
            std::byte{0xF2}, std::byte{0x3A}, std::byte{0x6B}, std::byte{0xA0}, std::byte{0xAB},
            std::byte{0x90}, std::byte{0xF4}, std::byte{0xFF}};
        std::size_t Offset = 0;
        const auto Decoded = H2::DecodeString(Encoded, Offset);
        ASSERT_TRUE(Decoded.has_value());
        EXPECT_EQ(*Decoded, "www.example.com");
        EXPECT_EQ(Offset, Encoded.size());
    }

    // ── 会话状态机 ──

    TEST(H2Session, FeedCollectRoundTrip)
    {
        Net::io_context IoContext;
        auto Client = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), false);
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);

        // 客户端 SETTINGS + 开流 + 数据
        Client->SendSettings();
        const int StreamId = Client->OpenStream({{":method", "GET"}, {":path", "/"}}, false);
        EXPECT_GT(StreamId, 0);
        (void)Client->SubmitData(StreamId, std::span<const std::byte>(), false); // 空数据
        const std::byte Payload[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        (void)Client->SubmitData(StreamId, Payload, true);

        // 收集客户端输出 → 投喂服务端
        std::vector<std::byte> Wire;
        (void)Client->Collect(Wire);
        ASSERT_FALSE(Wire.empty());

        int HeadersSeen = 0;
        int DataSeen = 0;
        int ClosedSeen = 0;
        Server->OnHeaders = [&](std::int32_t Id, const HeaderList &hdrs, bool EndStream)
        {
            HeadersSeen = Id;
            EXPECT_FALSE(EndStream);
            EXPECT_EQ(hdrs.size(), 2u);
        };
        Server->OnData = [&](std::int32_t Id, std::span<const std::byte> Data) { DataSeen += static_cast<int>(Data.size()); };
        Server->OnStreamClose = [&](std::int32_t Id, std::uint32_t ErrorCode) { ClosedSeen = Id; EXPECT_EQ(ErrorCode, H2::ErrorNoError); };

        std::error_code ErrorCode;
        EXPECT_TRUE(Server->Feed(Wire, ErrorCode));
        EXPECT_EQ(HeadersSeen, StreamId);
        EXPECT_EQ(DataSeen, 3);
        EXPECT_EQ(ClosedSeen, StreamId);
    }

    TEST(H2Session, ServerConsumesStandardConnectionPreface)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        const auto Settings = H2::BuildFrame({FrameType::Settings, 0, 0, {}});
        std::vector<std::byte> Wire;
        Wire.reserve(Preface.size() + Settings.size());
        for (const auto Character : Preface)
        {
            Wire.push_back(static_cast<std::byte>(Character));
        }
        Wire.insert(Wire.end(), Settings.begin(), Settings.end());

        std::error_code Error;
        EXPECT_TRUE(Server->Feed(Wire, Error));
        EXPECT_FALSE(Error);
        std::vector<std::byte> Reply;
        EXPECT_TRUE(Server->Collect(Reply));
        const auto Header = H2::ParseFrameHeader(Reply);
        ASSERT_TRUE(Header.has_value());
        EXPECT_EQ(Header->Type, FrameType::Settings);
        EXPECT_EQ(Header->Flags, H2::FlagAck);
    }

    TEST(H2Session, ServerConsumesSplitConnectionPreface)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        const auto Settings = H2::BuildFrame({FrameType::Settings, 0, 0, {}});
        std::vector<std::byte> First;
        std::vector<std::byte> Second;
        for (std::size_t Index = 0; Index < 11; ++Index)
        {
            First.push_back(static_cast<std::byte>(Preface[Index]));
        }
        for (std::size_t Index = 11; Index < Preface.size(); ++Index)
        {
            Second.push_back(static_cast<std::byte>(Preface[Index]));
        }
        Second.insert(Second.end(), Settings.begin(), Settings.end());

        std::error_code Error;
        EXPECT_TRUE(Server->Feed(First, Error));
        EXPECT_FALSE(Error);
        EXPECT_TRUE(Server->Feed(Second, Error));
        EXPECT_FALSE(Error);
        std::vector<std::byte> Reply;
        EXPECT_TRUE(Server->Collect(Reply));
        const auto Header = H2::ParseFrameHeader(Reply);
        ASSERT_TRUE(Header.has_value());
        EXPECT_EQ(Header->Type, FrameType::Settings);
        EXPECT_EQ(Header->Flags, H2::FlagAck);
    }

    TEST(H2Session, ClientSendsConnectionPrefaceBeforeSettings)
    {
        Net::io_context IoContext;
        auto Client = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), false);
        constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        Client->SendSettings();
        std::vector<std::byte> Wire;
        ASSERT_TRUE(Client->Collect(Wire));
        ASSERT_GE(Wire.size(), Preface.size());
        for (std::size_t Index = 0; Index < Preface.size(); ++Index)
        {
            EXPECT_EQ(std::to_integer<char>(Wire[Index]), Preface[Index]);
        }
        const auto Header = H2::ParseFrameHeader(
            std::span<const std::byte>(Wire).subspan(Preface.size()));
        ASSERT_TRUE(Header.has_value());
        EXPECT_EQ(Header->Type, FrameType::Settings);
    }

    TEST(H2Session, ResponseOnLocallyOpenedStreamAfterPeerEnd)
    {
        Net::io_context IoContext;
        auto Client = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), false);
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto StreamId = Client->OpenStream({{":method", "POST"}, {":path", "/"}}, false);
        ASSERT_GT(StreamId, 0);
        const std::array<std::byte, 1> RequestData{std::byte{0x41}};
        ASSERT_EQ(Client->SubmitData(StreamId, RequestData, true), 0);

        Server->OnHeaders = [&](std::int32_t Id, const HeaderList &, bool EndStream)
        {
            EXPECT_FALSE(EndStream);
            EXPECT_EQ(Server->SubmitHeaders(Id, {{":status", "200"}}, false), 0);
            EXPECT_EQ(Server->SubmitData(Id, RequestData, false), 0);
        };
        std::vector<std::byte> RequestWire;
        ASSERT_TRUE(Client->Collect(RequestWire));
        std::error_code Error;
        ASSERT_TRUE(Server->Feed(RequestWire, Error));

        std::vector<std::byte> ResponseWire;
        ASSERT_TRUE(Server->Collect(ResponseWire));
        ASSERT_FALSE(ResponseWire.empty());
        EXPECT_TRUE(Client->Feed(ResponseWire, Error));
    }

    TEST(H2Session, SettingsAckAutoReply)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);

        std::vector<H2::SettingsEntry> Entries = {{H2::SettingsMaxConcurrentStreams, 10}};
        auto Payload = H2::EncodeSettings(Entries);
        auto Frame = H2::BuildFrame({FrameType::Settings, 0, 0, Payload});

        int SettingsSeen = 0;
        Server->OnSettings = [&](const std::vector<H2::SettingsEntry> &e) { SettingsSeen = static_cast<int>(e.size()); };
        std::error_code ErrorCode;
        EXPECT_TRUE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(SettingsSeen, 1);

        // ACK 帧入队
        std::vector<std::byte> Output;
        (void)Server->Collect(Output);
        ASSERT_GE(Output.size(), H2::FrameHeaderSize);
        const auto h = H2::ParseFrameHeader(Output);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->Type, FrameType::Settings);
        EXPECT_EQ(h->Flags, H2::FlagAck);
    }

    TEST(H2Session, SettingsAckWithPayloadRejected)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const std::array<std::byte, 1> Payload{std::byte{0x01}};
        const auto Frame = H2::BuildFrame({FrameType::Settings, H2::FlagAck, 0, Payload});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, WindowUpdateZeroIncrementRejected)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const std::array<std::byte, 4> Payload{};
        const auto Frame = H2::BuildFrame({FrameType::WindowUpdate, 0, 0, Payload});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, RstStreamInvalidLengthRejected)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto Frame = H2::BuildFrame({FrameType::RstStream, 0, 1, {}});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, RstStreamOnConnectionStreamRejected)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto Frame = H2::BuildFrame({FrameType::RstStream, 0, 0, H2::EncodeRstStream(H2::ErrorCancel)});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, RstStreamOnIdleStreamRejected)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto Frame = H2::BuildFrame({FrameType::RstStream, 0, 1, H2::EncodeRstStream(H2::ErrorCancel)});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, HeadersWithoutEndHeadersWaitsForContinuation)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto Headers = H2::BuildFrame({FrameType::Headers, 0, 1, {}});
        const auto Data = H2::BuildFrame({FrameType::Data, 0, 1, {}});
        std::error_code ErrorCode;
        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        EXPECT_FALSE(Server->Feed(Data, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, DataOnIdleStreamRejected)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const std::array<std::byte, 1> Payload{std::byte{0x01}};
        const auto Frame = H2::BuildFrame({FrameType::Data, 0, 1, Payload});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, DataAfterEndStreamRejected)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto Headers = H2::BuildFrame({FrameType::Headers,
                                              static_cast<std::uint8_t>(H2::FlagEndHeaders | H2::FlagEndStream),
                                              1,
                                              {}});
        const std::array<std::byte, 1> Payload{std::byte{0x01}};
        const auto Data = H2::BuildFrame({FrameType::Data, 0, 1, Payload});
        std::error_code ErrorCode;
        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        EXPECT_FALSE(Server->Feed(Data, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, PriorityInvalidLengthRejected)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const std::array<std::byte, 4> Payload{};
        const auto Frame = H2::BuildFrame({FrameType::Priority, 0, 1, Payload});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, BadFrameRejected)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);

        // 流 0 上发 DATA → 协议错误
        std::vector<std::byte> Payload(10, std::byte{0});
        auto Bad = H2::BuildFrame({FrameType::Data, 0, 0, Payload});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Bad, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, ContinuationRejected)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        auto Bad = H2::BuildFrame({FrameType::Continuation, 0, 1, {}});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Bad, ErrorCode));
    }

    TEST(H2Session, HeadersContinuationReassemblesBeforeDispatch)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        int HeadersSeen = 0;
        Server->OnHeaders = [&HeadersSeen](std::int32_t, const HeaderList &, bool)
        {
            ++HeadersSeen;
        };
        const auto Headers = H2::BuildFrame({FrameType::Headers, 0, 1, {}});
        const auto Continuation = H2::BuildFrame({FrameType::Continuation, H2::FlagEndHeaders, 1, {}});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        EXPECT_TRUE(Server->Feed(Continuation, ErrorCode));
        EXPECT_EQ(HeadersSeen, 1);
    }

    TEST(H2Session, HeadersContinuationDecodesSplitHpackBlock)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        HeaderList Received;
        Server->OnHeaders = [&Received](std::int32_t, const HeaderList &Headers, bool EndStream)
        {
            EXPECT_FALSE(EndStream);
            Received = Headers;
        };
        H2::HpackEncoder Encoder;
        const auto Block = Encoder.Encode({{":method", "GET"}, {":path", "/carrier"},
                                            {":authority", "edge.example"}});
        ASSERT_GT(Block.size(), 1U);
        const auto Split = H2::BuildFrame({FrameType::Headers, 0, 1,
                                            std::span<const std::byte>(Block).first(1)});
        const auto Tail = H2::BuildFrame({FrameType::Continuation, H2::FlagEndHeaders, 1,
                                          std::span<const std::byte>(Block).subspan(1)});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Split, ErrorCode));
        ASSERT_TRUE(Server->Feed(Tail, ErrorCode));
        ASSERT_EQ(Received.size(), 3U);
        EXPECT_EQ(Received[0].Name, ":method");
        EXPECT_EQ(Received[0].value, "GET");
        EXPECT_EQ(Received[1].value, "/carrier");
        EXPECT_EQ(Received[2].value, "edge.example");
    }

    TEST(H2Session, HeadersContinuationExcludesTrailingPadding)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        HeaderList Received;
        Server->OnHeaders = [&Received](std::int32_t, const HeaderList &Headers, bool)
        {
            Received = Headers;
        };
        H2::HpackEncoder Encoder;
        const auto Block = Encoder.Encode({{":method", "GET"}, {":path", "/padded"}});
        std::vector<std::byte> FirstPayload;
        FirstPayload.push_back(std::byte{0x02});
        FirstPayload.insert(FirstPayload.end(), Block.begin(), Block.end());
        FirstPayload.push_back(std::byte{0x00});
        FirstPayload.push_back(std::byte{0x00});
        const auto Headers = H2::BuildFrame({FrameType::Headers, H2::FlagPadded, 1, FirstPayload});
        const auto Continuation = H2::BuildFrame({FrameType::Continuation, H2::FlagEndHeaders, 1, {}});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        ASSERT_TRUE(Server->Feed(Continuation, ErrorCode));
        ASSERT_EQ(Received.size(), 2U);
        EXPECT_EQ(Received[1].value, "/padded");
    }

    TEST(H2Session, ContinuationRejectsEndStreamFlag)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto Headers = H2::BuildFrame({FrameType::Headers, 0, 1, {}});
        const auto Continuation = H2::BuildFrame({FrameType::Continuation,
                                                  static_cast<std::uint8_t>(H2::FlagEndHeaders | H2::FlagEndStream),
                                                  1, {}});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        EXPECT_FALSE(Server->Feed(Continuation, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, DataRefreshesConnectionAndStreamWindow)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto Headers = H2::BuildFrame({FrameType::Headers, H2::FlagEndHeaders, 1, {}});
        const std::vector<std::byte> Payload(16384, std::byte{0x5A});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        for (std::size_t Index = 0; Index < 8; ++Index)
        {
            const auto DataFrame = H2::BuildFrame({FrameType::Data, 0, 1, Payload});
            ASSERT_TRUE(Server->Feed(DataFrame, ErrorCode));
        }

        std::vector<std::byte> Out;
        ASSERT_TRUE(Server->Collect(Out));
        std::size_t Offset = 0;
        std::size_t ConnectionUpdates = 0;
        std::size_t StreamUpdates = 0;
        while (Offset < Out.size())
        {
            const auto Remaining = std::span<const std::byte>(Out).subspan(Offset);
            const auto Header = H2::ParseFrameHeader(Remaining);
            ASSERT_TRUE(Header.has_value());
            ASSERT_LE(H2::FrameHeaderSize + Header->length, Remaining.size());
            if (Header->Type == FrameType::WindowUpdate)
            {
                ASSERT_EQ(Header->length, 4U);
                if (Header->StreamId == 0)
                {
                    ++ConnectionUpdates;
                }
                else
                {
                    EXPECT_EQ(Header->StreamId, 1U);
                    ++StreamUpdates;
                }
            }
            Offset += H2::FrameHeaderSize + Header->length;
        }
        EXPECT_EQ(ConnectionUpdates, 8U);
        EXPECT_EQ(StreamUpdates, 8U);
    }

    TEST(H2Session, ConsumeDataCapsWindowUpdateAt31Bits)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto Headers = H2::BuildFrame({FrameType::Headers, H2::FlagEndHeaders, 1, {}});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        Server->ConsumeData(1, static_cast<std::size_t>(0x80000010ULL));

        std::vector<std::byte> Out;
        ASSERT_TRUE(Server->Collect(Out));
        std::size_t Offset = 0;
        std::size_t ConnectionUpdates = 0;
        std::size_t StreamUpdates = 0;
        while (Offset < Out.size())
        {
            const auto Remaining = std::span<const std::byte>(Out).subspan(Offset);
            const auto Header = H2::ParseFrameHeader(Remaining);
            ASSERT_TRUE(Header.has_value());
            ASSERT_LE(H2::FrameHeaderSize + Header->length, Remaining.size());
            if (Header->Type == FrameType::WindowUpdate)
            {
                ASSERT_EQ(Header->length, 4U);
                const auto Payload = Remaining.subspan(H2::FrameHeaderSize, Header->length);
                const auto Increment = H2::DecodeU31(Payload);
                EXPECT_GT(Increment, 0U);
                EXPECT_LE(Increment, 0x7FFFFFFFU);
                if (Header->StreamId == 0)
                {
                    ++ConnectionUpdates;
                }
                else
                {
                    EXPECT_EQ(Header->StreamId, 1U);
                    ++StreamUpdates;
                }
            }
            Offset += H2::FrameHeaderSize + Header->length;
        }
        EXPECT_EQ(ConnectionUpdates, 1U);
        EXPECT_EQ(StreamUpdates, 1U);
    }

    TEST(H2Session, SettingsUpdatePeerWindowAndFrameSize)
    {
        Net::io_context IoContext;
        auto Client = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), false);
        const auto StreamId = Client->OpenStream({{":method", "GET"}, {":path", "/"}}, false);
        ASSERT_GT(StreamId, 0);
        const std::vector<H2::SettingsEntry> Entries = {
            {H2::SettingsInitialWindowSize, 0}, {H2::SettingsMaxFrameSize, 16384}};
        const auto Settings = H2::BuildFrame({FrameType::Settings, 0, 0, H2::EncodeSettings(Entries)});
        std::error_code ErrorCode;

        ASSERT_TRUE(Client->Feed(Settings, ErrorCode));
        const std::array<std::byte, 1> Byte{std::byte{0x01}};
        EXPECT_EQ(Client->SubmitData(StreamId, Byte, false), -1);
        const auto Update = H2::BuildFrame({FrameType::WindowUpdate, 0, static_cast<std::uint32_t>(StreamId),
                                             H2::EncodeWindowUpdate(1)});
        ASSERT_TRUE(Client->Feed(Update, ErrorCode));
        EXPECT_EQ(Client->SubmitData(StreamId, Byte, false), 0);

        const auto MoreConnection = H2::BuildFrame({FrameType::WindowUpdate, 0, 0,
                                                     H2::EncodeWindowUpdate(20000)});
        const auto MoreStream = H2::BuildFrame({FrameType::WindowUpdate, 0,
                                                static_cast<std::uint32_t>(StreamId),
                                                H2::EncodeWindowUpdate(20000)});
        ASSERT_TRUE(Client->Feed(MoreConnection, ErrorCode));
        ASSERT_TRUE(Client->Feed(MoreStream, ErrorCode));
        std::vector<std::byte> Large(17000, std::byte{0x2A});
        EXPECT_EQ(Client->SubmitData(StreamId, Large, false), 0);
    }

    TEST(H2Session, RstStreamReportsFullErrorCode)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto Headers = H2::BuildFrame({FrameType::Headers, H2::FlagEndHeaders, 1, {}});
        const auto Rst = H2::BuildFrame({FrameType::RstStream, 0, 1, H2::EncodeRstStream(0x80000001U)});
        std::uint32_t StreamErrorCode = 0;
        Server->OnStreamClose = [&StreamErrorCode](std::int32_t, std::uint32_t Value)
        {
            StreamErrorCode = Value;
        };
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        ASSERT_TRUE(Server->Feed(Rst, ErrorCode));
        EXPECT_EQ(StreamErrorCode, 0x80000001U);
    }

    TEST(H2Frame, RejectsPayloadLargerThan24Bits)
    {
        const std::vector<std::byte> Payload(0x1000000U, std::byte{0x01});
        EXPECT_TRUE(H2::BuildFrame({FrameType::Data, 0, 1, Payload}).empty());
    }

    TEST(H2Session, ResetStreamRejectsIdleAndClosedStreams)
    {
        Net::io_context IoContext;
        auto Client = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), false);
        EXPECT_EQ(Client->ResetStream(0, H2::ErrorCancel), -1);
        EXPECT_EQ(Client->ResetStream(1, H2::ErrorCancel), -1);
        const auto StreamId = Client->OpenStream({}, true);
        ASSERT_GT(StreamId, 0);
        EXPECT_EQ(Client->ResetStream(StreamId, H2::ErrorCancel), -1);
    }

    TEST(H2Session, HeadersRejectPeerStreamParityAndRegression)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto EvenStream = H2::BuildFrame({FrameType::Headers, H2::FlagEndHeaders, 2, {}});
        const auto First = H2::BuildFrame({FrameType::Headers, H2::FlagEndHeaders, 3, {}});
        const auto Lower = H2::BuildFrame({FrameType::Headers, H2::FlagEndHeaders, 1, {}});
        std::error_code ErrorCode;

        EXPECT_FALSE(Server->Feed(EvenStream, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
        ErrorCode.clear();
        ASSERT_TRUE(Server->Feed(First, ErrorCode));
        EXPECT_FALSE(Server->Feed(Lower, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, WindowUpdateConnectionOverflowRejected)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto Update = H2::BuildFrame({FrameType::WindowUpdate, 0, 0,
                                             H2::EncodeWindowUpdate(0x7FFFFFFFU)});
        std::error_code ErrorCode;

        EXPECT_FALSE(Server->Feed(Update, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, UnknownFrameTypeRejected)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto Unknown = H2::BuildFrame({static_cast<FrameType>(0xFF), 0, 0, {}});
        std::error_code ErrorCode;

        EXPECT_FALSE(Server->Feed(Unknown, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, ContinuationOnDifferentStreamRejected)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        const auto Headers = H2::BuildFrame({FrameType::Headers, 0, 1, {}});
        const auto Continuation = H2::BuildFrame({FrameType::Continuation, H2::FlagEndHeaders, 3, {}});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        EXPECT_FALSE(Server->Feed(Continuation, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, PingPong)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), true);
        std::array<std::byte, 8> Opaque{};
        auto Ping = H2::BuildFrame({FrameType::Ping, 0, 0, Opaque});
        std::error_code ErrorCode;
        EXPECT_TRUE(Server->Feed(Ping, ErrorCode));
        std::vector<std::byte> Output;
        (void)Server->Collect(Output);
        ASSERT_GE(Output.size(), H2::FrameHeaderSize);
        const auto h = H2::ParseFrameHeader(Output);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->Type, FrameType::Ping);
        EXPECT_EQ(h->Flags, H2::FlagAck);
    }

    TEST(H2Session, RejectsNegativeStreamIdOnSend)
    {
        Net::io_context IoContext;
        auto Client = std::make_shared<H2::SessionImpl>(IoContext.get_executor(), false);
        EXPECT_EQ(Client->SubmitHeaders(-1, {}, false), -1);
        EXPECT_EQ(Client->SubmitData(-1, {}, false), -1);
        EXPECT_EQ(Client->ResetStream(-1, H2::ErrorCancel), -1);
        std::vector<std::byte> Out;
        EXPECT_FALSE(Client->Collect(Out));
        EXPECT_TRUE(Out.empty());
    }
} // namespace
