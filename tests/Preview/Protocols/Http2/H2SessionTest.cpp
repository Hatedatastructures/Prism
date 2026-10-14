/**
 * @file H2SessionTest.cpp
 * @brief HTTP/2 会话状态机测试（T2-6）
 * @details 覆盖：
 *          - 帧头编解码（长度/类型/标志/流 ID 边界）
 *          - 帧载荷编解码（SETTINGS/WINDOW_UPDATE/RST/GOAWAY）
 *          - HPACK 静态表索引/字面量编解码
 *          - 会话状态机（Feed/Collect 往返、流生命周期、坏帧拒绝）
 */

#include <Preview/Protocols/Http2/Detail/Codec.hpp>
#include <Preview/Protocols/Http2/Detail/Frame.hpp>
#include <Preview/Protocols/Http2/Detail/SessionState.hpp>
#include <Preview/Protocols/Http2/Session.hpp>


#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

#include <gtest/gtest.h>

namespace
{
    namespace H2 = Preview::Http2;
    namespace Net = boost::asio;
    using H2::Detail::FrameHeader;
    using H2::Detail::FrameType;
    using Preview::Http2::Header;
    using Preview::Http2::HeaderList;

    template<class SessionOwner>
    auto FeedConnectionPreface(SessionOwner &Server) -> void
    {
        constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        const auto Wire = std::as_bytes(std::span{Preface.data(), Preface.size()});
        std::error_code Error;
        EXPECT_TRUE(Server.Feed(Wire, Error));
        EXPECT_FALSE(Error);
    }

    [[nodiscard]] auto MakePrefacedServer(Net::io_context &IoContext) -> std::shared_ptr<H2::Session>
    {
        auto Server = std::make_shared<H2::Session>(IoContext.get_executor(), true);
        FeedConnectionPreface(*Server);
        return Server;
    }

    [[nodiscard]] auto MakePrefacedServerState(
        Net::io_context &IoContext, H2::Session &EventTarget)
        -> std::unique_ptr<H2::Detail::SessionState>
    {
        auto Server = std::make_unique<H2::Detail::SessionState>(IoContext.get_executor(), true, EventTarget);
        FeedConnectionPreface(*Server);
        return Server;
    }
    // ── 帧头编解码 ──

    TEST(H2Session, FeedCollectRoundTrip)
    {
        Net::io_context IoContext;
        auto Client = std::make_shared<H2::Session>(IoContext.get_executor(), false);
        auto Server = std::make_shared<H2::Session>(IoContext.get_executor(), true);

        // 客户端 SETTINGS + 开流 + 数据
        Client->SendSettings();
        const auto Opened = Client->OpenStream({{":method", "GET"}, {":path", "/"}}, false);
        ASSERT_TRUE(Opened); const auto StreamId = *Opened; EXPECT_GT(StreamId, 0);
        EXPECT_EQ(Client->SubmitData(StreamId, std::span<const std::byte>(), false), H2::SubmitDataStatus::Accepted); // 空数据
        const std::byte Payload[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        EXPECT_EQ(Client->SubmitData(StreamId, Payload, true), H2::SubmitDataStatus::Accepted);

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
        Server->OnStreamClose = [&](const H2::StreamReceiveClosure &Closure)
        {
            ClosedSeen = Closure.StreamId;
            EXPECT_EQ(Closure.Kind, H2::StreamReceiveClosureKind::EndStream);
            EXPECT_EQ(Closure.ErrorCode, H2::ErrorNoError);
        };

        std::error_code ErrorCode;
        EXPECT_TRUE(Server->Feed(Wire, ErrorCode));
        EXPECT_EQ(HeadersSeen, StreamId);
        EXPECT_EQ(DataSeen, 3);
        EXPECT_EQ(ClosedSeen, StreamId);
    }

    TEST(H2Session, ServerConsumesStandardConnectionPreface)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::Session>(IoContext.get_executor(), true);
        constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        const auto Settings = H2::Detail::BuildFrame({FrameType::Settings, 0, 0, {}});
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
        const auto Header = H2::Detail::ParseFrameHeader(Reply);
        ASSERT_TRUE(Header.has_value());
        EXPECT_EQ(Header->Type, FrameType::Settings);
        EXPECT_EQ(Header->Flags, H2::Detail::FlagAck);
    }

    TEST(H2Session, ServerConsumesSplitConnectionPreface)
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<H2::Session>(IoContext.get_executor(), true);
        constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        const auto Settings = H2::Detail::BuildFrame({FrameType::Settings, 0, 0, {}});
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
        const auto Header = H2::Detail::ParseFrameHeader(Reply);
        ASSERT_TRUE(Header.has_value());
        EXPECT_EQ(Header->Type, FrameType::Settings);
        EXPECT_EQ(Header->Flags, H2::Detail::FlagAck);
    }

    TEST(H2Session, RejectsSettingsWithoutConnectionPreface)
    {
        Net::io_context IoContext;
        auto EventTarget = std::make_shared<H2::Session>(IoContext.get_executor(), true);
        H2::Detail::SessionState Server(IoContext.get_executor(), true, *EventTarget);
        int SettingsSeen = 0;
        Server.OnSettings = [&SettingsSeen](const std::vector<H2::SettingsEntry> &)
        {
            ++SettingsSeen;
        };
        const auto Frame = H2::Detail::BuildFrame({FrameType::Settings, 0, 0, {}});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server.Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
        EXPECT_EQ(SettingsSeen, 0);
    }

    TEST(H2Session, ClientSendsConnectionPrefaceBeforeSettings)
    {
        Net::io_context IoContext;
        auto Client = std::make_shared<H2::Session>(IoContext.get_executor(), false);
        constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        Client->SendSettings();
        std::vector<std::byte> Wire;
        ASSERT_TRUE(Client->Collect(Wire));
        ASSERT_GE(Wire.size(), Preface.size());
        for (std::size_t Index = 0; Index < Preface.size(); ++Index)
        {
            EXPECT_EQ(std::to_integer<char>(Wire[Index]), Preface[Index]);
        }
        const auto Header = H2::Detail::ParseFrameHeader(
            std::span<const std::byte>(Wire).subspan(Preface.size()));
        ASSERT_TRUE(Header.has_value());
        EXPECT_EQ(Header->Type, FrameType::Settings);
    }

    TEST(H2Session, ResponseOnLocallyOpenedStreamAfterPeerEnd)
    {
        Net::io_context IoContext;
        auto Client = std::make_shared<H2::Session>(IoContext.get_executor(), false);
        auto Server = std::make_shared<H2::Session>(IoContext.get_executor(), true);
        const auto Opened = Client->OpenStream({{":method", "POST"}, {":path", "/"}}, false);
        ASSERT_TRUE(Opened); const auto StreamId = *Opened; ASSERT_GT(StreamId, 0);
        const std::array<std::byte, 1> RequestData{std::byte{0x41}};
        ASSERT_EQ(Client->SubmitData(StreamId, RequestData, true), Preview::Http2::SubmitDataStatus::Accepted);

        Server->OnHeaders = [&](std::int32_t Id, const HeaderList &, bool EndStream)
        {
            EXPECT_FALSE(EndStream);
            EXPECT_TRUE(Server->SubmitHeaders(Id, {{":status", "200"}}, false));
            EXPECT_EQ(Server->SubmitData(Id, RequestData, false), Preview::Http2::SubmitDataStatus::Accepted);
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
        auto EventTarget = std::make_shared<H2::Session>(IoContext.get_executor(), true);
        auto Server = MakePrefacedServerState(IoContext, *EventTarget);

        std::vector<H2::SettingsEntry> Entries = {{H2::SettingsMaxConcurrentStreams, 10}};
        auto Payload = H2::Detail::EncodeSettings(Entries);
        auto Frame = H2::Detail::BuildFrame({FrameType::Settings, 0, 0, Payload});

        int SettingsSeen = 0;
        Server->OnSettings = [&](const std::vector<H2::SettingsEntry> &e) { SettingsSeen = static_cast<int>(e.size()); };
        std::error_code ErrorCode;
        EXPECT_TRUE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(SettingsSeen, 1);

        // ACK 帧入队
        std::vector<std::byte> Output;
        (void)Server->Collect(Output);
        ASSERT_GE(Output.size(), H2::Detail::FrameHeaderSize);
        const auto h = H2::Detail::ParseFrameHeader(Output);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->Type, FrameType::Settings);
        EXPECT_EQ(h->Flags, H2::Detail::FlagAck);
    }

    TEST(H2Session, SettingsAckWithPayloadRejected)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const std::array<std::byte, 1> Payload{std::byte{0x01}};
        const auto Frame = H2::Detail::BuildFrame({FrameType::Settings, H2::Detail::FlagAck, 0, Payload});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, WindowUpdateZeroIncrementRejected)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const std::array<std::byte, 4> Payload{};
        const auto Frame = H2::Detail::BuildFrame({FrameType::WindowUpdate, 0, 0, Payload});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, RstStreamInvalidLengthRejected)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Frame = H2::Detail::BuildFrame({FrameType::RstStream, 0, 1, {}});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, RstStreamOnConnectionStreamRejected)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Frame = H2::Detail::BuildFrame({FrameType::RstStream, 0, 0, H2::Detail::EncodeRstStream(H2::ErrorCancel)});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, RstStreamOnIdleStreamRejected)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Frame = H2::Detail::BuildFrame({FrameType::RstStream, 0, 1, H2::Detail::EncodeRstStream(H2::ErrorCancel)});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, HeadersWithoutEndHeadersWaitsForContinuation)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, 0, 1, {}});
        const auto Data = H2::Detail::BuildFrame({FrameType::Data, 0, 1, {}});
        std::error_code ErrorCode;
        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        EXPECT_FALSE(Server->Feed(Data, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, DataOnIdleStreamRejected)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const std::array<std::byte, 1> Payload{std::byte{0x01}};
        const auto Frame = H2::Detail::BuildFrame({FrameType::Data, 0, 1, Payload});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, DataAfterEndStreamRejected)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers,
                                              static_cast<std::uint8_t>(H2::Detail::FlagEndHeaders | H2::Detail::FlagEndStream),
                                              1,
                                              {}});
        const std::array<std::byte, 1> Payload{std::byte{0x01}};
        const auto Data = H2::Detail::BuildFrame({FrameType::Data, 0, 1, Payload});
        std::error_code ErrorCode;
        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        EXPECT_FALSE(Server->Feed(Data, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, PriorityInvalidLengthRejected)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const std::array<std::byte, 4> Payload{};
        const auto Frame = H2::Detail::BuildFrame({FrameType::Priority, 0, 1, Payload});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Frame, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, BadFrameRejected)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);

        // 流 0 上发 DATA → 协议错误
        std::vector<std::byte> Payload(10, std::byte{0});
        auto Bad = H2::Detail::BuildFrame({FrameType::Data, 0, 0, Payload});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Bad, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, ContinuationRejected)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        auto Bad = H2::Detail::BuildFrame({FrameType::Continuation, 0, 1, {}});
        std::error_code ErrorCode;
        EXPECT_FALSE(Server->Feed(Bad, ErrorCode));
    }

    TEST(H2Session, HeadersContinuationReassemblesBeforeDispatch)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        int HeadersSeen = 0;
        Server->OnHeaders = [&HeadersSeen](std::int32_t, const HeaderList &, bool)
        {
            ++HeadersSeen;
        };
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, 0, 1, {}});
        const auto Continuation = H2::Detail::BuildFrame({FrameType::Continuation, H2::Detail::FlagEndHeaders, 1, {}});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        EXPECT_TRUE(Server->Feed(Continuation, ErrorCode));
        EXPECT_EQ(HeadersSeen, 1);
    }

    TEST(H2Session, HeadersContinuationDecodesSplitHpackBlock)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        HeaderList Received;
        Server->OnHeaders = [&Received](std::int32_t, const HeaderList &Headers, bool EndStream)
        {
            EXPECT_FALSE(EndStream);
            Received = Headers;
        };
        H2::Detail::HpackEncoder Encoder;
        const auto Block = Encoder.Encode({{":method", "GET"}, {":path", "/carrier"},
                                            {":authority", "edge.example"}});
        ASSERT_GT(Block.size(), 1U);
        const auto Split = H2::Detail::BuildFrame({FrameType::Headers, 0, 1,
                                            std::span<const std::byte>(Block).first(1)});
        const auto Tail = H2::Detail::BuildFrame({FrameType::Continuation, H2::Detail::FlagEndHeaders, 1,
                                          std::span<const std::byte>(Block).subspan(1)});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Split, ErrorCode));
        ASSERT_TRUE(Server->Feed(Tail, ErrorCode));
        ASSERT_EQ(Received.size(), 3U);
        EXPECT_EQ(Received[0].Name, ":method");
        EXPECT_EQ(Received[0].Value, "GET");
        EXPECT_EQ(Received[1].Value, "/carrier");
        EXPECT_EQ(Received[2].Value, "edge.example");
    }

    TEST(H2Session, HeadersContinuationExcludesTrailingPadding)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        HeaderList Received;
        Server->OnHeaders = [&Received](std::int32_t, const HeaderList &Headers, bool)
        {
            Received = Headers;
        };
        H2::Detail::HpackEncoder Encoder;
        const auto Block = Encoder.Encode({{":method", "GET"}, {":path", "/padded"}});
        std::vector<std::byte> FirstPayload;
        FirstPayload.push_back(std::byte{0x02});
        FirstPayload.insert(FirstPayload.end(), Block.begin(), Block.end());
        FirstPayload.push_back(std::byte{0x00});
        FirstPayload.push_back(std::byte{0x00});
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, H2::Detail::FlagPadded, 1, FirstPayload});
        const auto Continuation = H2::Detail::BuildFrame({FrameType::Continuation, H2::Detail::FlagEndHeaders, 1, {}});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        ASSERT_TRUE(Server->Feed(Continuation, ErrorCode));
        ASSERT_EQ(Received.size(), 2U);
        EXPECT_EQ(Received[1].Value, "/padded");
    }

    TEST(H2Session, ContinuationRejectsEndStreamFlag)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, 0, 1, {}});
        const auto Continuation = H2::Detail::BuildFrame({FrameType::Continuation,
                                                  static_cast<std::uint8_t>(H2::Detail::FlagEndHeaders | H2::Detail::FlagEndStream),
                                                  1, {}});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        EXPECT_FALSE(Server->Feed(Continuation, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, DataRefreshesConnectionAndStreamWindow)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, H2::Detail::FlagEndHeaders, 1, {}});
        const std::vector<std::byte> Payload(16384, std::byte{0x5A});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        for (std::size_t Index = 0; Index < 8; ++Index)
        {
            const auto DataFrame = H2::Detail::BuildFrame({FrameType::Data, 0, 1, Payload});
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
            const auto Header = H2::Detail::ParseFrameHeader(Remaining);
            ASSERT_TRUE(Header.has_value());
            ASSERT_LE(H2::Detail::FrameHeaderSize + Header->Length, Remaining.size());
            if (Header->Type == FrameType::WindowUpdate)
            {
                ASSERT_EQ(Header->Length, 4U);
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
            Offset += H2::Detail::FrameHeaderSize + Header->Length;
        }
        EXPECT_EQ(ConnectionUpdates, 8U);
        EXPECT_EQ(StreamUpdates, 8U);
    }

    TEST(H2Session, ConsumeDataCapsWindowUpdateAt31Bits)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, H2::Detail::FlagEndHeaders, 1, {}});
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
            const auto Header = H2::Detail::ParseFrameHeader(Remaining);
            ASSERT_TRUE(Header.has_value());
            ASSERT_LE(H2::Detail::FrameHeaderSize + Header->Length, Remaining.size());
            if (Header->Type == FrameType::WindowUpdate)
            {
                ASSERT_EQ(Header->Length, 4U);
                const auto Payload = Remaining.subspan(H2::Detail::FrameHeaderSize, Header->Length);
                const auto Increment = H2::Detail::DecodeU31(Payload);
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
            Offset += H2::Detail::FrameHeaderSize + Header->Length;
        }
        EXPECT_EQ(ConnectionUpdates, 1U);
        EXPECT_EQ(StreamUpdates, 1U);
    }

    TEST(H2Session, SettingsUpdatePeerWindowAndFrameSize)
    {
        Net::io_context IoContext;
        auto Client = std::make_shared<H2::Session>(IoContext.get_executor(), false);
        const auto Opened = Client->OpenStream({{":method", "GET"}, {":path", "/"}}, false);
        ASSERT_TRUE(Opened); const auto StreamId = *Opened; ASSERT_GT(StreamId, 0);
        const std::vector<H2::SettingsEntry> Entries = {
            {H2::SettingsInitialWindowSize, 0}, {H2::SettingsMaxFrameSize, 16384}};
        const auto Settings = H2::Detail::BuildFrame({FrameType::Settings, 0, 0, H2::Detail::EncodeSettings(Entries)});
        std::error_code ErrorCode;

        ASSERT_TRUE(Client->Feed(Settings, ErrorCode));
        const std::array<std::byte, 1> Byte{std::byte{0x01}};
        EXPECT_EQ(Client->SubmitData(StreamId, Byte, false), H2::SubmitDataStatus::Blocked);
        const auto Update = H2::Detail::BuildFrame({FrameType::WindowUpdate, 0, static_cast<std::uint32_t>(StreamId),
                                             H2::Detail::EncodeWindowUpdate(1)});
        ASSERT_TRUE(Client->Feed(Update, ErrorCode));
        EXPECT_EQ(Client->SubmitData(StreamId, Byte, false), Preview::Http2::SubmitDataStatus::Accepted);

        const auto MoreConnection = H2::Detail::BuildFrame({FrameType::WindowUpdate, 0, 0,
                                                     H2::Detail::EncodeWindowUpdate(20000)});
        const auto MoreStream = H2::Detail::BuildFrame({FrameType::WindowUpdate, 0,
                                                static_cast<std::uint32_t>(StreamId),
                                                H2::Detail::EncodeWindowUpdate(20000)});
        ASSERT_TRUE(Client->Feed(MoreConnection, ErrorCode));
        ASSERT_TRUE(Client->Feed(MoreStream, ErrorCode));
        std::vector<std::byte> Large(17000, std::byte{0x2A});
        EXPECT_EQ(Client->SubmitData(StreamId, Large, false), Preview::Http2::SubmitDataStatus::Accepted);
    }

    TEST(H2Session, RstStreamReportsFullErrorCode)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, H2::Detail::FlagEndHeaders, 1, {}});
        const auto Rst = H2::Detail::BuildFrame({FrameType::RstStream, 0, 1, H2::Detail::EncodeRstStream(0x80000001U)});
        std::optional<H2::StreamReceiveClosure> Closure;
        Server->OnStreamClose = [&Closure](const H2::StreamReceiveClosure &Value)
        {
            Closure = Value;
        };
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        ASSERT_TRUE(Server->Feed(Rst, ErrorCode));
        ASSERT_TRUE(Closure.has_value());
        EXPECT_EQ(Closure->Kind, H2::StreamReceiveClosureKind::Reset);
        EXPECT_EQ(Closure->ErrorCode, 0x80000001U);
    }

    TEST(H2Session, ResetStreamRejectsIdleAndClosedStreams)
    {
        Net::io_context IoContext;
        auto Client = std::make_shared<H2::Session>(IoContext.get_executor(), false);
        EXPECT_FALSE(Client->ResetStream(0, H2::ErrorCancel));
        EXPECT_FALSE(Client->ResetStream(1, H2::ErrorCancel));
        const auto Opened = Client->OpenStream({}, true);
        ASSERT_TRUE(Opened); const auto StreamId = *Opened; ASSERT_GT(StreamId, 0);
        EXPECT_TRUE(Client->ResetStream(StreamId, H2::ErrorCancel));
        EXPECT_FALSE(Client->ResetStream(StreamId, H2::ErrorCancel));

        constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        std::vector<std::byte> Wire;
        ASSERT_TRUE(Client->Collect(Wire));
        ASSERT_GE(Wire.size(), Preface.size());
        const auto Reset = H2::Detail::BuildFrame({
            FrameType::RstStream, 0, static_cast<std::uint32_t>(StreamId),
            H2::Detail::EncodeRstStream(H2::ErrorCancel)});
        const auto Frame = std::search(
            Wire.begin() + static_cast<std::ptrdiff_t>(Preface.size()), Wire.end(),
            Reset.begin(), Reset.end());
        EXPECT_NE(Frame, Wire.end());
    }

    TEST(H2Session, ResetWithNoErrorRemainsDistinctFromEndStream)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, H2::Detail::FlagEndHeaders, 1, {}});
        const auto Reset = H2::Detail::BuildFrame(
            {FrameType::RstStream, 0, 1, H2::Detail::EncodeRstStream(H2::ErrorNoError)});
        std::optional<H2::StreamReceiveClosure> Closure;
        Server->OnStreamClose = [&Closure](const H2::StreamReceiveClosure &Value)
        {
            Closure = Value;
        };
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        ASSERT_TRUE(Server->Feed(Reset, ErrorCode));
        ASSERT_TRUE(Closure.has_value());
        EXPECT_EQ(Closure->Kind, H2::StreamReceiveClosureKind::Reset);
        EXPECT_EQ(Closure->ErrorCode, H2::ErrorNoError);

        auto EndServer = MakePrefacedServer(IoContext);
        const auto EndHeaders = H2::Detail::BuildFrame({FrameType::Headers, H2::Detail::FlagEndHeaders, 1, {}});
        const auto EndStream = H2::Detail::BuildFrame({FrameType::Data, H2::Detail::FlagEndStream, 1, {}});
        std::optional<H2::StreamReceiveClosure> EndClosure;
        EndServer->OnStreamClose = [&EndClosure](const H2::StreamReceiveClosure &Value)
        {
            EndClosure = Value;
        };
        ASSERT_TRUE(EndServer->Feed(EndHeaders, ErrorCode));
        ASSERT_TRUE(EndServer->Feed(EndStream, ErrorCode));
        ASSERT_TRUE(EndClosure.has_value());
        EXPECT_EQ(EndClosure->Kind, H2::StreamReceiveClosureKind::EndStream);
        EXPECT_EQ(EndClosure->ErrorCode, 0U);
        const std::array<std::byte, 1> Response{std::byte{0x41}};
        EXPECT_EQ(EndServer->SubmitData(1, Response, true), Preview::Http2::SubmitDataStatus::Accepted);
        EXPECT_FALSE(EndServer->ResetStream(1, H2::ErrorCancel));
    }

    TEST(H2Session, LateDataAfterResetRestoresConnectionCreditOnly)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, H2::Detail::FlagEndHeaders, 1, {}});
        const auto Reset = H2::Detail::BuildFrame(
            {FrameType::RstStream, 0, 1, H2::Detail::EncodeRstStream(H2::ErrorCancel)});
        const std::vector<std::byte> Payload(32, std::byte{0x5A});
        const auto LateData = H2::Detail::BuildFrame({FrameType::Data, 0, 1, Payload});
        const auto SiblingHeaders = H2::Detail::BuildFrame({FrameType::Headers, H2::Detail::FlagEndHeaders, 3, {}});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        ASSERT_TRUE(Server->Feed(Reset, ErrorCode));
        ASSERT_TRUE(Server->Feed(LateData, ErrorCode));
        ASSERT_TRUE(Server->Feed(SiblingHeaders, ErrorCode));

        std::vector<std::byte> Output;
        ASSERT_TRUE(Server->Collect(Output));
        std::size_t ConnectionUpdates = 0;
        std::size_t StreamUpdates = 0;
        std::size_t Offset = 0;
        while (Offset < Output.size())
        {
            const auto Remaining = std::span<const std::byte>(Output).subspan(Offset);
            const auto Header = H2::Detail::ParseFrameHeader(Remaining);
            ASSERT_TRUE(Header.has_value());
            ASSERT_LE(H2::Detail::FrameHeaderSize + Header->Length, Remaining.size());
            if (Header->Type == FrameType::WindowUpdate)
            {
                if (Header->StreamId == H2::Detail::ConnectionStreamId) ++ConnectionUpdates;
                else ++StreamUpdates;
            }
            Offset += H2::Detail::FrameHeaderSize + Header->Length;
        }
        EXPECT_EQ(ConnectionUpdates, 1U);
        EXPECT_EQ(StreamUpdates, 0U);
    }

    TEST(H2Session, RemoteEndRetainsStateUntilLocalEndStream)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, H2::Detail::FlagEndHeaders, 1, {}});
        const auto RemoteEnd = H2::Detail::BuildFrame({FrameType::Data, H2::Detail::FlagEndStream, 1, {}});
        const std::array<std::byte, 1> Reply{std::byte{0x41}};
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        ASSERT_TRUE(Server->Feed(RemoteEnd, ErrorCode));
        EXPECT_EQ(Server->SubmitData(1, Reply, false), Preview::Http2::SubmitDataStatus::Accepted);
        EXPECT_EQ(Server->SubmitData(1, Reply, true), Preview::Http2::SubmitDataStatus::Accepted);
        EXPECT_EQ(Server->SubmitData(1, {}, false), H2::SubmitDataStatus::Closed);
    }

    TEST(H2Session, HeadersRejectPeerStreamParityAndRegression)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto EvenStream = H2::Detail::BuildFrame({FrameType::Headers, H2::Detail::FlagEndHeaders, 2, {}});
        const auto First = H2::Detail::BuildFrame({FrameType::Headers, H2::Detail::FlagEndHeaders, 3, {}});
        const auto Lower = H2::Detail::BuildFrame({FrameType::Headers, H2::Detail::FlagEndHeaders, 1, {}});
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
        auto Server = MakePrefacedServer(IoContext);
        const auto Update = H2::Detail::BuildFrame({FrameType::WindowUpdate, 0, 0,
                                             H2::Detail::EncodeWindowUpdate(0x7FFFFFFFU)});
        std::error_code ErrorCode;

        EXPECT_FALSE(Server->Feed(Update, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, UnknownFrameTypeRejected)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Unknown = H2::Detail::BuildFrame({static_cast<FrameType>(0xFF), 0, 0, {}});
        std::error_code ErrorCode;

        EXPECT_FALSE(Server->Feed(Unknown, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, ContinuationOnDifferentStreamRejected)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, 0, 1, {}});
        const auto Continuation = H2::Detail::BuildFrame({FrameType::Continuation, H2::Detail::FlagEndHeaders, 3, {}});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        EXPECT_FALSE(Server->Feed(Continuation, ErrorCode));
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::ProtocolError));
    }

    TEST(H2Session, PingPong)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        std::array<std::byte, 8> Opaque{};
        auto Ping = H2::Detail::BuildFrame({FrameType::Ping, 0, 0, Opaque});
        std::error_code ErrorCode;
        EXPECT_TRUE(Server->Feed(Ping, ErrorCode));
        std::vector<std::byte> Output;
        (void)Server->Collect(Output);
        ASSERT_GE(Output.size(), H2::Detail::FrameHeaderSize);
        const auto h = H2::Detail::ParseFrameHeader(Output);
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(h->Type, FrameType::Ping);
        EXPECT_EQ(h->Flags, H2::Detail::FlagAck);
    }

    TEST(H2Session, RejectsNegativeStreamIdOnSend)
    {
        Net::io_context IoContext;
        auto Client = std::make_shared<H2::Session>(IoContext.get_executor(), false);
        EXPECT_FALSE(Client->SubmitHeaders(-1, {}, false));
        EXPECT_EQ(Client->SubmitData(-1, {}, false), H2::SubmitDataStatus::Invalid);
        EXPECT_FALSE(Client->ResetStream(-1, H2::ErrorCancel));
        std::vector<std::byte> Out;
        EXPECT_FALSE(Client->Collect(Out));
        EXPECT_TRUE(Out.empty());
    }
} // namespace
