/**
 * @file H2FrameValidationTest.cpp
 * @brief HTTP/2 帧分发、必需长度与语义错误分类测试。
 */

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Http2/Detail/Codec.hpp>
#include <Prism/Protocols/Http2/Detail/Frame.hpp>
#include <Prism/Protocols/Http2/Session.hpp>

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
    namespace H2 = Prism::Http2;
    namespace Net = boost::asio;
    using H2::Detail::FrameType;

    [[nodiscard]] auto MakePrefacedServer(Net::io_context &IoContext)
        -> std::shared_ptr<H2::Session>
    {
        auto Server = std::make_shared<H2::Session>(IoContext.get_executor(), true);
        constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        const auto Wire = std::as_bytes(std::span{Preface.data(), Preface.size()});
        std::error_code Error;
        EXPECT_TRUE(Server->Feed(Wire, Error));
        EXPECT_FALSE(Error);
        return Server;
    }

    auto ExpectBadLength(H2::Session &Session, const std::vector<std::byte> &Frame) -> void
    {
        std::error_code Error;
        EXPECT_FALSE(Session.Feed(Frame, Error));
        EXPECT_EQ(Error, Prism::make_error_code(Prism::Error::BadLength));
    }

    auto ExpectProtocolError(H2::Session &Session, const std::vector<std::byte> &Frame) -> void
    {
        std::error_code Error;
        EXPECT_FALSE(Session.Feed(Frame, Error));
        EXPECT_EQ(Error, Prism::make_error_code(Prism::Error::ProtocolError));
    }

    auto ExpectBadLengthFromHeader(H2::Session &Session, std::vector<std::byte> Frame) -> void
    {
        Frame.resize(H2::Detail::FrameHeaderSize);
        ExpectBadLength(Session, Frame);
    }

    [[nodiscard]] auto MakeHeaderOnlyFrame(
        const FrameType Type,
        const std::uint32_t StreamId) -> std::vector<std::byte>
    {
        auto Frame = H2::Detail::BuildFrame({Type, 0, StreamId, {}});
        Frame.resize(H2::Detail::FrameHeaderSize);
        return Frame;
    }

    [[nodiscard]] auto MakeEnablePushSettingsFrame(const std::uint32_t Value)
        -> std::vector<std::byte>
    {
        const std::array Entries{H2::SettingsEntry{H2::SettingsEnablePush, Value}};
        const auto Payload = H2::Detail::EncodeSettings(Entries);
        return H2::Detail::BuildFrame({FrameType::Settings, 0, 0, Payload});
    }

    TEST(H2FrameDispatch, UnknownFrameDiscardedAndFollowingHeadersProcessed)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        bool HeadersReceived = false;
        Server->OnHeaders = [&HeadersReceived](std::int32_t, const H2::HeaderList &, bool)
        { HeadersReceived = true; };

        const std::array<std::byte, 3> UnknownPayload{
            std::byte{0x13}, std::byte{0x37}, std::byte{0xA5}};
        const auto Unknown = H2::Detail::BuildFrame(
            {static_cast<FrameType>(0xFF), 0, 0, UnknownPayload});
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers,
            H2::Detail::FlagEndHeaders, 1, {}});
        auto Wire = Unknown;
        Wire.insert(Wire.end(), Headers.begin(), Headers.end());
        std::error_code Error;

        EXPECT_TRUE(Server->Feed(Wire, Error));
        EXPECT_FALSE(Error);
        EXPECT_TRUE(HeadersReceived);
    }

    TEST(H2Session, UnknownFrameBreaksPendingHeaderContinuation)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, 0, 1, {}});
        const auto Unknown = H2::Detail::BuildFrame({static_cast<FrameType>(0xFF), 0, 0, {}});
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        ASSERT_FALSE(ErrorCode);
        EXPECT_FALSE(Server->Feed(Unknown, ErrorCode));
        EXPECT_EQ(ErrorCode, Prism::make_error_code(Prism::Error::ProtocolError));
    }

    TEST(H2Session, UnknownFrameTypeIgnored)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Unknown = H2::Detail::BuildFrame(
            {static_cast<FrameType>(0xFF), 0, 0, {}});
        std::error_code ErrorCode;

        EXPECT_TRUE(Server->Feed(Unknown, ErrorCode));
        EXPECT_FALSE(ErrorCode);
    }

    TEST(H2Session, ContinuationIgnoresUndefinedEndStreamFlag)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        H2::Detail::HpackEncoder Encoder;
        const auto Block = Encoder.Encode({{":method", "GET"}, {":path", "/continued"}});
        ASSERT_GT(Block.size(), 1U);
        const auto Split = Block.size() / 2;
        const std::vector<std::byte> FirstFragment(Block.begin(), Block.begin() + Split);
        const std::vector<std::byte> SecondFragment(Block.begin() + Split, Block.end());
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, 0, 1, FirstFragment});
        const auto Continuation = H2::Detail::BuildFrame({FrameType::Continuation,
                                                  static_cast<std::uint8_t>(H2::Detail::FlagEndHeaders | H2::Detail::FlagEndStream),
                                                  1, SecondFragment});
        std::optional<bool> HeaderEndStream;
        std::optional<H2::HeaderList> ReceivedHeaders;
        bool StreamClosed = false;
        Server->OnHeaders = [&HeaderEndStream, &ReceivedHeaders](
                                std::int32_t, const H2::HeaderList &HeadersValue, bool EndStream)
        {
            HeaderEndStream = EndStream;
            ReceivedHeaders = HeadersValue;
        };
        Server->OnStreamClose = [&StreamClosed](const H2::StreamReceiveClosure &)
        { StreamClosed = true; };
        std::error_code ErrorCode;

        ASSERT_TRUE(Server->Feed(Headers, ErrorCode));
        EXPECT_TRUE(Server->Feed(Continuation, ErrorCode));
        EXPECT_FALSE(ErrorCode);
        ASSERT_TRUE(HeaderEndStream.has_value());
        EXPECT_FALSE(*HeaderEndStream);
        ASSERT_TRUE(ReceivedHeaders.has_value());
        ASSERT_EQ(ReceivedHeaders->size(), 2U);
        EXPECT_EQ((*ReceivedHeaders)[1].Value, "/continued");
        EXPECT_FALSE(StreamClosed);
    }

    TEST(H2FrameValidation, SettingsPayloadNotAlignedToSixBytesUsesBadLength)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const std::array<std::byte, 1> Payload{std::byte{0x01}};
        const auto Frame = H2::Detail::BuildFrame({FrameType::Settings, 0, 0, Payload});
        ExpectBadLength(*Server, Frame);

        auto LongServer = MakePrefacedServer(IoContext);
        const std::array<std::byte, 7> LongPayload{};
        const auto LongFrame = H2::Detail::BuildFrame({FrameType::Settings, 0, 0, LongPayload});
        ExpectBadLength(*LongServer, LongFrame);
    }

    TEST(H2FrameValidation, PingPayloadLengthUsesBadLength)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const std::array<std::byte, 7> Payload{};
        const auto Frame = H2::Detail::BuildFrame({FrameType::Ping, 0, 0, Payload});
        ExpectBadLength(*Server, Frame);

        auto LongServer = MakePrefacedServer(IoContext);
        const std::array<std::byte, 9> LongPayload{};
        const auto LongFrame = H2::Detail::BuildFrame({FrameType::Ping, 0, 0, LongPayload});
        ExpectBadLength(*LongServer, LongFrame);
    }

    TEST(H2FrameValidation, PingConnectionStreamRequirementUsesProtocolError)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const std::array<std::byte, 8> Payload{};
        const auto Frame = H2::Detail::BuildFrame({FrameType::Ping, 0, 1, Payload});
        ExpectProtocolError(*Server, Frame);
    }

    TEST(H2FrameValidation, WindowUpdatePayloadLengthUsesBadLength)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const std::array<std::byte, 3> Payload{};
        const auto Frame = H2::Detail::BuildFrame({FrameType::WindowUpdate, 0, 0, Payload});
        ExpectBadLength(*Server, Frame);

        auto LongServer = MakePrefacedServer(IoContext);
        const std::array<std::byte, 5> LongPayload{};
        const auto LongFrame = H2::Detail::BuildFrame(
            {FrameType::WindowUpdate, 0, 0, LongPayload});
        ExpectBadLength(*LongServer, LongFrame);
    }

    TEST(H2FrameValidation, PaddedDataWithoutPadLengthUsesBadLength)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers,
            H2::Detail::FlagEndHeaders, 1, {}});
        std::error_code Error;
        ASSERT_TRUE(Server->Feed(Headers, Error));

        const auto Data = H2::Detail::BuildFrame({FrameType::Data,
            H2::Detail::FlagPadded, 1, {}});
        ExpectBadLength(*Server, Data);
    }

    TEST(H2FrameValidation, PaddedHeadersWithoutPadLengthUsesBadLength)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers,
            static_cast<std::uint8_t>(H2::Detail::FlagPadded | H2::Detail::FlagEndHeaders),
            1, {}});
        ExpectBadLength(*Server, Headers);
    }

    TEST(H2FrameValidation, HeadersPriorityWithoutDependencyFieldUsesBadLength)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        std::array<std::byte, 4> Payload{};
        H2::Detail::EncodeU31(1, std::span<std::byte, 4>{Payload});
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers,
            static_cast<std::uint8_t>(H2::Detail::FlagPriority | H2::Detail::FlagEndHeaders),
            1, Payload});
        ExpectBadLength(*Server, Headers);
    }

    TEST(H2FrameValidation, PriorityFrameSelfDependencyUsesProtocolError)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        std::array<std::byte, 5> Payload{};
        H2::Detail::EncodeU31(1, std::span<std::byte, 4>{Payload.data(), 4});
        const auto Frame = H2::Detail::BuildFrame({FrameType::Priority, 0, 1, Payload});
        ExpectProtocolError(*Server, Frame);
    }

    TEST(H2FrameValidation, HeadersPrioritySelfDependencyUsesProtocolError)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        std::array<std::byte, 5> Payload{};
        H2::Detail::EncodeU31(1, std::span<std::byte, 4>{Payload.data(), 4});
        const auto Frame = H2::Detail::BuildFrame({FrameType::Headers,
            static_cast<std::uint8_t>(H2::Detail::FlagPriority | H2::Detail::FlagEndHeaders),
            1, Payload});
        ExpectProtocolError(*Server, Frame);
    }

    TEST(H2FrameValidation, GoawayWithoutRequiredFieldsUsesBadLength)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Frame = H2::Detail::BuildFrame({FrameType::Goaway, 0, 0, {}});
        ExpectBadLength(*Server, Frame);

        auto ShortServer = MakePrefacedServer(IoContext);
        const std::array<std::byte, 7> ShortPayload{};
        const auto ShortFrame = H2::Detail::BuildFrame(
            {FrameType::Goaway, 0, 0, ShortPayload});
        ExpectBadLength(*ShortServer, ShortFrame);
    }

    TEST(H2FrameValidation, GoawayRequiresConnectionStream)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const std::array<std::byte, 8> Payload{};
        const auto Frame = H2::Detail::BuildFrame({FrameType::Goaway, 0, 1, Payload});
        ExpectProtocolError(*Server, Frame);
    }

    TEST(H2FrameValidation, PayloadAboveDefaultFrameLimitUsesBadLength)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const std::vector<std::byte> Payload(H2::Detail::DefaultFramePayload + 1);
        const auto Frame = H2::Detail::BuildFrame({FrameType::Ping, 0, 0, Payload});
        ExpectBadLength(*Server, Frame);
    }

    TEST(H2FrameValidation, OversizedFrameHeaderAloneUsesBadLength)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const std::vector<std::byte> Payload(H2::Detail::DefaultFramePayload + 1);
        const auto Frame = H2::Detail::BuildFrame({FrameType::Ping, 0, 0, Payload});
        const auto Header = std::span<const std::byte>(Frame).first<H2::Detail::FrameHeaderSize>();
        const std::vector<std::byte> HeaderOnly(Header.begin(), Header.end());
        ExpectBadLength(*Server, HeaderOnly);
    }

    TEST(H2FrameValidation, TypeSpecificLengthErrorsRejectHeaderBeforePayload)
    {
        struct HeaderCase
        {
            FrameType Type;
            std::uint8_t Flags;
            std::size_t PayloadLength;
        };
        constexpr std::array Cases{
            HeaderCase{FrameType::Settings, 0, 1},
            HeaderCase{FrameType::Settings, H2::Detail::FlagAck, 6},
            HeaderCase{FrameType::Ping, 0, 7},
            HeaderCase{FrameType::RstStream, 0, 3},
            HeaderCase{FrameType::WindowUpdate, 0, 3},
            HeaderCase{FrameType::Priority, 0, 4},
            HeaderCase{FrameType::Goaway, 0, 7},
            HeaderCase{FrameType::PushPromise, 0, 3},
            HeaderCase{FrameType::PushPromise, H2::Detail::FlagPadded, 4},
            HeaderCase{FrameType::Data, H2::Detail::FlagPadded, 0},
            HeaderCase{FrameType::Headers, H2::Detail::FlagPadded, 0},
            HeaderCase{FrameType::Headers, H2::Detail::FlagPriority, 4},
            HeaderCase{FrameType::Headers,
                static_cast<std::uint8_t>(H2::Detail::FlagPadded | H2::Detail::FlagPriority), 5},
        };

        for (const auto &Case : Cases)
        {
            Net::io_context IoContext;
            auto Server = MakePrefacedServer(IoContext);
            const std::vector<std::byte> Payload(Case.PayloadLength);
            auto Frame = H2::Detail::BuildFrame({Case.Type, Case.Flags,
                Case.Type == FrameType::Settings || Case.Type == FrameType::Ping ||
                        Case.Type == FrameType::Goaway
                    ? 0U
                    : 1U,
                Payload});
            ExpectBadLengthFromHeader(*Server, std::move(Frame));
        }
    }

    TEST(H2FrameValidation, PendingHeaderSequenceErrorPrecedesTypeLengthError)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, 0, 1, {}});
        std::error_code Error;
        ASSERT_TRUE(Server->Feed(Headers, Error));

        const std::vector<std::byte> Payload(7);
        auto Ping = H2::Detail::BuildFrame({FrameType::Ping, 0, 0, Payload});
        Ping.resize(H2::Detail::FrameHeaderSize);
        ExpectProtocolError(*Server, Ping);
    }

    TEST(H2FrameValidation, ContinuationSequenceErrorsRejectHeaderBeforePayload)
    {
        Net::io_context OrphanIoContext;
        auto OrphanServer = MakePrefacedServer(OrphanIoContext);
        ExpectProtocolError(*OrphanServer, MakeHeaderOnlyFrame(FrameType::Continuation, 1));

        Net::io_context ZeroStreamIoContext;
        auto ZeroStreamServer = MakePrefacedServer(ZeroStreamIoContext);
        const auto Headers = H2::Detail::BuildFrame({FrameType::Headers, 0, 1, {}});
        std::error_code Error;
        ASSERT_TRUE(ZeroStreamServer->Feed(Headers, Error));
        ExpectProtocolError(*ZeroStreamServer,
            MakeHeaderOnlyFrame(FrameType::Continuation, H2::Detail::ConnectionStreamId));

        Net::io_context WrongStreamIoContext;
        auto WrongStreamServer = MakePrefacedServer(WrongStreamIoContext);
        ASSERT_TRUE(WrongStreamServer->Feed(Headers, Error));
        ExpectProtocolError(*WrongStreamServer, MakeHeaderOnlyFrame(FrameType::Continuation, 3));
    }

    TEST(H2FrameValidation, ServerValidatesEnablePushDirectionAndValue)
    {
        constexpr std::array Cases{
            std::pair<std::uint32_t, bool>{0, true},
            std::pair<std::uint32_t, bool>{1, true},
            std::pair<std::uint32_t, bool>{2, false},
        };
        for (const auto &[Value, Accepted] : Cases)
        {
            Net::io_context IoContext;
            auto Server = MakePrefacedServer(IoContext);
            std::error_code Error;
            EXPECT_EQ(Server->Feed(MakeEnablePushSettingsFrame(Value), Error), Accepted);
            if (Accepted)
            {
                EXPECT_FALSE(Error);
            }
            else
            {
                EXPECT_EQ(Error, Prism::make_error_code(Prism::Error::ProtocolError));
            }
        }
    }

    TEST(H2FrameValidation, ClientValidatesServerEnablePushValue)
    {
        Net::io_context IoContext;
        H2::Session AcceptingClient(IoContext.get_executor(), false);
        std::error_code Error;
        EXPECT_TRUE(AcceptingClient.Feed(MakeEnablePushSettingsFrame(0), Error));
        EXPECT_FALSE(Error);

        H2::Session RejectingClient(IoContext.get_executor(), false);
        EXPECT_FALSE(RejectingClient.Feed(MakeEnablePushSettingsFrame(1), Error));
        EXPECT_EQ(Error, Prism::make_error_code(Prism::Error::ProtocolError));
    }

    TEST(H2FrameValidation, RstStreamPayloadTooLongUsesBadLength)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const std::array<std::byte, 5> Payload{};
        const auto Frame = H2::Detail::BuildFrame({FrameType::RstStream, 0, 1, Payload});
        ExpectBadLength(*Server, Frame);
    }

    TEST(H2FrameValidation, PriorityPayloadTooLongUsesBadLength)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const std::array<std::byte, 6> Payload{};
        const auto Frame = H2::Detail::BuildFrame({FrameType::Priority, 0, 1, Payload});
        ExpectBadLength(*Server, Frame);
    }

    TEST(H2FrameValidation, PushPromiseWithoutPromisedStreamUsesBadLength)
    {
        Net::io_context IoContext;
        auto Server = MakePrefacedServer(IoContext);
        const auto Frame = H2::Detail::BuildFrame({FrameType::PushPromise, 0, 1, {}});
        ExpectBadLength(*Server, Frame);

        auto PaddedServer = MakePrefacedServer(IoContext);
        const std::array<std::byte, 4> PaddedPayload{};
        const auto PaddedFrame = H2::Detail::BuildFrame({FrameType::PushPromise,
            H2::Detail::FlagPadded, 1, PaddedPayload});
        ExpectBadLength(*PaddedServer, PaddedFrame);
    }
} // namespace
