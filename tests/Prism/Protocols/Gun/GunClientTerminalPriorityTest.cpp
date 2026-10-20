/**
 * @file GunClientTerminalPriorityTest.cpp
 * @brief gRPC 客户端同读解析终态与 ACK 写失败优先级回归。
 */

#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/this_coro.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Gun/Grpc.hpp>
#include <Prism/Protocols/Gun/Detail/GrpcSession.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Gun = Prism::Gun::Grpc::Detail;

    struct ScriptedExchange final
    {
        std::vector<std::byte> Input;
        Fault::Failure ReadFailure;
        std::size_t FailWriteCall{0};
        Fault::Failure WriteFailure;
        bool FailSettingsAck{false};
        Fault::Failure CloseFailure;
        bool FailFirstClose{false};
    };

    struct Http2WireSummary final
    {
        std::size_t DataPayloadBytes{0};
        bool HasSettingsAck{false};
        bool HasDataEndStream{false};
    };

    [[nodiscard]] auto SummarizeHttp2Wire(std::span<const std::byte> Wire)
        -> Http2WireSummary
    {
        Http2WireSummary Summary;
        std::size_t Offset = !Wire.empty() && std::to_integer<char>(Wire.front()) == 'P'
            ? 24U
            : 0U;
        if (Offset > Wire.size())
        {
            return Summary;
        }
        while (Wire.size() - Offset >= 9U)
        {
            const auto Length =
                (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Wire[Offset])) << 16U) |
                (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Wire[Offset + 1U])) << 8U) |
                static_cast<std::size_t>(std::to_integer<std::uint8_t>(Wire[Offset + 2U]));
            if (Length > Wire.size() - Offset - 9U)
            {
                break;
            }
            const auto Type = std::to_integer<std::uint8_t>(Wire[Offset + 3U]);
            const auto Flags = std::to_integer<std::uint8_t>(Wire[Offset + 4U]);
            if (Type == 0U)
            {
                Summary.DataPayloadBytes += Length;
                Summary.HasDataEndStream = Summary.HasDataEndStream || (Flags & 0x01U) != 0U;
            }
            if (Type == 4U && (Flags & 0x01U) != 0U && Length == 0U)
            {
                Summary.HasSettingsAck = true;
            }
            Offset += 9U + Length;
        }
        return Summary;
    }

    class ScriptedGrpcTransmission final : public Prism::Transmission
    {
    public:
        ScriptedGrpcTransmission(ExecutorType Executor, ScriptedExchange Exchange)
            : Transmission(Executor), Executor_(std::move(Executor)),
              Input_(std::move(Exchange.Input)), ReadFailure_(std::move(Exchange.ReadFailure)),
              FailWriteCall_(Exchange.FailWriteCall), WriteFailure_(std::move(Exchange.WriteFailure)),
              FailSettingsAck_(Exchange.FailSettingsAck),
              CloseFailure_(std::move(Exchange.CloseFailure)),
              FailFirstClose_(Exchange.FailFirstClose)
        {
        }

        [[nodiscard]] auto ReadCount() const noexcept -> std::size_t { return ReadCount_; }
        [[nodiscard]] auto WriteCount() const noexcept -> std::size_t { return WriteCount_; }
        [[nodiscard]] auto CloseCount() const noexcept -> std::size_t { return CloseCount_; }
        [[nodiscard]] auto AckWriteFailureSeen() const noexcept -> bool
        {
            return AckWriteFailureSeen_;
        }
        [[nodiscard]] auto IsOpen() const -> bool override { return !Closed_; }
        [[nodiscard]] auto Written() const noexcept -> const std::vector<std::byte> &
        {
            return Written_;
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override { return Executor_; }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCount_;
            const auto Count = (std::min)(Buffer.size(), Input_.size() - Offset_);
            if (Count != 0U)
            {
                std::memcpy(Buffer.data(), Input_.data() + Offset_, Count);
                Offset_ += Count;
            }
            auto Failure = Fault::Failure{};
            if (Offset_ == Input_.size() && !TerminalDelivered_)
            {
                Failure = ReadFailure_;
                TerminalDelivered_ = true;
            }
            else if (TerminalDelivered_)
            {
                Failure = {Fault::Code::WouldBlock};
            }
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {Count, Failure});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            ++WriteCount_;
            const auto Wire = SummarizeHttp2Wire(Buffer);
            if (FailSettingsAck_ && Wire.HasSettingsAck)
            {
                AckWriteFailureSeen_ = true;
                Prism::Transmission::PostResult(
                    Executor_, std::move(Handler), {0U, WriteFailure_});
                return;
            }
            if (WriteCount_ == FailWriteCall_)
            {
                Prism::Transmission::PostResult(
                    Executor_, std::move(Handler), {0U, WriteFailure_});
                return;
            }
            Written_.insert(Written_.end(), Buffer.begin(), Buffer.end());
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ++CloseCount_;
            if (FailFirstClose_ && CloseCount_ == 1U)
            {
                return std::unexpected(CloseFailure_);
            }
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override { return {}; }

    private:
        ExecutorType Executor_;
        std::vector<std::byte> Input_;
        std::vector<std::byte> Written_;
        Fault::Failure ReadFailure_;
        std::size_t FailWriteCall_{0};
        Fault::Failure WriteFailure_;
        Fault::Failure CloseFailure_;
        std::size_t Offset_{0};
        std::size_t ReadCount_{0};
        std::size_t WriteCount_{0};
        std::size_t CloseCount_{0};
        bool FailSettingsAck_{false};
        bool FailFirstClose_{false};
        bool Closed_{false};
        bool AckWriteFailureSeen_{false};
        bool TerminalDelivered_{false};
    };

    struct RunOutcome final
    {
        bool ParserAccepted{false};
        bool ParserErrorObserved{false};
        Fault::Failure ParserFailure{};
        Prism::Gun::Grpc::ClientOutcome Result{};
        std::shared_ptr<ScriptedGrpcTransmission> Transport;
        std::size_t DataPayloadBytesWritten{0};
        bool AckWritten{false};
        bool DataEndStreamWritten{false};
        bool AckWriteFailureSeen{false};
        std::size_t ReadCount{0};
        std::size_t WriteCount{0};
        std::size_t CloseCount{0};
    };

    struct RunRequest final
    {
        ScriptedExchange Exchange;
        RunOutcome *Outcome{nullptr};
        std::vector<std::byte> Payload;
        bool CaptureTransport{false};
    };

    [[nodiscard]] auto MakeMalformedSettingsFrame() -> std::vector<std::byte>
    {
        return {
            std::byte{0}, std::byte{0}, std::byte{1}, std::byte{0x04},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}};
    }

    [[nodiscard]] auto MakeSettingsFrame() -> std::vector<std::byte>
    {
        return {
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0x04},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}};
    }

    [[nodiscard]] auto MakePartialSettingsFrame() -> std::vector<std::byte>
    {
        return {std::byte{0}, std::byte{0}, std::byte{0}};
    }

    [[nodiscard]] auto MakeGrpcResponseWire(
        Net::any_io_executor Executor,
        std::vector<std::byte> Message) -> std::vector<std::byte>
    {
        Prism::Http2::Session Client(Executor, false);
        Client.SendSettings();
        const auto Stream = Client.OpenStream(
            Prism::Gun::Grpc::MakeRequestHeaders("/GunService/Tun", "gun"), false);
        if (!Stream)
        {
            return {};
        }
        const auto RequestMessage = Prism::Gun::Grpc::EncodeMessage(
            std::span<const std::byte>{});
        if (Client.SubmitData(
                *Stream, std::span<const std::byte>(RequestMessage), true) !=
            Prism::Http2::SubmitDataStatus::Accepted)
        {
            return {};
        }
        std::vector<std::byte> RequestWire;
        if (!Client.Collect(RequestWire))
        {
            return {};
        }

        Prism::Http2::Session Server(std::move(Executor), true);
        std::error_code Error;
        if (!Server.Feed(std::span<const std::byte>(RequestWire), Error) || Error)
        {
            return {};
        }
        Server.SendSettings();
        if (!Server.SubmitHeaders(1, Prism::Gun::Grpc::MakeResponseHeaders(), false) ||
            Server.SubmitData(1, std::span<const std::byte>(Message), false) !=
                Prism::Http2::SubmitDataStatus::Accepted ||
            !Server.SubmitHeaders(1, Prism::Gun::Grpc::MakeResponseTrailers(0), true))
        {
            return {};
        }
        std::vector<std::byte> ResponseWire;
        if (!Server.Collect(ResponseWire))
        {
            return {};
        }
        return ResponseWire;
    }

    auto RunClient(RunRequest Request) -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        Prism::Http2::Session Parser(Executor, false);
        Parser.SendSettings();
        const auto ParserStream = Parser.OpenStream(
            Prism::Gun::Grpc::MakeRequestHeaders("/GunService/Tun", "gun"), false);
        if (!ParserStream)
        {
            Request.Outcome->ParserAccepted = false;
            Request.Outcome->ParserErrorObserved = true;
        }
        std::error_code ParserError;
        if (ParserStream)
        {
            Request.Outcome->ParserAccepted = Parser.Feed(Request.Exchange.Input, ParserError);
            Request.Outcome->ParserErrorObserved = static_cast<bool>(ParserError);
        }
        if (ParserError)
        {
            Request.Outcome->ParserFailure = Fault::FromNative(ParserError);
        }
        auto Transport = std::make_shared<ScriptedGrpcTransmission>(
            Executor, std::move(Request.Exchange));
        if (Request.CaptureTransport)
            Request.Outcome->Transport = Transport;
        auto Client = std::make_shared<Gun::ClientSession>(Transport);
        auto Payload = std::move(Request.Payload);
        if (Payload.empty())
        {
            Payload.push_back(std::byte{0x61});
        }
        Request.Outcome->Result = co_await Client->Run(
            std::span<const std::byte>(Payload));
        Request.Outcome->DataPayloadBytesWritten =
            SummarizeHttp2Wire(Transport->Written()).DataPayloadBytes;
        const auto Written = SummarizeHttp2Wire(Transport->Written());
        Request.Outcome->AckWritten = Written.HasSettingsAck;
        Request.Outcome->DataEndStreamWritten = Written.HasDataEndStream;
        Request.Outcome->AckWriteFailureSeen = Transport->AckWriteFailureSeen();
        Request.Outcome->ReadCount = Transport->ReadCount();
        Request.Outcome->WriteCount = Transport->WriteCount();
        Request.Outcome->CloseCount = Transport->CloseCount();
    }

    auto DrainActivity(
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity,
        bool *DrainSucceeded,
        Fault::Failure *FinalDrainFailure) -> Net::awaitable<void>
    {
        const auto Drained = co_await Activity->Drain();
        *DrainSucceeded = static_cast<bool>(Drained);
        if (!Drained) *FinalDrainFailure = Drained.error();
    }

    auto RunCoroutine(Net::awaitable<void> Operation) -> void
    {
        Net::io_context Io;
        std::exception_ptr Exception;
        Net::co_spawn(Io, std::move(Operation),
            [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
        Io.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto ExpectFailure(
        const RunOutcome &Outcome,
        const Fault::Failure &Expected,
        const std::size_t ExpectedWrites) -> void
    {
        EXPECT_EQ(Outcome.Result.Terminal.Code, Expected.Code);
        EXPECT_EQ(Outcome.Result.Terminal.Native, Expected.Native);
        EXPECT_FALSE(Outcome.Result.CloseFailure.Failed());
        EXPECT_FALSE(Outcome.Result.DrainFailure.Failed());
        EXPECT_EQ(Outcome.ReadCount, 1U);
        EXPECT_EQ(Outcome.WriteCount, ExpectedWrites);
        EXPECT_EQ(Outcome.CloseCount, 1U);
    }

    TEST(GunClientTerminalPriority, CompleteMalformedFrameKeepsEof)
    {
        const Fault::Failure Eof{Fault::Code::Eof};
        RunOutcome Outcome;
        RunCoroutine(RunClient({{MakeMalformedSettingsFrame(), Eof, 0U, {}}, &Outcome}));
        EXPECT_FALSE(Outcome.ParserAccepted);
        EXPECT_TRUE(Outcome.ParserErrorObserved);
        ExpectFailure(Outcome, Outcome.ParserFailure, 1U);
        EXPECT_FALSE(Outcome.Result.Response.has_value());
    }

    TEST(GunClientTerminalPriority, CompleteMalformedFrameKeepsNativeReset)
    {
        const Fault::Failure Reset{
            Fault::Code::ConnectionReset,
            std::make_error_code(std::errc::connection_reset)};
        RunOutcome Outcome;
        RunCoroutine(RunClient({{MakeMalformedSettingsFrame(), Reset, 0U, {}}, &Outcome}));
        EXPECT_FALSE(Outcome.ParserAccepted);
        EXPECT_TRUE(Outcome.ParserErrorObserved);
        ExpectFailure(Outcome, Outcome.ParserFailure, 1U);
        EXPECT_FALSE(Outcome.Result.Response.has_value());
    }

    TEST(GunClientTerminalPriority, PartialFramePreservesEof)
    {
        const Fault::Failure Eof{Fault::Code::Eof};
        RunOutcome Outcome;
        RunCoroutine(RunClient({{MakePartialSettingsFrame(), Eof, 0U, {}}, &Outcome}));
        EXPECT_TRUE(Outcome.ParserAccepted);
        EXPECT_FALSE(Outcome.ParserErrorObserved);
        ExpectFailure(Outcome, Eof, 1U);
        EXPECT_FALSE(Outcome.Result.Response.has_value());
    }

    TEST(GunClientTerminalPriority, PartialFramePreservesNativeReset)
    {
        const Fault::Failure Reset{
            Fault::Code::ConnectionReset,
            std::make_error_code(std::errc::connection_reset)};
        RunOutcome Outcome;
        RunCoroutine(RunClient({{MakePartialSettingsFrame(), Reset, 0U, {}}, &Outcome}));
        EXPECT_TRUE(Outcome.ParserAccepted);
        EXPECT_FALSE(Outcome.ParserErrorObserved);
        ExpectFailure(Outcome, Reset, 1U);
        EXPECT_FALSE(Outcome.Result.Response.has_value());
    }

    TEST(GunClientTerminalPriority, CompleteResponsePrecedesEof)
    {
        constexpr std::array<std::byte, 4> Payload{
            std::byte{0x67}, std::byte{0x75}, std::byte{0x6e}, std::byte{0x21}};
        Net::io_context Io;
        const auto Message = Prism::Gun::Grpc::EncodeMessage(Payload);
        auto Input = MakeGrpcResponseWire(Io.get_executor(), Message);
        ASSERT_FALSE(Input.empty());
        const Fault::Failure Eof{Fault::Code::Eof};
        RunOutcome Outcome;
        RunCoroutine(RunClient({{std::move(Input), Eof, 0U, {}}, &Outcome}));

        EXPECT_TRUE(Outcome.ParserAccepted);
        EXPECT_FALSE(Outcome.ParserErrorObserved);
        ASSERT_TRUE(Outcome.Result.Response.has_value());
        EXPECT_EQ(Outcome.Result.Terminal.Code, Fault::Code::Eof);
        const auto &Response = *Outcome.Result.Response;
        ASSERT_FALSE(Response.ResponseHeaders.empty());
        EXPECT_EQ(Response.ResponseHeaders.front().Name, ":status");
        EXPECT_EQ(Response.ResponseHeaders.front().Value, "200");
        ASSERT_FALSE(Response.Trailers.empty());
        EXPECT_EQ(Response.Trailers.front().Name, "grpc-status");
        EXPECT_EQ(Response.Trailers.front().Value, "0");
        EXPECT_EQ(Response.Payload, std::vector<std::byte>(Payload.begin(), Payload.end()));
        EXPECT_EQ(Response.GrpcStatus, 0U);
        EXPECT_FALSE(Outcome.Result.CloseFailure.Failed());
        EXPECT_FALSE(Outcome.Result.DrainFailure.Failed());
        EXPECT_EQ(Outcome.ReadCount, 1U);
        EXPECT_EQ(Outcome.WriteCount, 2U);
        EXPECT_EQ(Outcome.CloseCount, 1U);
    }

    TEST(GunClientTerminalPriority, CompleteResponsePreservesNativeReset)
    {
        constexpr std::array<std::byte, 4> Payload{
            std::byte{0x67}, std::byte{0x75}, std::byte{0x6e}, std::byte{0x21}};
        Net::io_context Io;
        const auto Message = Prism::Gun::Grpc::EncodeMessage(Payload);
        auto Input = MakeGrpcResponseWire(Io.get_executor(), Message);
        ASSERT_FALSE(Input.empty());
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const Fault::Failure Reset = Fault::FromNative(Native);
        RunOutcome Outcome;
        RunCoroutine(RunClient({{std::move(Input), Reset, 0U, {}}, &Outcome}));

        EXPECT_TRUE(Outcome.ParserAccepted);
        EXPECT_FALSE(Outcome.ParserErrorObserved);
        ExpectFailure(Outcome, Reset, 2U);
        ASSERT_TRUE(Outcome.Result.Response.has_value());
        EXPECT_EQ(Outcome.Result.Response->GrpcStatus, 0U);
        EXPECT_EQ(Outcome.Result.Response->Payload, std::vector<std::byte>(Payload.begin(), Payload.end()));
    }

    TEST(GunClientTerminalPriority, CompleteMalformedGrpcMessagePrecedesEof)
    {
        Net::io_context Io;
        auto Input = MakeGrpcResponseWire(
            Io.get_executor(), {std::byte{0x01}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}});
        ASSERT_FALSE(Input.empty());
        const Fault::Failure Eof{Fault::Code::Eof};
        RunOutcome Outcome;
        RunCoroutine(RunClient({{std::move(Input), Eof, 0U, {}}, &Outcome}));

        EXPECT_TRUE(Outcome.ParserAccepted);
        EXPECT_FALSE(Outcome.ParserErrorObserved);
        EXPECT_EQ(Outcome.Result.Terminal.Code, Fault::Code::ProtocolError);
        EXPECT_FALSE(Outcome.Result.Terminal.Native);
        EXPECT_FALSE(Outcome.Result.Response.has_value());
        EXPECT_FALSE(Outcome.Result.CloseFailure.Failed());
        EXPECT_FALSE(Outcome.Result.DrainFailure.Failed());
        EXPECT_EQ(Outcome.ReadCount, 1U);
        EXPECT_EQ(Outcome.WriteCount, 2U);
        EXPECT_TRUE(Outcome.AckWritten);
        EXPECT_EQ(Outcome.CloseCount, 1U);
    }

    TEST(GunClientTerminalPriority, IncompleteGrpcMessagePrecedesNativeReset)
    {
        Net::io_context Io;
        auto Input = MakeGrpcResponseWire(
            Io.get_executor(), {std::byte{0}, std::byte{0}, std::byte{0}});
        ASSERT_FALSE(Input.empty());
        const Fault::Failure Reset{
            Fault::Code::ConnectionReset,
            std::make_error_code(std::errc::connection_reset)};
        RunOutcome Outcome;
        RunCoroutine(RunClient({{std::move(Input), Reset, 0U, {}}, &Outcome}));

        EXPECT_TRUE(Outcome.ParserAccepted);
        EXPECT_FALSE(Outcome.ParserErrorObserved);
        EXPECT_EQ(Outcome.Result.Terminal.Code, Fault::Code::ProtocolError);
        EXPECT_FALSE(Outcome.Result.Terminal.Native);
        EXPECT_FALSE(Outcome.Result.Response.has_value());
        EXPECT_FALSE(Outcome.Result.CloseFailure.Failed());
        EXPECT_FALSE(Outcome.Result.DrainFailure.Failed());
        EXPECT_EQ(Outcome.ReadCount, 1U);
        EXPECT_EQ(Outcome.CloseCount, 1U);
    }

    TEST(GunClientTerminalPriority, IncompleteGrpcMessagePrecedesAckWriteFailureAndEof)
    {
        Net::io_context Io;
        auto Input = MakeGrpcResponseWire(
            Io.get_executor(), {std::byte{0}, std::byte{0}, std::byte{0}});
        ASSERT_FALSE(Input.empty());
        const Fault::Failure Eof{Fault::Code::Eof};
        const Fault::Failure WriteFailure{
            Fault::Code::IoError,
            std::make_error_code(std::errc::broken_pipe)};
        RunOutcome Outcome;
        RunCoroutine(RunClient({
            {std::move(Input), Eof, 0U, WriteFailure, true},
            &Outcome}));

        EXPECT_TRUE(Outcome.ParserAccepted);
        EXPECT_FALSE(Outcome.ParserErrorObserved);
        EXPECT_FALSE(Outcome.Result.Response.has_value());
        EXPECT_EQ(Outcome.Result.Terminal.Code, Fault::Code::ProtocolError);
        EXPECT_FALSE(Outcome.Result.Terminal.Native);
        EXPECT_TRUE(Outcome.AckWriteFailureSeen);
        EXPECT_EQ(Outcome.ReadCount, 1U);
        EXPECT_EQ(Outcome.WriteCount, 2U);
        EXPECT_FALSE(Outcome.Result.CloseFailure.Failed());
        EXPECT_FALSE(Outcome.Result.DrainFailure.Failed());
        EXPECT_EQ(Outcome.CloseCount, 1U);
    }

    TEST(GunClientTerminalPriority, AckWriteFailurePrecedesEof)
    {
        const Fault::Failure Eof{Fault::Code::Eof};
        const Fault::Failure WriteFailure{
            Fault::Code::IoError,
            std::make_error_code(std::errc::broken_pipe)};
        RunOutcome Outcome;
        RunCoroutine(RunClient({{MakeSettingsFrame(), Eof, 2U, WriteFailure}, &Outcome}));
        EXPECT_TRUE(Outcome.ParserAccepted);
        EXPECT_FALSE(Outcome.ParserErrorObserved);
        ExpectFailure(Outcome, WriteFailure, 2U);
    }

    TEST(GunClientTerminalPriority, NativeResetPrecedesAckWriteFailure)
    {
        const Fault::Failure Reset{
            Fault::Code::ConnectionReset,
            std::make_error_code(std::errc::connection_reset)};
        const Fault::Failure WriteFailure{
            Fault::Code::IoError,
            std::make_error_code(std::errc::broken_pipe)};
        RunOutcome Outcome;
        RunCoroutine(RunClient({{MakeSettingsFrame(), Reset, 2U, WriteFailure}, &Outcome}));
        EXPECT_TRUE(Outcome.ParserAccepted);
        EXPECT_FALSE(Outcome.ParserErrorObserved);
        ExpectFailure(Outcome, Reset, 2U);
    }

    TEST(GunClientTerminalPriority, CompleteResponseEofPrecedesAckWriteFailureWhileRequestBlocked)
    {
        Net::io_context Io;
        std::vector<std::byte> RequestPayload(128U * 1024U, std::byte{0x61});
        const auto EncodedRequest = Prism::Gun::Grpc::EncodeMessage(
            std::span<const std::byte>(RequestPayload));
        ASSERT_GT(EncodedRequest.size(), 65535U);
        constexpr std::string_view ResponseText{"blocked-request-response"};
        const auto ResponsePayload = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(ResponseText.data()), ResponseText.size());
        auto Input = MakeGrpcResponseWire(
            Io.get_executor(), Prism::Gun::Grpc::EncodeMessage(ResponsePayload));
        ASSERT_FALSE(Input.empty());

        const Fault::Failure Eof{Fault::Code::Eof};
        const Fault::Failure WriteFailure{
            Fault::Code::IoError,
            std::make_error_code(std::errc::broken_pipe)};
        RunOutcome Outcome;
        RunCoroutine(RunClient({
            {std::move(Input), Eof, 0U, WriteFailure, true},
            &Outcome,
            std::move(RequestPayload)}));

        EXPECT_TRUE(Outcome.ParserAccepted);
        EXPECT_FALSE(Outcome.ParserErrorObserved);
        ASSERT_TRUE(Outcome.Result.Response.has_value());
        EXPECT_EQ(Outcome.Result.Terminal.Code, Fault::Code::Eof);
        EXPECT_FALSE(Outcome.Result.Terminal.Native);
        EXPECT_EQ(Outcome.Result.Response->GrpcStatus, 0U);
        EXPECT_EQ(Outcome.Result.Response->Payload,
                  std::vector<std::byte>(ResponsePayload.begin(), ResponsePayload.end()));
        EXPECT_TRUE(Outcome.AckWriteFailureSeen);
        EXPECT_GT(Outcome.DataPayloadBytesWritten, 0U);
        EXPECT_LT(Outcome.DataPayloadBytesWritten, EncodedRequest.size());
        EXPECT_EQ(Outcome.ReadCount, 1U);
        EXPECT_FALSE(Outcome.Result.CloseFailure.Failed());
        EXPECT_FALSE(Outcome.Result.DrainFailure.Failed());
        EXPECT_EQ(Outcome.CloseCount, 1U);
    }

    TEST(GunClientTerminalPriority, CompleteResponseEofStopsBlockedRequestAfterAckFlush)
    {
        Net::io_context Io;
        std::vector<std::byte> RequestPayload(128U * 1024U, std::byte{0x61});
        const auto EncodedRequest = Prism::Gun::Grpc::EncodeMessage(
            std::span<const std::byte>(RequestPayload));
        ASSERT_GT(EncodedRequest.size(), 65535U);
        constexpr std::string_view ResponseText{"blocked-request-response"};
        const auto ResponsePayload = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(ResponseText.data()), ResponseText.size());
        auto Input = MakeGrpcResponseWire(
            Io.get_executor(), Prism::Gun::Grpc::EncodeMessage(ResponsePayload));
        ASSERT_FALSE(Input.empty());

        const Fault::Failure Eof{Fault::Code::Eof};
        RunOutcome Outcome;
        RunCoroutine(RunClient({
            {std::move(Input), Eof, 0U, {}, false},
            &Outcome,
            std::move(RequestPayload)}));

        EXPECT_TRUE(Outcome.ParserAccepted);
        EXPECT_FALSE(Outcome.ParserErrorObserved);
        ASSERT_TRUE(Outcome.Result.Response.has_value());
        EXPECT_EQ(Outcome.Result.Terminal.Code, Fault::Code::Eof);
        EXPECT_FALSE(Outcome.Result.Terminal.Native);
        EXPECT_EQ(Outcome.Result.Response->GrpcStatus, 0U);
        EXPECT_EQ(Outcome.Result.Response->Payload,
                  std::vector<std::byte>(ResponsePayload.begin(), ResponsePayload.end()));
        EXPECT_TRUE(Outcome.AckWritten);
        EXPECT_FALSE(Outcome.AckWriteFailureSeen);
        EXPECT_GT(Outcome.DataPayloadBytesWritten, 0U);
        EXPECT_LT(Outcome.DataPayloadBytesWritten, EncodedRequest.size());
        EXPECT_FALSE(Outcome.DataEndStreamWritten);
        EXPECT_EQ(Outcome.ReadCount, 1U);
        EXPECT_FALSE(Outcome.Result.CloseFailure.Failed());
        EXPECT_FALSE(Outcome.Result.DrainFailure.Failed());
        EXPECT_EQ(Outcome.CloseCount, 1U);
    }

    TEST(GunClientTerminalPriority, DrainFailureRetainsCloseCauseUntilOwnerRetryRetires)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        constexpr std::string_view ResponseText{"drain-failure-response"};
        const auto ResponsePayload = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(ResponseText.data()), ResponseText.size());
        auto Input = MakeGrpcResponseWire(
            Context->Io.get_executor(), Prism::Gun::Grpc::EncodeMessage(ResponsePayload));
        ASSERT_FALSE(Input.empty());

        const Fault::Failure Eof{Fault::Code::Eof};
        const auto Native = std::make_error_code(std::errc::io_error);
        const auto CloseFailure = Fault::FromNative(Native);
        ScriptedExchange Exchange;
        Exchange.Input = std::move(Input);
        Exchange.ReadFailure = Eof;
        Exchange.CloseFailure = CloseFailure;
        Exchange.FailFirstClose = true;
        std::vector<std::byte> RequestPayload(128U * 1024U, std::byte{0x61});
        RunOutcome Outcome;
        std::exception_ptr Exception;

        Net::co_spawn(Context->Io,
            RunClient({std::move(Exchange), &Outcome, std::move(RequestPayload), true}),
            [&Exception, &Context](std::exception_ptr Failure)
            {
                Exception = std::move(Failure);
                // 首次 close 失败会故意保留可重试命令及其 IoActivity 预约；
                // 这是显式阶段边界，不是超时，后续由 Storage->Retry() 释放。
                Context->Io.stop();
            });
        Context->Io.run();

        const auto Transport = Outcome.Transport;
        const auto Activity = Transport ? Transport->Activity() : nullptr;
        ASSERT_TRUE(Transport);
        ASSERT_TRUE(Activity);
        // 首次 close 已失败，但可重试命令与其活动预约仍持有第一阶段；
        // 第二阶段的 Retry 尚未投递，此时底层 owner 必须保持打开。
        EXPECT_TRUE(Transport->IsOpen());
        EXPECT_FALSE(Activity->IsRetired());
        const auto RetainedBeforeRetry = Storage->Pending();
        EXPECT_GT(RetainedBeforeRetry, 0U);
        std::exception_ptr DrainException;
        bool DrainSucceeded = false;
        Fault::Failure FinalDrainFailure;
        Context->Io.restart();
        Storage->Retry();
        Net::co_spawn(Context->Io,
            DrainActivity(Activity, &DrainSucceeded, &FinalDrainFailure),
            [&DrainException](std::exception_ptr Failure)
            { DrainException = std::move(Failure); });
        Context->Io.run();
        Storage->Collect();

        EXPECT_FALSE(Exception);
        EXPECT_FALSE(DrainException);
        EXPECT_TRUE(Outcome.ParserAccepted);
        EXPECT_FALSE(Outcome.ParserErrorObserved);
        ASSERT_TRUE(Outcome.Result.Response.has_value());
        EXPECT_EQ(Outcome.Result.Terminal.Code, Fault::Code::Eof);
        EXPECT_EQ(Outcome.Result.Response->Payload,
                  std::vector<std::byte>(ResponsePayload.begin(), ResponsePayload.end()));
        EXPECT_FALSE(Outcome.Result.CloseFailure.Failed());
        EXPECT_EQ(Outcome.Result.DrainFailure.Code, CloseFailure.Code);
        EXPECT_EQ(Outcome.Result.DrainFailure.Native, Native);
        EXPECT_EQ(Outcome.CloseCount, 1U);
        EXPECT_TRUE(DrainSucceeded);
        EXPECT_FALSE(FinalDrainFailure.Failed());
        EXPECT_EQ(Transport->CloseCount(), 2U);
        EXPECT_FALSE(Transport->IsOpen());
        EXPECT_TRUE(Activity->IsRetired());
        Storage->Collect();
        EXPECT_LT(Storage->Pending(), RetainedBeforeRetry);
        EXPECT_EQ(Storage->Pending(), 0U);
    }
} // namespace
