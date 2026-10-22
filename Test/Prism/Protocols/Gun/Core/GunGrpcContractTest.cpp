/**
 * @file GunGrpcContractTest.cpp
 * @brief 标准 gRPC/HTTP2 Gun metadata、message 和 trailer contract。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Http2/Types.hpp>
#include <Prism/Protocols/Gun/Grpc.hpp>
#include <Prism/Protocols/Gun/Detail/GrpcSession.hpp>
#include <Prism/Protocols/Gun/Detail/GrpcStreamActivity.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/MemoryStream.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
    namespace H2 = Prism::Http2;
    namespace Grpc = Prism::Gun::Grpc;

    struct GrpcTransportCleanupOutcome final
    {
        std::optional<Prism::Fault::Failure> CloseFailure, DrainFailure;
        std::exception_ptr Exception;
    };

    struct GrpcClientRunOutcome final
    {
        std::optional<Prism::Gun::Grpc::ClientOutcome> Result;
        std::exception_ptr RunException;
        GrpcTransportCleanupOutcome Cleanup;
    };

    struct GrpcClientRunRequest final
    {
        Prism::SharedTransmission Transport;
        std::shared_ptr<Prism::Gun::Grpc::Detail::ClientSession> Client;
        std::string Payload;
        GrpcClientRunOutcome *Outcome;
    };

    /** @brief 等待 gRPC 传输 Activity 排空并记录失败。 */
    auto DrainGrpcTransport(Prism::SharedTransmission Transport,
        GrpcTransportCleanupOutcome &Outcome) -> boost::asio::awaitable<void>
    {
        const auto Activity = Transport->Activity();
        if (!Activity)
        {
            Outcome.DrainFailure = Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
            co_return;
        }
        try { const auto Drained = co_await Activity->Drain(); if (!Drained) Outcome.DrainFailure = Drained.error(); }
        catch (...) { if (!Outcome.Exception) Outcome.Exception = std::current_exception(); }
    }

    /** @brief 先同步请求关闭，再返回 Activity drain 协程。 */
    auto CloseAndDrainGrpcTransport(Prism::SharedTransmission Transport,
        GrpcTransportCleanupOutcome &Outcome) -> boost::asio::awaitable<void>
    {
        try { const auto Closed = Transport->Close(); if (!Closed) Outcome.CloseFailure = Closed.error(); }
        catch (...) { if (!Outcome.Exception) Outcome.Exception = std::current_exception(); }
        return DrainGrpcTransport(std::move(Transport), Outcome);
    }

    auto RunGrpcClient(GrpcClientRunRequest Request) -> boost::asio::awaitable<void>
    {
        try
        {
            Request.Outcome->Result = co_await Request.Client->Run(std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Request.Payload.data()),
                Request.Payload.size()));
        }
        catch (...)
        {
            Request.Outcome->RunException = std::current_exception();
        }
        if (Request.Outcome->RunException)
        {
            try
            {
                co_await CloseAndDrainGrpcTransport(
                    std::move(Request.Transport), Request.Outcome->Cleanup);
            }
            catch (...)
            {
                if (!Request.Outcome->Cleanup.Exception)
                    Request.Outcome->Cleanup.Exception = std::current_exception();
            }
        }
    }

    class NativeFailingTransmission final : public Prism::Transmission
    {
    public:
        NativeFailingTransmission(ExecutorType Executor, std::error_code Native)
            : Transmission(std::move(Executor)), Native_(Native)
        {
        }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler),
                {0, {Prism::Fault::Code::IoError, Native_}});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler),
                {0, {Prism::Fault::Code::IoError, Native_}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        std::error_code Native_;
    };

    class GrpcReadCompletionTransmission final : public Prism::Transmission
    {
    public:
        GrpcReadCompletionTransmission(
            ExecutorType Executor,
            std::vector<std::byte> Input,
            Prism::Fault::Failure ReadFailure)
            : Transmission(std::move(Executor)), Input_(std::move(Input)),
              ReadFailure_(ReadFailure)
        {
        }

        [[nodiscard]] auto Written() const noexcept -> const std::vector<std::byte> &
        {
            return Written_;
        }

        [[nodiscard]] auto ReadCount() const noexcept -> std::size_t
        {
            return ReadCount_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCount_;
            if (ReadDelivered_)
            {
                Prism::Transmission::PostResult(
                    Executor(), std::move(Handler),
                    {0, {Prism::Fault::Code::Eof}});
                return;
            }
            ReadDelivered_ = true;
            const auto Count = (std::min)(Buffer.size(), Input_.size());
            std::copy_n(Input_.begin(), Count, Buffer.begin());
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Count, ReadFailure_});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Written_.insert(Written_.end(), Buffer.begin(), Buffer.end());
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        std::vector<std::byte> Input_;
        std::vector<std::byte> Written_;
        Prism::Fault::Failure ReadFailure_;
        bool ReadDelivered_{false};
        bool Closed_{false};
        std::size_t ReadCount_{0};
    };

    [[nodiscard]] auto MakeGrpcRequestWire(
        boost::asio::io_context &IoContext,
        std::string_view Payload) -> std::vector<std::byte>
    {
        H2::Session Client(IoContext.get_executor(), false);
        const std::array<H2::SettingsEntry, 1> Settings{{
            {H2::SettingsMaxConcurrentStreams, 10}}};
        Client.SendSettings(Settings);
        const auto Stream = Client.OpenStream(
            Grpc::MakeRequestHeaders("/GunService/Tun", "gun"), false);
        if (!Stream)
        {
            return {};
        }
        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        const auto Message = Grpc::EncodeMessage(PayloadBytes);
        if (Client.SubmitData(
                *Stream, std::span<const std::byte>(Message), true) !=
            H2::SubmitDataStatus::Accepted)
        {
            return {};
        }
        std::vector<std::byte> Wire;
        if (!Client.Collect(Wire))
        {
            return {};
        }
        return Wire;
    }

    [[nodiscard]] auto MakeGrpcResponseWire(
        boost::asio::io_context &IoContext,
        std::string_view Payload) -> std::optional<std::vector<std::byte>>
    {
        H2::Session Server(IoContext.get_executor(), true);
        const auto Request = MakeGrpcRequestWire(IoContext, {});
        std::error_code Error;
        if (!Server.Feed(std::span<const std::byte>(Request), Error) || Error)
        {
            return std::nullopt;
        }
        Server.SendSettings();
        const auto Headers = Server.SubmitHeaders(
            1, {{":status", "200"}, {"content-type", "application/grpc"}}, false);
        const auto Message = Grpc::EncodeMessage(std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
        if (!Headers || Server.SubmitData(
                1, std::span<const std::byte>(Message), false) != H2::SubmitDataStatus::Accepted ||
            !Server.SubmitHeaders(1, Grpc::MakeResponseTrailers(0), true))
        {
            return std::nullopt;
        }
        std::vector<std::byte> Wire;
        if (!Server.Collect(Wire))
        {
            return std::nullopt;
        }
        return Wire;
    }

    [[nodiscard]] auto CountHttp2FrameType(
        const std::vector<std::byte> &Wire,
        const std::uint8_t Type) -> std::size_t
    {
        std::size_t Count = 0;
        std::size_t Offset = !Wire.empty() && std::to_integer<char>(Wire.front()) == 'P' ? 24U : 0U;
        if (Offset > Wire.size())
        {
            return 0;
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
            if (std::to_integer<std::uint8_t>(Wire[Offset + 3U]) == Type)
            {
                ++Count;
            }
            Offset += 9U + Length;
        }
        return Count;
    }

    [[nodiscard]] auto HasSettingsAck(const std::vector<std::byte> &Wire) -> bool
    {
        constexpr std::array Ack{
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{4}, std::byte{1},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}};
        return std::search(Wire.begin(), Wire.end(), Ack.begin(), Ack.end()) != Wire.end();
    }

    auto CaptureServerSessionResult(
        std::shared_ptr<Prism::Gun::Grpc::Detail::ServerSession> Server,
        std::optional<Prism::Fault::Failure> *Result) -> boost::asio::awaitable<void>
    {
        Result->emplace(co_await Server->Run());
    }

    struct GrpcServerRunState final
    {
        std::shared_ptr<Prism::Gun::Grpc::Detail::ServerSession> Server;
        std::shared_ptr<Prism::MemoryStream> Transport;
        std::optional<Prism::Fault::Failure> RunResult;
        std::exception_ptr RunException;
        GrpcTransportCleanupOutcome Cleanup;
    };

    auto RunGrpcServer(std::shared_ptr<GrpcServerRunState> State) -> boost::asio::awaitable<void>
    {
        try { State->RunResult.emplace(co_await State->Server->Run()); }
        catch (...) { State->RunException = std::current_exception(); }
        try { co_await CloseAndDrainGrpcTransport(State->Transport, State->Cleanup); }
        catch (...) { if (!State->Cleanup.Exception) State->Cleanup.Exception = std::current_exception(); }
    }

    auto CaptureMissingStreamAccept(
        std::optional<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>> *Result)
        -> boost::asio::awaitable<void>
    {
        Result->emplace(co_await Prism::Gun::Grpc::StreamTransport::Accept(
            {}, Prism::Gun::Grpc::Config{}));
    }

    auto DrainGrpcStreamActivity(
        std::shared_ptr<Prism::Gun::Grpc::Detail::GrpcStreamActivity> Activity,
        std::expected<void, Prism::Fault::Failure> *Result) -> boost::asio::awaitable<void>
    {
        *Result = co_await Activity->Drain();
    }

    auto RunServerSession(
        boost::asio::io_context &Io,
        const std::shared_ptr<Prism::Gun::Grpc::Detail::ServerSession> &Server,
        std::optional<Prism::Fault::Failure> &Result) -> void
    {
        std::exception_ptr Exception;
        boost::asio::co_spawn(
            Io,
            CaptureServerSessionResult(Server, &Result),
            [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
        Io.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }
}

TEST(GunGrpcContract, ValidatesUnaryRequestHeaders)
{
    const auto Headers = Prism::Gun::Grpc::MakeRequestHeaders(
        "/GunService/Tun", "edge.example");

    const auto Request = Prism::Gun::Grpc::ParseRequestHeaders(Headers);

    ASSERT_TRUE(Request.has_value());
    EXPECT_EQ(Request->Path, "/GunService/Tun");
    EXPECT_EQ(Request->Authority, "edge.example");
    EXPECT_EQ(Request->ContentType, "application/grpc");
    EXPECT_EQ(Request->Te, "trailers");
}

TEST(GunGrpcContract, DecodesFragmentedGrpcMessage)
{
    constexpr std::string_view Payload{"gun-grpc-payload"};
    const auto Wire = Prism::Gun::Grpc::EncodeMessage(
        std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
    Prism::Gun::Grpc::MessageDecoder Decoder;
    std::vector<std::vector<std::byte>> Messages;

    ASSERT_TRUE(Decoder.Feed(std::span<const std::byte>(Wire).first(3), Messages));
    ASSERT_TRUE(Decoder.Feed(std::span<const std::byte>(Wire).subspan(3), Messages));
    ASSERT_EQ(Messages.size(), 1U);
    EXPECT_EQ(Messages.front().size(), Payload.size());
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Messages.front().data()),
                               Messages.front().size()),
              Payload);
}

TEST(GunGrpcContract, AcceptsGrpcGoHeadersWithoutTeTrailerHint)
{
    auto Headers = Prism::Gun::Grpc::MakeRequestHeaders(
        "/GunService/Tun", "edge.example");
    Headers.erase(std::remove_if(Headers.begin(), Headers.end(),
                                 [](const auto &Header) { return Header.Name == "te"; }),
                  Headers.end());

    const auto Request = Prism::Gun::Grpc::ParseRequestHeaders(Headers);

    ASSERT_TRUE(Request.has_value());
    EXPECT_TRUE(Request->Te.empty());
}

TEST(GunGrpcContract, BuildsSuccessfulTrailers)
{
    const auto Headers = Prism::Gun::Grpc::MakeResponseTrailers(0);

    ASSERT_EQ(Headers.size(), 2U);
    EXPECT_EQ(Headers[0].Name, "grpc-status");
    EXPECT_EQ(Headers[0].Value, "0");
    EXPECT_EQ(Headers[1].Name, "grpc-message");
    EXPECT_TRUE(Headers[1].Value.empty());
}

TEST(GunGrpcContract, WrapsAndUnwrapsTunMessageEnvelope)
{
    constexpr std::string_view Payload{"vless-over-mihomo-gun"};
    const auto Wire = Prism::Gun::Grpc::EncodeTunMessage(
        std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                   Payload.size()));
    const auto Decoded = Prism::Gun::Grpc::DecodeTunMessage(Wire);

    ASSERT_TRUE(Decoded.has_value());
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Decoded->data()),
                               Decoded->size()),
              Payload);
}

TEST(GunGrpcContract, RoundTripsUnaryMessageAndGrpcStatus)
{
    boost::asio::io_context Io;
    auto [ClientPipe, ServerPipe] = Prism::MakeMemoryPair(Io.get_executor());
    auto ClientTransport = std::make_shared<Prism::MemoryStream>(std::move(ClientPipe));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerPipe));
    auto Server = std::make_shared<Prism::Gun::Grpc::Detail::ServerSession>(
        ServerTransport, Prism::Gun::Grpc::Config{},
        [](std::span<const std::byte> Payload)
        { return std::vector<std::byte>(Payload.begin(), Payload.end()); });
    auto Client = std::make_shared<Prism::Gun::Grpc::Detail::ClientSession>(ClientTransport);

    constexpr std::string_view Payload{"grpc-unary-echo"};
    GrpcClientRunOutcome ClientOutcome;
    auto ServerRun = std::make_shared<GrpcServerRunState>(GrpcServerRunState{Server, ServerTransport});
    std::exception_ptr ServerTaskFailure;
    boost::asio::co_spawn(
        Io,
        RunGrpcServer(ServerRun),
        [&ServerTaskFailure](std::exception_ptr Error)
        { ServerTaskFailure = std::move(Error); });
    boost::asio::co_spawn(
        Io,
        RunGrpcClient(GrpcClientRunRequest{
            ClientTransport, Client, std::string(Payload), &ClientOutcome}),
        boost::asio::detached);
    Io.run();

    EXPECT_FALSE(ClientOutcome.Cleanup.Exception);
    EXPECT_FALSE(ClientOutcome.Cleanup.CloseFailure.has_value());
    EXPECT_FALSE(ClientOutcome.Cleanup.DrainFailure.has_value());
    ASSERT_FALSE(ClientOutcome.RunException);
    EXPECT_FALSE(ServerTaskFailure);
    EXPECT_FALSE(ServerRun->RunException);
    EXPECT_TRUE(ServerRun->RunResult.has_value());
    EXPECT_TRUE(ServerRun->RunResult && ServerRun->RunResult->Succeeded());
    EXPECT_FALSE(ServerRun->Cleanup.CloseFailure.has_value());
    EXPECT_FALSE(ServerRun->Cleanup.DrainFailure.has_value());
    EXPECT_FALSE(ServerRun->Cleanup.Exception);
    ASSERT_TRUE(ClientOutcome.Result.has_value());
    ASSERT_TRUE(ClientOutcome.Result->Response.has_value());
    EXPECT_TRUE(ClientOutcome.Result->Terminal.Succeeded());
    EXPECT_FALSE(ClientOutcome.Result->CloseFailure.Failed());
    EXPECT_FALSE(ClientOutcome.Result->DrainFailure.Failed());
    const auto &Response = *ClientOutcome.Result->Response;
    EXPECT_EQ(Response.GrpcStatus, 0U);
    ASSERT_EQ(Response.Payload.size(), Payload.size());
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Response.Payload.data()),
                               Response.Payload.size()),
              Payload);
}

TEST(GunGrpcContract, RejectsMissingStreamOwnerWithTypedFailure)
{
    boost::asio::io_context Io;
    std::optional<std::expected<
        Prism::SharedTransmission,
        Prism::Fault::Failure>> Result;

    boost::asio::co_spawn(
        Io, CaptureMissingStreamAccept(&Result), boost::asio::detached);
    Io.run();

    ASSERT_TRUE(Result.has_value());
    ASSERT_FALSE(Result->has_value());
    EXPECT_EQ(Result->error().Code, Prism::Fault::Code::InvalidArgument);
    EXPECT_FALSE(Result->error().Native);
}

TEST(GunGrpcContract, ClientRunPreservesNativeFailure)
{
    boost::asio::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    auto Transport = std::make_shared<NativeFailingTransmission>(Io.get_executor(), Native);
    auto Client = std::make_shared<Prism::Gun::Grpc::Detail::ClientSession>(Transport);
    constexpr std::string_view Payload{"grpc-native-failure"};
    GrpcClientRunOutcome ClientOutcome;

    boost::asio::co_spawn(
        Io,
        RunGrpcClient(GrpcClientRunRequest{
            Transport, Client, std::string(Payload), &ClientOutcome}),
        boost::asio::detached);
    Io.run();

    ASSERT_FALSE(ClientOutcome.RunException);
    ASSERT_TRUE(ClientOutcome.Result.has_value());
    EXPECT_FALSE(ClientOutcome.Result->Response.has_value());
    EXPECT_EQ(ClientOutcome.Result->Terminal.Native, Native);
    EXPECT_FALSE(ClientOutcome.Result->CloseFailure.Failed());
    EXPECT_FALSE(ClientOutcome.Result->DrainFailure.Failed());
}

TEST(GunGrpcContract, ClientConsumesCompleteGrpcFramesBeforeEof)
{
    boost::asio::io_context Io;
    const auto ResponseWire = MakeGrpcResponseWire(Io, "grpc-response-body");
    ASSERT_TRUE(ResponseWire.has_value());
    auto Transport = std::make_shared<GrpcReadCompletionTransmission>(
        Io.get_executor(), *ResponseWire, Prism::Fault::Failure{Prism::Fault::Code::Eof});
    auto Client = std::make_shared<Prism::Gun::Grpc::Detail::ClientSession>(Transport);
    GrpcClientRunOutcome ClientOutcome;

    boost::asio::co_spawn(
        Io,
        RunGrpcClient(GrpcClientRunRequest{
            Transport, Client, "grpc-request", &ClientOutcome}),
        boost::asio::detached);
    Io.run();

    ASSERT_FALSE(ClientOutcome.RunException);
    ASSERT_TRUE(ClientOutcome.Result.has_value());
    ASSERT_TRUE(ClientOutcome.Result->Response.has_value());
    EXPECT_EQ(ClientOutcome.Result->Terminal.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(ClientOutcome.Result->Response->GrpcStatus, 0U);
    EXPECT_EQ(std::string_view(
        reinterpret_cast<const char *>(ClientOutcome.Result->Response->Payload.data()),
        ClientOutcome.Result->Response->Payload.size()), "grpc-response-body");
    EXPECT_FALSE(ClientOutcome.Result->CloseFailure.Failed());
    EXPECT_FALSE(ClientOutcome.Result->DrainFailure.Failed());
    EXPECT_EQ(Transport->ReadCount(), 1U);
    EXPECT_TRUE(HasSettingsAck(Transport->Written()));
    EXPECT_EQ(CountHttp2FrameType(Transport->Written(), 8U), 2U);
}

TEST(GunGrpcContract, ClientConsumesCompleteGrpcFramesBeforeNativeFailure)
{
    boost::asio::io_context Io;
    const auto ResponseWire = MakeGrpcResponseWire(Io, "grpc-response-body");
    ASSERT_TRUE(ResponseWire.has_value());
    const auto Native = std::make_error_code(std::errc::connection_reset);
    auto Transport = std::make_shared<GrpcReadCompletionTransmission>(
        Io.get_executor(), *ResponseWire,
        Prism::Fault::Failure{Prism::Fault::Code::IoError, Native});
    auto Client = std::make_shared<Prism::Gun::Grpc::Detail::ClientSession>(Transport);
    GrpcClientRunOutcome ClientOutcome;

    boost::asio::co_spawn(
        Io,
        RunGrpcClient(GrpcClientRunRequest{
            Transport, Client, "grpc-request", &ClientOutcome}),
        boost::asio::detached);
    Io.run();

    ASSERT_FALSE(ClientOutcome.RunException);
    ASSERT_TRUE(ClientOutcome.Result.has_value());
    ASSERT_TRUE(ClientOutcome.Result->Response.has_value());
    EXPECT_EQ(ClientOutcome.Result->Terminal.Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(ClientOutcome.Result->Terminal.Native, Native);
    EXPECT_EQ(std::string_view(
        reinterpret_cast<const char *>(ClientOutcome.Result->Response->Payload.data()),
        ClientOutcome.Result->Response->Payload.size()), "grpc-response-body");
    EXPECT_FALSE(ClientOutcome.Result->CloseFailure.Failed());
    EXPECT_FALSE(ClientOutcome.Result->DrainFailure.Failed());
    EXPECT_EQ(Transport->ReadCount(), 1U);
    EXPECT_TRUE(HasSettingsAck(Transport->Written()));
    EXPECT_EQ(CountHttp2FrameType(Transport->Written(), 8U), 2U);
}

TEST(GunGrpcContract, ClientPreservesEofAfterPartialResponseFrame)
{
    boost::asio::io_context Io;
    const auto ResponseWire = MakeGrpcResponseWire(Io, "grpc-response-body");
    ASSERT_TRUE(ResponseWire.has_value());
    std::vector<std::byte> PartialWire(ResponseWire->begin(), ResponseWire->begin() + 4);
    auto Transport = std::make_shared<GrpcReadCompletionTransmission>(
        Io.get_executor(), std::move(PartialWire),
        Prism::Fault::Failure{Prism::Fault::Code::Eof});
    auto Client = std::make_shared<Prism::Gun::Grpc::Detail::ClientSession>(Transport);
    GrpcClientRunOutcome ClientOutcome;

    boost::asio::co_spawn(
        Io,
        RunGrpcClient(GrpcClientRunRequest{
            Transport, Client, "grpc-request", &ClientOutcome}),
        boost::asio::detached);
    Io.run();

    ASSERT_FALSE(ClientOutcome.RunException);
    ASSERT_TRUE(ClientOutcome.Result.has_value());
    EXPECT_FALSE(ClientOutcome.Result->Response.has_value());
    EXPECT_EQ(ClientOutcome.Result->Terminal.Code, Prism::Fault::Code::Eof);
    EXPECT_FALSE(ClientOutcome.Result->CloseFailure.Failed());
    EXPECT_FALSE(ClientOutcome.Result->DrainFailure.Failed());
    EXPECT_EQ(Transport->ReadCount(), 1U);
    EXPECT_FALSE(HasSettingsAck(Transport->Written()));
    EXPECT_EQ(CountHttp2FrameType(Transport->Written(), 8U), 0U);
}

namespace
{
    class GunActivityProbe final : public Prism::Contract::CarrierActivity
    {
    public:
        explicit GunActivityProbe(boost::asio::any_io_executor Executor)
            : Executor_(std::move(Executor))
        {
        }

        auto Seal() noexcept -> void override { Sealed_ = true; }
        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override
        { return Executor_; }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return Retired_; }
        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            if (!Sealed_)
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            Retired_ = true;
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

    private:
        boost::asio::any_io_executor Executor_;
        bool Sealed_{false};
        bool Retired_{false};
    };

    class GunCloseReceiptProbe final : public Prism::Contract::CarrierCloseReceipt
    {
    public:
        auto ConfirmExternalClose() noexcept -> void override { Confirmed = true; }
        auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        bool Confirmed{false};
    };
}

TEST(GunGrpcContract, StreamActivityReportsNativeFailureAfterDriverRetirement)
{
    boost::asio::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const auto Failure = Prism::Fault::FromNative(Native);
    auto Front = std::make_shared<GunActivityProbe>(Io.get_executor());
    auto Child = std::make_shared<GunActivityProbe>(Io.get_executor());
    auto Receipt = std::make_shared<GunCloseReceiptProbe>();
    auto Activity = std::make_shared<Prism::Gun::Grpc::Detail::GrpcStreamActivity>(
        Io.get_executor(), Prism::Gun::Grpc::Detail::GrpcStreamActivityLayers{
            Front, Child, Receipt});
    ASSERT_TRUE(Activity->StartDriver());
    Activity->CompleteDriver(Failure);
    std::expected<void, Prism::Fault::Failure> DrainResult;
    std::exception_ptr Exception;

    boost::asio::co_spawn(
        Io,
        DrainGrpcStreamActivity(Activity, &DrainResult),
        [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
    Io.run();

    ASSERT_FALSE(Exception);
    ASSERT_FALSE(DrainResult);
    EXPECT_EQ(DrainResult.error().Native, Native);
    EXPECT_TRUE(Activity->IsRetired());
    EXPECT_TRUE(Receipt->Confirmed);
}

TEST(GunGrpcContract, ServerConsumesCompleteRequestBeforeEof)
{
    boost::asio::io_context Io;
    constexpr std::string_view Payload{"grpc-complete-before-eof"};
    const auto Input = MakeGrpcRequestWire(Io, Payload);
    ASSERT_FALSE(Input.empty());

    auto Transport = std::make_shared<GrpcReadCompletionTransmission>(
        Io.get_executor(), Input, Prism::Fault::Failure{Prism::Fault::Code::Eof});
    std::size_t HandledBytes = 0;
    auto Server = std::make_shared<Grpc::Detail::ServerSession>(
        Transport, Grpc::Config{},
        [&HandledBytes](const std::span<const std::byte> Message)
        {
            HandledBytes += Message.size();
            return std::vector<std::byte>(Message.begin(), Message.end());
        });
    std::optional<Prism::Fault::Failure> Result;

    RunServerSession(Io, Server, Result);

    ASSERT_TRUE(Result.has_value());
    EXPECT_TRUE(Result->Succeeded());
    EXPECT_EQ(HandledBytes, Payload.size());
    EXPECT_TRUE(HasSettingsAck(Transport->Written()));
}

TEST(GunGrpcContract, ServerRejectsIncompleteRequestBeforeEof)
{
    boost::asio::io_context Io;
    constexpr std::string_view Payload{"grpc-incomplete-before-eof"};
    auto Input = MakeGrpcRequestWire(Io, Payload);
    ASSERT_GT(Input.size(), 1U);
    Input.pop_back();

    auto Transport = std::make_shared<GrpcReadCompletionTransmission>(
        Io.get_executor(), std::move(Input),
        Prism::Fault::Failure{Prism::Fault::Code::Eof});
    std::size_t HandledBytes = 0;
    auto Server = std::make_shared<Grpc::Detail::ServerSession>(
        Transport, Grpc::Config{},
        [&HandledBytes](const std::span<const std::byte> Message)
        {
            HandledBytes += Message.size();
            return std::vector<std::byte>(Message.begin(), Message.end());
        });
    std::optional<Prism::Fault::Failure> Result;

    RunServerSession(Io, Server, Result);

    ASSERT_TRUE(Result.has_value());
    EXPECT_EQ(Result->Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(HandledBytes, 0U);
}

TEST(GunGrpcContract, ServerPreservesNativeReadFailureAfterCompleteRequest)
{
    boost::asio::io_context Io;
    constexpr std::string_view Payload{"grpc-native-after-request"};
    const auto Input = MakeGrpcRequestWire(Io, Payload);
    ASSERT_FALSE(Input.empty());
    const auto Native = std::make_error_code(std::errc::connection_reset);

    auto Transport = std::make_shared<GrpcReadCompletionTransmission>(
        Io.get_executor(), Input, Prism::Fault::FromNative(Native));
    std::size_t HandledBytes = 0;
    auto Server = std::make_shared<Grpc::Detail::ServerSession>(
        Transport, Grpc::Config{},
        [&HandledBytes](const std::span<const std::byte> Message)
        {
            HandledBytes += Message.size();
            return std::vector<std::byte>(Message.begin(), Message.end());
        });
    std::optional<Prism::Fault::Failure> Result;

    RunServerSession(Io, Server, Result);

    ASSERT_TRUE(Result.has_value());
    EXPECT_EQ(Result->Native, Native);
    EXPECT_EQ(HandledBytes, Payload.size());
}
