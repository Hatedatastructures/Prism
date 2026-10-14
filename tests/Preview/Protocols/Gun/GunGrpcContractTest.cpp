/**
 * @file GunGrpcContractTest.cpp
 * @brief 标准 gRPC/HTTP2 Gun metadata、message 和 trailer contract。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <Preview/Protocols/Gun/Grpc.hpp>
#include <Preview/Protocols/Gun/Detail/GrpcSession.hpp>
#include <Preview/Protocols/Gun/Detail/GrpcStreamActivity.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <Preview/Transport/MemoryStream.hpp>

#include <algorithm>
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
    struct GrpcClientRunRequest final
    {
        std::shared_ptr<Preview::Gun::Grpc::Detail::ClientSession> Client;
        std::string Payload;
        std::optional<Preview::Gun::Grpc::ClientResult> *Result;
        std::exception_ptr *Failure;
        boost::asio::io_context *Io;
    };

    /**
     * @brief 驱动 gRPC 客户端 unary Run 并传播异常结果。
     * @param Request 客户端、拥有型 payload 和结果输出。
     */
    auto RunGrpcClient(GrpcClientRunRequest Request)
        -> boost::asio::awaitable<void>
    {
        try
        {
            *Request.Result = co_await Request.Client->Run(std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Request.Payload.data()),
                Request.Payload.size()));
        }
        catch (...)
        {
            *Request.Failure = std::current_exception();
        }
        Request.Io->stop();
    }

    class NativeFailingTransmission final : public Preview::Transmission
    {
    public:
        NativeFailingTransmission(ExecutorType Executor, std::error_code Native)
            : Transmission(std::move(Executor)), Native_(Native)
        {
        }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
                Executor(), std::move(Handler),
                {0, {Preview::Fault::Code::IoError, Native_}});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
                Executor(), std::move(Handler),
                {0, {Preview::Fault::Code::IoError, Native_}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
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
}

TEST(GunGrpcContract, ValidatesUnaryRequestHeaders)
{
    const auto Headers = Preview::Gun::Grpc::MakeRequestHeaders(
        "/GunService/Tun", "edge.example");

    const auto Request = Preview::Gun::Grpc::ParseRequestHeaders(Headers);

    ASSERT_TRUE(Request.has_value());
    EXPECT_EQ(Request->Path, "/GunService/Tun");
    EXPECT_EQ(Request->Authority, "edge.example");
    EXPECT_EQ(Request->ContentType, "application/grpc");
    EXPECT_EQ(Request->Te, "trailers");
}

TEST(GunGrpcContract, DecodesFragmentedGrpcMessage)
{
    constexpr std::string_view Payload{"gun-grpc-payload"};
    const auto Wire = Preview::Gun::Grpc::EncodeMessage(
        std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
    Preview::Gun::Grpc::MessageDecoder Decoder;
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
    auto Headers = Preview::Gun::Grpc::MakeRequestHeaders(
        "/GunService/Tun", "edge.example");
    Headers.erase(std::remove_if(Headers.begin(), Headers.end(),
                                 [](const auto &Header) { return Header.Name == "te"; }),
                  Headers.end());

    const auto Request = Preview::Gun::Grpc::ParseRequestHeaders(Headers);

    ASSERT_TRUE(Request.has_value());
    EXPECT_TRUE(Request->Te.empty());
}

TEST(GunGrpcContract, BuildsSuccessfulTrailers)
{
    const auto Headers = Preview::Gun::Grpc::MakeResponseTrailers(0);

    ASSERT_EQ(Headers.size(), 2U);
    EXPECT_EQ(Headers[0].Name, "grpc-status");
    EXPECT_EQ(Headers[0].Value, "0");
    EXPECT_EQ(Headers[1].Name, "grpc-message");
    EXPECT_TRUE(Headers[1].Value.empty());
}

TEST(GunGrpcContract, WrapsAndUnwrapsTunMessageEnvelope)
{
    constexpr std::string_view Payload{"vless-over-mihomo-gun"};
    const auto Wire = Preview::Gun::Grpc::EncodeTunMessage(
        std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                   Payload.size()));
    const auto Decoded = Preview::Gun::Grpc::DecodeTunMessage(Wire);

    ASSERT_TRUE(Decoded.has_value());
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Decoded->data()),
                               Decoded->size()),
              Payload);
}

TEST(GunGrpcContract, RoundTripsUnaryMessageAndGrpcStatus)
{
    boost::asio::io_context Io;
    auto [ClientPipe, ServerPipe] = Preview::MakeMemoryPair(Io.get_executor());
    auto ClientTransport = std::make_shared<Preview::MemoryStream>(std::move(ClientPipe));
    auto ServerTransport = std::make_shared<Preview::MemoryStream>(std::move(ServerPipe));
    auto Server = std::make_shared<Preview::Gun::Grpc::Detail::ServerSession>(
        ServerTransport, Preview::Gun::Grpc::Config{},
        [](std::span<const std::byte> Payload)
        { return std::vector<std::byte>(Payload.begin(), Payload.end()); });
    auto Client = std::make_shared<Preview::Gun::Grpc::Detail::ClientSession>(ClientTransport);

    constexpr std::string_view Payload{"grpc-unary-echo"};
    std::optional<Preview::Gun::Grpc::ClientResult> Result;
    std::exception_ptr Failure;
    boost::asio::co_spawn(
        Io,
        [Server]() -> boost::asio::awaitable<void>
        {
            (void)co_await Server->Run();
        },
        boost::asio::detached);
    boost::asio::co_spawn(
        Io,
        RunGrpcClient(GrpcClientRunRequest{
            Client, std::string(Payload), &Result, &Failure, &Io}),
        boost::asio::detached);
    Io.run();

    ASSERT_FALSE(Failure);
    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(*Result);
    const auto &Response = **Result;
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
        Preview::SharedTransmission,
        Preview::Fault::Failure>> Result;
    auto Accept = [&Result]() -> boost::asio::awaitable<void>
    {
        Result.emplace(co_await Preview::Gun::Grpc::StreamTransport::Accept(
            {}, Preview::Gun::Grpc::Config{}));
    };

    boost::asio::co_spawn(Io, Accept(), boost::asio::detached);
    Io.run();

    ASSERT_TRUE(Result.has_value());
    ASSERT_FALSE(Result->has_value());
    EXPECT_EQ(Result->error().Code, Preview::Fault::Code::InvalidArgument);
    EXPECT_FALSE(Result->error().Native);
}

TEST(GunGrpcContract, ClientRunPreservesNativeFailure)
{
    boost::asio::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    auto Transport = std::make_shared<NativeFailingTransmission>(Io.get_executor(), Native);
    auto Client = std::make_shared<Preview::Gun::Grpc::Detail::ClientSession>(Transport);
    constexpr std::string_view Payload{"grpc-native-failure"};
    std::optional<Preview::Gun::Grpc::ClientResult> Result;
    std::exception_ptr Failure;

    boost::asio::co_spawn(
        Io,
        RunGrpcClient(GrpcClientRunRequest{
            Client, std::string(Payload), &Result, &Failure, &Io}),
        boost::asio::detached);
    Io.run();

    ASSERT_FALSE(Failure);
    ASSERT_TRUE(Result.has_value());
    ASSERT_FALSE(*Result);
    EXPECT_EQ(Result->error().Native, Native);
}

namespace
{
    class GunActivityProbe final : public Preview::Contract::CarrierActivity
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
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            if (!Sealed_)
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            Retired_ = true;
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

    private:
        boost::asio::any_io_executor Executor_;
        bool Sealed_{false};
        bool Retired_{false};
    };

    class GunCloseReceiptProbe final : public Preview::Contract::CarrierCloseReceipt
    {
    public:
        auto ConfirmExternalClose() noexcept -> void override { Confirmed = true; }
        bool Confirmed{false};
    };
}

TEST(GunGrpcContract, StreamActivityReportsNativeFailureAfterDriverRetirement)
{
    boost::asio::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const auto Failure = Preview::Fault::FromNative(Native);
    auto Front = std::make_shared<GunActivityProbe>(Io.get_executor());
    auto Child = std::make_shared<GunActivityProbe>(Io.get_executor());
    auto Receipt = std::make_shared<GunCloseReceiptProbe>();
    auto Activity = std::make_shared<Preview::Gun::Grpc::Detail::GrpcStreamActivity>(
        Io.get_executor(), Preview::Gun::Grpc::Detail::GrpcStreamActivityLayers{
            Front, Child, Receipt});
    ASSERT_TRUE(Activity->StartDriver());
    Activity->CompleteDriver(Failure);
    std::expected<void, Preview::Fault::Failure> DrainResult;
    std::exception_ptr Exception;

    boost::asio::co_spawn(
        Io,
        [&]() -> boost::asio::awaitable<void>
        {
            DrainResult = co_await Activity->Drain();
        }(),
        [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
    Io.run();

    ASSERT_FALSE(Exception);
    ASSERT_FALSE(DrainResult);
    EXPECT_EQ(DrainResult.error().Native, Native);
    EXPECT_TRUE(Activity->IsRetired());
    EXPECT_TRUE(Receipt->Confirmed);
}
