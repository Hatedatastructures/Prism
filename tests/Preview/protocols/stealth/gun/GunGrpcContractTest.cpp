/**
 * @file GunGrpcContractTest.cpp
 * @brief 标准 gRPC/HTTP2 Gun metadata、message 和 trailer contract。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <Preview/Protocols/Gun/Grpc.hpp>
#include <Preview/Transport/MemoryStream.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

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

TEST(GunGrpcContract, BuildsSuccessfulTrailers)
{
    const auto Headers = Preview::Gun::Grpc::MakeResponseTrailers(0);

    ASSERT_EQ(Headers.size(), 2U);
    EXPECT_EQ(Headers[0].Name, "grpc-status");
    EXPECT_EQ(Headers[0].value, "0");
    EXPECT_EQ(Headers[1].Name, "grpc-message");
    EXPECT_TRUE(Headers[1].value.empty());
}

TEST(GunGrpcContract, RoundTripsUnaryMessageAndGrpcStatus)
{
    boost::asio::io_context Io;
    auto [ClientPipe, ServerPipe] = Preview::MakeMemoryPair(Io.get_executor());
    auto ClientTransport = std::make_shared<Preview::MemoryStream>(std::move(ClientPipe));
    auto ServerTransport = std::make_shared<Preview::MemoryStream>(std::move(ServerPipe));
    auto Server = std::make_shared<Preview::Gun::Grpc::ServerSession>(
        ServerTransport, Preview::Gun::Grpc::Config{},
        [](std::span<const std::byte> Payload)
        { return std::vector<std::byte>(Payload.begin(), Payload.end()); });
    auto Client = std::make_shared<Preview::Gun::Grpc::ClientSession>(ClientTransport);

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
        [Client, &Result, &Failure, &Io, Payload]() -> boost::asio::awaitable<void>
        {
            try
            {
                Result = co_await Client->Run(std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
            }
            catch (...)
            {
                Failure = std::current_exception();
            }
            Io.stop();
        },
        boost::asio::detached);
    Io.run();

    ASSERT_FALSE(Failure);
    ASSERT_TRUE(Result.has_value());
    EXPECT_EQ(Result->Code, Preview::Fault::Code::Success);
    EXPECT_EQ(Result->GrpcStatus, 0U);
    ASSERT_EQ(Result->Payload.size(), Payload.size());
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Result->Payload.data()),
                               Result->Payload.size()),
              Payload);
}
