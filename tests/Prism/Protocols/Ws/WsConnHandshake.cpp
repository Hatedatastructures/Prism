/**
 * @file WsConnHandshake.cpp
 * @brief 验证 WebSocket Upgrade header 与错误响应。
 */
#include "WsFactorySupport.hpp"
#include "WsConnSessionSupport.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <expected>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Ws/Detail/Codec.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <gtest/gtest.h>
namespace
{
    namespace Net = boost::asio;
    namespace Ws = Prism::Ws;
    namespace TestSupport = Prism::Tests::WsConnSessionSupport;
    using Prism::AsBytes;
    using Prism::AsU8Span;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using TestSupport::CloseAndWait;
    using TestSupport::WaitThenClose;
    using TestSupport::EagerTask;
    using TestSupport::ErrorWireRequest;
    using TestSupport::HeaderRequest;
    using TestSupport::PairCompletion;
    using TestSupport::ResponseRejectRequest;
    using TestSupport::RunCoro;
    using TestSupport::SpawnEager;
    using TestSupport::StreamPairRequest;
    using TestSupport::TestKey;
    /** @brief 服务端验证大小写不敏感的 Upgrade header。 */
    auto RunCaseInsensitiveServer(std::shared_ptr<MemoryStream> Server,
                                  std::shared_ptr<bool> Result)
        -> Net::awaitable<void>
    {
        auto Accepted = co_await Prism::Ws::Accept(
            Prism::Tests::WsFactorySupport::MakeAcceptOptionsForTest(
                Server, Ws::ServerOptions{}));
        if (!Accepted)
        {
            *Result = false;
            co_return;
        }
        *Result = Accepted->Key == TestKey && Accepted->Connection != nullptr;
        auto Connection = std::move(Accepted->Connection);
        if (Connection)
        {
            const auto CloseResult = Connection->Close();
            EXPECT_TRUE(CloseResult);
            const auto DrainResult = co_await Connection->Activity()->Drain();
            EXPECT_TRUE(DrainResult);
        }
    }

    /** @brief 驱动服务端大小写不敏感 header 场景。 */
    auto RunServerAcceptsCaseInsensitiveHeaders(HeaderRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Pair.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Pair.Server));
        auto ServerTask = SpawnEager(
            Server->Executor(), RunCaseInsensitiveServer(Server, Request.Result));
        bool InputComplete = false;
        std::exception_ptr ParentFailure;
        try
        {
            std::error_code ErrorCode;
            const auto ClientWrite = co_await Client->WriteSome(AsBytes(AsU8Span(Request.Request)));
            ErrorCode = Prism::Fault::ToNative(ClientWrite.Failure);
            EXPECT_FALSE(ErrorCode);
            InputComplete = !ErrorCode && ClientWrite.Bytes == Request.Request.size();
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        if (InputComplete)
        {
            co_await WaitThenClose(PairCompletion{Client, Server, std::move(ServerTask)});
        }
        else
        {
            co_await CloseAndWait(PairCompletion{Client, Server, std::move(ServerTask)});
        }
        EXPECT_TRUE(*Request.Result);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    /** @brief 原始服务端返回大小写混合的 101 response。 */
    auto RunCaseInsensitiveResponseServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 512> Request{};
        std::error_code ErrorCode;
        const auto Read = co_await Server->ReadSome(Request);
        ErrorCode = Prism::Fault::ToNative(Read.Failure);
        const auto Accept = Ws::Detail::ComputeAccept(TestKey);
        const std::string Response =
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: WebSocket\r\n"
            "connection: Upgrade\r\nsec-websocket-accept: " + Accept + "\r\n\r\n";
        const auto ResponseWrite = co_await Server->WriteSome(AsBytes(AsU8Span(Response)));
        ErrorCode = Prism::Fault::ToNative(ResponseWrite.Failure);
    }
    /** @brief 驱动客户端大小写不敏感 response 场景。 */
    auto RunClientAcceptsCaseInsensitiveResponse(StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = SpawnEager(
            Server->Executor(), RunCaseInsensitiveResponseServer(Server));
        std::exception_ptr ParentFailure;
        try
        {
            const Ws::ClientOptions Config{"example.com", TestKey};
            auto Connected = co_await Prism::Ws::Connect(
                Prism::Tests::WsFactorySupport::MakeConnectOptionsForTest(
                    Client, Config));
            EXPECT_TRUE(Connected);
            if (Connected)
            {
                auto Connection = std::move(Connected->Connection);
                const auto CloseResult = Connection->Close();
                EXPECT_TRUE(CloseResult);
                const auto DrainResult = co_await Connection->Activity()->Drain();
                EXPECT_TRUE(DrainResult);
            }
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        co_await CloseAndWait(PairCompletion{Client, Server, std::move(ServerTask)});
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    /** @brief 服务端验证请求失败的正式错误类型。 */
    auto RunExpectedServerError(std::shared_ptr<MemoryStream> Server,
                                const Prism::Fault::Code Expected)
        -> Net::awaitable<void>
    {
        auto Accepted = co_await Prism::Ws::Accept(
            Prism::Tests::WsFactorySupport::MakeAcceptOptionsForTest(
                Server, Ws::ServerOptions{}));
        EXPECT_FALSE(Accepted);
        if (Accepted)
        {
            auto Connection = std::move(Accepted->Connection);
            if (Connection)
            {
                const auto CloseResult = Connection->Close();
                EXPECT_TRUE(CloseResult);
                const auto DrainResult = co_await Connection->Activity()->Drain();
                EXPECT_TRUE(DrainResult);
            }
            co_return;
        }
        EXPECT_EQ(Accepted.error().Code, Expected);
        EXPECT_FALSE(Accepted.error().Native);
    }

    /** @brief 驱动服务端错误请求场景。 */
    auto RunServerRejectRequest(ErrorWireRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Pair.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Pair.Server));
        auto ServerTask = SpawnEager(
            Server->Executor(), RunExpectedServerError(Server, Request.Expected));
        bool InputComplete = false;
        std::exception_ptr ParentFailure;
        try
        {
            std::error_code ErrorCode;
            const auto Write = co_await Client->WriteSome(AsBytes(AsU8Span(Request.Request)));
            ErrorCode = Prism::Fault::ToNative(Write.Failure);
            InputComplete = !ErrorCode && Write.Bytes == Request.Request.size();
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        auto Completion = PairCompletion{Client, Server, std::move(ServerTask)};
        if (InputComplete)
        {
            co_await WaitThenClose(std::move(Completion));
        }
        else
        {
            co_await CloseAndWait(std::move(Completion));
        }
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    /** @brief 原始服务端读取请求并返回指定 HTTP response。 */
    auto RunResponseServer(std::shared_ptr<MemoryStream> Server,
                           std::string Response) -> Net::awaitable<void>
    {
        std::array<std::byte, 512> Request{};
        std::error_code ErrorCode;
        const auto Read = co_await Server->ReadSome(Request);
        ErrorCode = Prism::Fault::ToNative(Read.Failure);
        const auto Count = Read.Bytes;
        EXPECT_GT(Count, 0u);
        const auto ResponseWrite = co_await Server->WriteSome(AsBytes(AsU8Span(Response)));
        ErrorCode = Prism::Fault::ToNative(ResponseWrite.Failure);
    }

    /** @brief 驱动客户端非 101 或错误 accept 场景。 */
    auto RunClientRejectsResponse(ResponseRejectRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Pair.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Pair.Server));
        auto ServerTask = SpawnEager(
            Server->Executor(), RunResponseServer(Server, Request.Response));
        std::exception_ptr ParentFailure;
        try
        {
            const Ws::ClientOptions Config{"example.com", TestKey};
            auto Connected = co_await Prism::Ws::Connect(
                Prism::Tests::WsFactorySupport::MakeConnectOptionsForTest(
                    Client, Config));
            EXPECT_FALSE(Connected);
            if (Connected)
            {
                auto Connection = std::move(Connected->Connection);
                const auto CloseResult = Connection->Close();
                EXPECT_TRUE(CloseResult);
                const auto DrainResult = co_await Connection->Activity()->Drain();
                EXPECT_TRUE(DrainResult);
            }
            else
            {
                EXPECT_EQ(Connected.error().Code, Request.Expected);
                EXPECT_FALSE(Connected.error().Native);
            }
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        co_await CloseAndWait(PairCompletion{Client, Server, std::move(ServerTask)});
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    TEST(WsConnSession, ServerAcceptsCaseInsensitiveHeaders)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        const std::string Request =
            "GET / HTTP/1.1\r\nhost: example.com\r\nupgrade: WebSocket\r\n"
            "connection: keep-alive, Upgrade\r\nsec-websocket-key: " +
            std::string(TestKey) + "\r\nsec-websocket-version: 13\r\n\r\n";
        RunCoro(IoContext, RunServerAcceptsCaseInsensitiveHeaders(HeaderRequest{
                               {std::move(Client), std::move(Server)}, Request,
                               std::make_shared<bool>(false)}));
    }

    TEST(WsConnSession, ClientAcceptsCaseInsensitiveResponseHeaders)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunClientAcceptsCaseInsensitiveResponse(
                               StreamPairRequest{std::move(Client), std::move(Server)}));
    }

    TEST(WsConnSession, ServerRejectsNonUpgrade)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunServerRejectRequest(ErrorWireRequest{
                               {std::move(Client), std::move(Server)},
                               "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                               Prism::Fault::Code::BadMessage}));
    }

    TEST(WsConnSession, ServerRejectsMissingKey)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunServerRejectRequest(ErrorWireRequest{
                               {std::move(Client), std::move(Server)},
                               "GET / HTTP/1.1\r\nHost: example.com\r\n"
                               "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                               Prism::Fault::Code::BadMessage}));
    }

    TEST(WsConnSession, ClientRejectsNon101)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunClientRejectsResponse(ResponseRejectRequest{
                               {std::move(Client), std::move(Server)},
                               "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                               Prism::Fault::Code::BadMessage}));
    }

    TEST(WsConnSession, ClientRejectsBadAccept)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunClientRejectsResponse(ResponseRejectRequest{
                               {std::move(Client), std::move(Server)},
                               "HTTP/1.1 101 Switching Protocols\r\n"
                               "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                               "Sec-WebSocket-Accept: wrong-Accept-value\r\n\r\n",
                               Prism::Fault::Code::AuthFailed}));
    }

    TEST(WsFactory, ClientPartialNativeHandshakeFailureRetiresTheSameCarrier)
    {
        Net::io_context IoContext;
        auto Transport = std::make_shared<Prism::PrismMockTransport>(
            IoContext.get_executor());
        const auto Native = std::make_error_code(std::errc::connection_reset);
        Transport->SetWriteError(Native);
        Transport->WriteErrorBytes = 7;
        std::expected<Ws::ConnectResult, Prism::Fault::Failure> Outcome{
            std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument})};
        bool Drained = false;
        auto Run = [&]() -> Net::awaitable<void>
        {
            Outcome = co_await Ws::Connect(
                Prism::Tests::WsFactorySupport::MakeConnectOptionsForTest(
                    Transport, Ws::ClientOptions{"example.com", TestKey}));
            const auto Result = co_await Transport->Activity()->Drain();
            Drained = Result.has_value();
        };
        RunCoro(IoContext, Run());

        ASSERT_FALSE(Outcome);
        EXPECT_EQ(Outcome.error().Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.error().Native, Native);
        EXPECT_EQ(Transport->Written.size(), 7U);
        EXPECT_TRUE(Transport->IsCancelled());
        EXPECT_TRUE(Transport->IsClosed());
        EXPECT_TRUE(Drained);
    }

    TEST(WsFactory, ServerPartialNativeHandshakeFailureRetiresTheSameCarrier)
    {
        Net::io_context IoContext;
        auto Transport = std::make_shared<Prism::PrismMockTransport>(
            IoContext.get_executor());
        const std::string PartialRequest = "GET ";
        std::vector<std::uint8_t> Wire(PartialRequest.begin(), PartialRequest.end());
        Transport->InjectRead(std::move(Wire));
        const auto Native = std::make_error_code(std::errc::connection_reset);
        Transport->ReadErrorBytes = PartialRequest.size();
        Transport->SetReadError(Native);
        std::expected<Ws::AcceptResult, Prism::Fault::Failure> Outcome{
            std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument})};
        bool Drained = false;
        auto Run = [&]() -> Net::awaitable<void>
        {
            Outcome = co_await Ws::Accept(
                Prism::Tests::WsFactorySupport::MakeAcceptOptionsForTest(
                    Transport, Ws::ServerOptions{}));
            const auto Result = co_await Transport->Activity()->Drain();
            Drained = Result.has_value();
        };
        RunCoro(IoContext, Run());

        ASSERT_FALSE(Outcome);
        EXPECT_EQ(Outcome.error().Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.error().Native, Native);
        EXPECT_EQ(Transport->ReadsDone, 1U);
        EXPECT_TRUE(Transport->Written.empty());
        EXPECT_TRUE(Transport->IsCancelled());
        EXPECT_TRUE(Transport->IsClosed());
        EXPECT_TRUE(Drained);
    }
}
