/**
 * @file CarrierMemoryTtTest.cpp
 * @brief CarrierMemory 中 TrustTunnel 独立握手关闭场景。
 */
#include "MemorySupport.hpp"
#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <exception>
#include <memory>
#include <string>
#include <utility>

#include <Prism/Protocols/Trusttunnel/Trusttunnel.hpp>
#include <Prism/Transport/MemoryStream.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Trusttunnel = Prism::Trusttunnel;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::Tests::Integration::Layering::CarrierMemorySupport::CompletionChannel;
    using Prism::Tests::Integration::Layering::CarrierMemorySupport::RunCoroutine;
    using Prism::Tests::Integration::Layering::CarrierMemorySupport::WaitForCompletion;
    struct TrustTunnelHandshakeState final
    {
        std::shared_ptr<CompletionChannel> ServerCompletion;
        std::shared_ptr<std::exception_ptr> ServerException;
        std::shared_ptr<std::string> Target;
    };

    struct TrustTunnelServerRequest final
    {
        MemoryStream ServerMemory;
        std::shared_ptr<TrustTunnelHandshakeState> State;
    };

    auto RunTrustTunnelServer(TrustTunnelServerRequest Request) -> Net::awaitable<void>
    {
        auto [ErrorCode, AcceptedTarget, Connection] = co_await Trusttunnel::Accept(
            std::make_shared<MemoryStream>(std::move(Request.ServerMemory)),
            Trusttunnel::ServerConfig{"tu_user", "tu_pass"});
        if (ErrorCode != Error::None)
        {
            EXPECT_TRUE(false) << "Accept err=" << static_cast<int>(ErrorCode);
            co_return;
        }
        *Request.State->Target = std::move(AcceptedTarget);
        const auto CloseResult = Connection->Close();
        EXPECT_TRUE(CloseResult);
        if (CloseResult)
        {
            const auto DrainResult = co_await Connection->Activity()->Drain();
            EXPECT_TRUE(DrainResult);
        }
    }

    auto CompleteTrustTunnelServer(
        const std::shared_ptr<TrustTunnelHandshakeState> &State,
        std::exception_ptr Exception) -> void
    {
        *State->ServerException = std::move(Exception);
        (void)State->ServerCompletion->try_send(
            boost::system::error_code{});
    }

    struct TrustTunnelHandshakeRequest final
    {
        Net::io_context &IoContext;
        MemoryStream ClientMemory;
        MemoryStream ServerMemory;
        std::shared_ptr<TrustTunnelHandshakeState> State;
    };

    auto RunTrustTunnelHandshake(TrustTunnelHandshakeRequest Request)
        -> Net::awaitable<void>
    {
        const auto State = Request.State;
        Net::co_spawn(
            Request.IoContext,
            RunTrustTunnelServer(TrustTunnelServerRequest{
                std::move(Request.ServerMemory), State}),
            [State](std::exception_ptr Exception)
            { CompleteTrustTunnelServer(State, std::move(Exception)); });
        auto [ErrorCode, Connection] = co_await Trusttunnel::Connect(
            {std::make_shared<MemoryStream>(std::move(Request.ClientMemory)),
             Trusttunnel::ClientConfig{"tu_user", "tu_pass"}, "example.com", 443});
        if (ErrorCode != Error::None)
        {
            EXPECT_TRUE(false) << "Connect err=" << static_cast<int>(ErrorCode);
            co_await WaitForCompletion(State->ServerCompletion);
            if (*State->ServerException)
            {
                std::rethrow_exception(*State->ServerException);
            }
            co_return;
        }
        co_await WaitForCompletion(State->ServerCompletion);
        if (*State->ServerException)
        {
            std::rethrow_exception(*State->ServerException);
        }
        EXPECT_EQ(*State->Target, "example.com");
        const auto CloseResult = Connection->Close();
        EXPECT_TRUE(CloseResult);
        if (CloseResult)
        {
            const auto DrainResult = co_await Connection->Activity()->Drain();
            EXPECT_TRUE(DrainResult);
        }
    }

    TEST(TrustTunnelConn, HandshakeDirect)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto State = std::make_shared<TrustTunnelHandshakeState>();
        State->ServerCompletion = std::make_shared<CompletionChannel>(
            IoContext.get_executor(), 1);
        State->ServerException = std::make_shared<std::exception_ptr>();
        State->Target = std::make_shared<std::string>();
        RunCoroutine(IoContext, RunTrustTunnelHandshake(
            TrustTunnelHandshakeRequest{
                IoContext, std::move(ClientMemory), std::move(ServerMemory), State}));
    }
} // namespace
