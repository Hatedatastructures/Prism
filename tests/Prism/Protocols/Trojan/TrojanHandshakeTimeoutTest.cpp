/**
 * @file TrojanHandshakeTimeoutTest.cpp
 * @brief Trojan 服务端握手超时行为。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <chrono>
#include <exception>
#include <memory>
#include <utility>

#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;

    auto RunTrojanHandshakeTimeout(
        const std::shared_ptr<Prism::MemoryStream> &Client,
        const std::shared_ptr<Prism::MemoryStream> &Server) -> Net::awaitable<void>
    {
        Prism::Trojan::ServerConfig Config;
        Config.Password = "prepared-trojan-password";
        auto Result = co_await Prism::Trojan::Accept(Server, Config);

        EXPECT_FALSE(Result);
        if (Result)
        {
            EXPECT_TRUE(Result->Connection);
            if (Result->Connection)
            {
                (void)Result->Connection->Close();
                const auto ConnectionDrain = co_await Result->Connection->Activity()->Drain();
                EXPECT_TRUE(ConnectionDrain);
            }
        }
        else
        {
            EXPECT_EQ(Result.error().Code, Prism::Fault::Code::Timeout);
        }

        const auto ClientClose = Client->Close();
        const auto ServerClose = Server->Close();
        EXPECT_TRUE(ClientClose);
        EXPECT_TRUE(ServerClose);
        const auto ClientDrain = co_await Client->Activity()->Drain();
        const auto ServerDrain = co_await Server->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
        EXPECT_TRUE(ServerDrain);
    }

    TEST(HandshakeTimeout, TrojanHandshakeTimeout)
    {
        Net::io_context IoContext;
        auto [ClientEndpoint, ServerEndpoint] = Prism::MakeMemoryPair(IoContext.get_executor());
        auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEndpoint));
        auto Server = std::make_shared<Prism::MemoryStream>(std::move(ServerEndpoint));
        Server->SetTimeout(std::chrono::milliseconds(100));

        std::exception_ptr Exception;
        Net::co_spawn(IoContext, RunTrojanHandshakeTimeout(Client, Server),
            [&Exception](std::exception_ptr Error)
        {
            Exception = std::move(Error);
        });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

} // namespace
