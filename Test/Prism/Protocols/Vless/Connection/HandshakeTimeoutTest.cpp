/**
 * @file HandshakeTimeoutTest.cpp
 * @brief VLESS 服务端握手超时行为。
 */

#include "SessionSupport.hpp"

#include <chrono>

namespace
{

    auto RunVlessHandshakeTimeout(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server) -> Net::awaitable<void>
    {
        Vless::ServerConfig Config;
        Config.uuid = TestUuid();
        auto Result = co_await Vless::Accept(Server, Config);

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

    TEST(HandshakeTimeout, VlessHandshakeTimeout)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeSharedMemoryPair(IoContext.get_executor());
        Server->SetTimeout(std::chrono::milliseconds(100));

        RunCoro(IoContext, RunVlessHandshakeTimeout(Client, Server));
    }

} // namespace
