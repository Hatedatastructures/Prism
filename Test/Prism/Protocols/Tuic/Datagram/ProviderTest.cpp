/**
 * @file ProviderTest.cpp
 * @brief TUIC 数据报 provider 连接行为测试。
 * @details 覆盖内存 QUIC provider 的收发往返、短写与关闭错误。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Protocols/Tuic/Dgram.hpp>
#include <Prism/Protocols/Tuic/Tuic.hpp>
#include <TestSupport/Prism/Quic/MemoryProvider.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Tuic = Prism::Tuic;
    using Prism::AsU8Span;
    using Prism::Error;
    using Prism::Testing::MemoryDatagramProvider;
    using SharedDgram = std::shared_ptr<Tuic::Dgram<>>;

    /** @brief 驱动协程运行并传递异常。 */
    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        IoContext.restart();
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
            [&](std::exception_ptr ErrorValue)
            {
                Exception = ErrorValue;
                IoContext.stop();
            });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /** @brief 构造固定 IPv4 目标地址。 */
    auto MakeDestination() -> Tuic::Address
    {
        Tuic::Address Destination{};
        Destination.Type = Tuic::AddressType::Ipv4;
        Destination.Host = "93.184.216.34";
        Destination.Port = 443;
        return Destination;
    }

    /** @brief 验证 provider 短写错误以及关闭后的发送错误。 */
    auto RunShortWriteClose(MemoryDatagramProvider &Provider,
        SharedDgram Client, SharedDgram Server) -> Net::awaitable<void>
    {
        const auto Target = MakeDestination();
        Provider.MaxSend = 2;
        EXPECT_EQ(co_await Client->AsyncSendTo(Target, AsU8Span(std::string_view{"short"})),
            Error::IoError);
        Provider.MaxSend = 0;
        const auto CloseCommand = Server->Close();
        EXPECT_TRUE(CloseCommand);
        const auto CloseDrain = co_await Server->Activity()->Drain();
        EXPECT_TRUE(CloseDrain);
        EXPECT_EQ(co_await Client->AsyncSendTo(Target, AsU8Span(std::string_view{"closed"})),
            Error::IoError);
        (void)Client->Close();
    }

    TEST(TuicDgramProvider, MemoryProviderRoundtrip)
    {
        Net::io_context ioc;
        auto [ClientProvider, ServerProvider] =
            MemoryDatagramProvider::MakePair(ioc.get_executor());
        auto Client = Tuic::ConnectPacket(ClientProvider, Tuic::ClientConfig{});
        auto Server = Tuic::AcceptPacket(ServerProvider, Tuic::ServerConfig{});
        ASSERT_TRUE(Client);
        ASSERT_TRUE(Server);

        const auto Target = MakeDestination();
        const auto Payload = AsU8Span(std::string_view{"tuic-provider"});
        Tuic::Address ReceivedTarget;
        std::vector<std::uint8_t> ReceivedPayload;
        RunCoroutine(ioc,
            [&]() -> Net::awaitable<void>
            {
                EXPECT_EQ(co_await Client.value()->AsyncSendTo(Target, Payload), Error::None);
                EXPECT_EQ(co_await Server.value()->AsyncReceiveFrom(
                    ReceivedTarget, ReceivedPayload), Error::None);
                EXPECT_EQ(co_await Server.value()->AsyncSendTo(
                    ReceivedTarget, ReceivedPayload), Error::None);
                (void)Client.value()->Close();
                (void)Server.value()->Close();
            });

        EXPECT_EQ(ReceivedTarget.Host, Target.Host);
        EXPECT_EQ(ReceivedTarget.Port, Target.Port);
        EXPECT_EQ(std::string(ReceivedPayload.begin(), ReceivedPayload.end()), "tuic-provider");
    }

    TEST(TuicDgramProvider, ShortWriteAndCloseAreErrors)
    {
        Net::io_context ioc;
        auto [ClientProvider, ServerProvider] =
            MemoryDatagramProvider::MakePair(ioc.get_executor());
        auto Client = Tuic::ConnectPacket(ClientProvider, Tuic::ClientConfig{});
        auto Server = Tuic::AcceptPacket(ServerProvider, Tuic::ServerConfig{});
        ASSERT_TRUE(Client);
        ASSERT_TRUE(Server);

        RunCoroutine(ioc, RunShortWriteClose(
            *ClientProvider, Client.value(), Server.value()));
    }
}
