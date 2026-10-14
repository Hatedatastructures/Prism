/**
 * @file SS2022UdpE2ETest.cpp
 * @brief Shadowsocks2022 UDP 直连测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Shadowsocks2022 = Preview::Shadowsocks2022;
    using Preview::Error;
    using SharedDgram = Shadowsocks2022::SharedDgram;

    inline constexpr std::array<std::uint8_t, 16> UdpPsk{
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60};
    constexpr auto RecvDeadline = std::chrono::milliseconds(2000);

    struct RootCompletion final
    {
        std::exception_ptr Failure;
    };

    auto CompleteRoot(
        RootCompletion &State,
        std::exception_ptr Failure) -> void
    {
        if (!State.Failure)
        {
            State.Failure = std::move(Failure);
        }
    }

    /** @brief 驱动根协程直至真实完成，并保留首个异常。 */
    auto RunCoroutine(
        Net::io_context &IoContext,
        Net::awaitable<void> Operation) -> void
    {
        RootCompletion State;
        auto Completion = [&State](std::exception_ptr Failure)
        { CompleteRoot(State, std::move(Failure)); };
        IoContext.restart();
        Net::co_spawn(IoContext, std::move(Operation), std::move(Completion));
        IoContext.run();
        if (State.Failure)
        {
            std::rethrow_exception(State.Failure);
        }
    }

    struct DatagramCleanup final
    {
        SharedDgram Server;
        SharedDgram Client;

        ~DatagramCleanup()
        {
            if (Client)
            {
                Client->Close();
            }
            if (Server)
            {
                Server->Close();
            }
        }
    };

    auto RecvGuarded(
        const SharedDgram &Socket,
        Shadowsocks2022::Address &Source,
        std::vector<std::uint8_t> &Payload)
        -> Net::awaitable<std::optional<Error>>
    {
        Net::steady_timer Timer(Socket->Executor());
        Timer.expires_after(RecvDeadline);
        using Net::experimental::awaitable_operators::operator||;
        auto Result = co_await (
            Socket->AsyncReceiveFrom(Source, Payload) ||
            Timer.async_wait(Net::use_awaitable));
        if (Result.index() == 1)
        {
            Socket->Close();
            co_return std::nullopt;
        }
        co_return std::get<0>(std::move(Result));
    }

    auto MakeServer(Net::io_context &IoContext)
        -> std::pair<SharedDgram, Net::ip::udp::endpoint>
    {
        Net::ip::udp::endpoint Bound;
        Shadowsocks2022::ServerConfig Config;
        Config.Psk = UdpPsk;
        return {
            Shadowsocks2022::AcceptPacket(
                {IoContext.get_executor(), 0, Config, &Bound}),
            Bound};
    }

    struct ClientRoute final
    {
        std::string Remote;
        bool CorrectKey;
    };

    auto MakeClient(
        Net::io_context &IoContext,
        ClientRoute Route) -> SharedDgram
    {
        Shadowsocks2022::ClientConfig Config;
        Config.Psk = UdpPsk;
        if (!Route.CorrectKey)
        {
            Config.Psk[0] ^= 0xFF;
        }
        return Shadowsocks2022::ConnectPacket(
            IoContext.get_executor(), std::move(Route.Remote), Config);
    }

    struct UdpScenarioRequest final
    {
        Shadowsocks2022::AddressType AddressType;
        std::string Payload;
        bool CorrectKey;
    };

    /** @brief 驱动真实 UDP server/client 收发及错误 key 收口。 */
    auto RunUdpScenario(
        Net::io_context &IoContext,
        UdpScenarioRequest Request) -> Net::awaitable<void>
    {
        auto [Server, Bound] = MakeServer(IoContext);
        DatagramCleanup Cleanup{Server, nullptr};
        if (!Server)
        {
            ADD_FAILURE() << "SS2022 UDP server creation failed";
            co_return;
        }
        auto Client = MakeClient(
            IoContext,
            ClientRoute{
                "127.0.0.1:" + std::to_string(Bound.port()),
                Request.CorrectKey});
        Cleanup.Client = Client;
        if (!Client)
        {
            ADD_FAILURE() << "SS2022 UDP client creation failed";
            co_return;
        }
        const auto Target = Shadowsocks2022::Address{
            Request.AddressType,
            Request.AddressType == Shadowsocks2022::AddressType::Domain
                ? "example.com"
                : "1.2.3.4",
            443};
        const auto SendError = co_await Client->AsyncSendTo(
            Target,
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Request.Payload.data()),
                Request.Payload.size()));
        if (!Request.CorrectKey)
        {
            EXPECT_EQ(SendError, Error::None);
            Shadowsocks2022::Address Source;
            std::vector<std::uint8_t> Received;
            const auto ReceiveError = co_await RecvGuarded(
                Server, Source, Received);
            EXPECT_EQ(ReceiveError, Error::BadAuth);
            Server->Close();
            EXPECT_NE(
                co_await Server->AsyncReceiveFrom(Source, Received),
                Error::None);
            Client->Close();
            co_return;
        }
        EXPECT_EQ(SendError, Error::None);
        Shadowsocks2022::Address Source;
        std::vector<std::uint8_t> Received;
        const auto ReceiveError = co_await RecvGuarded(
            Server, Source, Received);
        EXPECT_EQ(ReceiveError, Error::None);
        EXPECT_EQ(
            std::string(Received.begin(), Received.end()), Request.Payload);
        if (Request.AddressType == Shadowsocks2022::AddressType::Domain)
        {
            const auto ResponseError = co_await Server->AsyncSendTo(
                Source, Received);
            EXPECT_EQ(ResponseError, Error::None);
            Shadowsocks2022::Address ResponseSource;
            std::vector<std::uint8_t> Echo;
            EXPECT_EQ(
                co_await RecvGuarded(Client, ResponseSource, Echo),
                Error::None);
            EXPECT_EQ(
                std::string(Echo.begin(), Echo.end()), Request.Payload);
        }
        Client->Close();
        Server->Close();
    }

    TEST(SS2022Udp, DirectEchoDomain)
    {
        Net::io_context IoContext;
        RunCoroutine(
            IoContext,
            RunUdpScenario(
                IoContext,
                UdpScenarioRequest{
                    Shadowsocks2022::AddressType::Domain,
                    "ss2022 udp payload",
                    true}));
    }

    TEST(SS2022Udp, DirectEchoIpv4)
    {
        Net::io_context IoContext;
        RunCoroutine(
            IoContext,
            RunUdpScenario(
                IoContext,
                UdpScenarioRequest{
                    Shadowsocks2022::AddressType::Ipv4,
                    "ipv4 payload",
                    true}));
    }

    TEST(SS2022Udp, BadPskDrop)
    {
        Net::io_context IoContext;
        RunCoroutine(
            IoContext,
            RunUdpScenario(
                IoContext,
                UdpScenarioRequest{
                    Shadowsocks2022::AddressType::Domain,
                    "bad psk",
                    false}));
    }
} // namespace
