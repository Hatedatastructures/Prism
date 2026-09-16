/**
 * @file Ss2022ClientServerPerf.cpp
 * @brief SS2022 客户端/服务端封装测试（握手、完整传输与性能）
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <gtest/gtest.h>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Preview/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Shadowsocks = Preview::Shadowsocks2022;

    using Address = Shadowsocks::Address;
    using AddressType = Shadowsocks::AddressType;
    using BenchOptions = Preview::BenchOptions;
    using BenchReport = Preview::BenchReport;
    using ClientConfig = Shadowsocks::ClientConfig;
    using Error = Preview::Error;
    using MemoryStream = Preview::MemoryStream;
    using ServerConfig = Shadowsocks::ServerConfig;
    using SharedTransmission = Preview::SharedTransmission;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct ServerOptions
    {
        SharedTransmission Transport;
        ServerConfig Config;
        std::size_t ExpectedBytes;
        bool Echo;
        std::shared_ptr<CompletionChannel> Completion;
    };

    template <typename Awaitable>
    auto RunCoroutine(
        Net::io_context &IoContext,
        Awaitable Coroutine) -> void
    {
        std::exception_ptr Exception;
        auto Completion =
            [&Exception, &IoContext](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            std::move(Completion));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    [[nodiscard]] auto MakeDestination() -> Address
    {
        Address Destination;
        Destination.Type = AddressType::Ipv4;
        Destination.Host = "93.184.216.34";
        Destination.Port = 443;
        return Destination;
    }

    auto RunServer(ServerOptions Options) -> Net::awaitable<void>
    {
        const auto AcceptResult = co_await Shadowsocks::Accept(
            std::move(Options.Transport),
            Options.Config);
        const auto HandshakeError = std::get<0>(AcceptResult);
        const auto &Request = std::get<1>(AcceptResult);
        const auto &Connection = std::get<2>(AcceptResult);
        (void)Request;
        if (HandshakeError != Error::None || !Connection)
        {
            (void)Options.Completion->try_send(
                boost::system::error_code{}, false);
            co_return;
        }

        std::array<std::byte, 128 * 1024> Buffer{};
        std::size_t Done = 0;
        std::error_code ReadError;
        while (Done < Options.ExpectedBytes)
        {
            const auto ReadSize =
                std::min(Buffer.size(), Options.ExpectedBytes - Done);
            auto ReadWindow = std::span<std::byte>(
                Buffer.data(),
                ReadSize);
            const auto Count =
                co_await Connection->async_read_some(ReadWindow, ReadError);
            if (ReadError || Count == 0 || Count > ReadSize)
            {
                break;
            }
            Done += Count;
            if (Options.Echo)
            {
                std::error_code WriteError;
                auto WriteWindow = std::span<const std::byte>(
                    Buffer.data(),
                    Count);
                const auto Written = co_await Connection->async_write_some(
                    WriteWindow,
                    WriteError);
                if (WriteError || Written != Count)
                {
                    break;
                }
            }
        }

        Connection->Close();
        const bool Completed = Done == Options.ExpectedBytes;
        (void)Options.Completion->try_send(
            boost::system::error_code{},
            Completed);
    }

    auto SpawnServer(
        Net::io_context &IoContext,
        ServerOptions Options) -> void
    {
        auto ServerCompletion =
            [Completion = Options.Completion](std::exception_ptr Exception)
            -> void
        {
            if (Exception)
            {
                (void)Completion->try_send(
                    boost::system::error_code{}, false);
            }
        };
        Net::co_spawn(
            IoContext.get_executor(),
            RunServer(std::move(Options)),
            std::move(ServerCompletion));
    }

    [[nodiscard]] auto MakeServerConfig() -> ServerConfig
    {
        ServerConfig Config;
        Config.password = "perf-Secret";
        return Config;
    }

    [[nodiscard]] auto MakeClientConfig() -> ClientConfig
    {
        ClientConfig Config;
        Config.password = "perf-Secret";
        return Config;
    }

    TEST(Ss2022ClientServer, HandshakeAndTransfer100MB)
    {
        Net::io_context IoContext;
        auto [ClientInput, ServerInput] =
            Preview::MakeMemoryPair(IoContext.get_executor());

        constexpr std::size_t Total = 100 * 1024 * 1024;
        constexpr std::size_t Block = 64 * 1024;
        const auto Completion =
            std::make_shared<CompletionChannel>(
                IoContext.get_executor(),
                1);
        ServerOptions Options{
            std::make_shared<MemoryStream>(std::move(ServerInput)),
            MakeServerConfig(),
            Total,
            false,
            Completion};
        SpawnServer(IoContext, std::move(Options));

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            auto ClientResult = co_await Shadowsocks::Connect(
                std::make_shared<MemoryStream>(std::move(ClientInput)),
                MakeClientConfig(),
                MakeDestination());
            const auto HandshakeError = std::get<0>(ClientResult);
            auto Client = std::get<1>(std::move(ClientResult));
            EXPECT_EQ(HandshakeError, Error::None);
            EXPECT_NE(Client, nullptr);
            if (HandshakeError != Error::None || !Client)
            {
                co_return;
            }

            std::vector<std::uint8_t> Payload(Block, 0x6E);
            std::size_t Sent = 0;
            while (Sent < Total)
            {
                const auto WriteSize = std::min(Block, Total - Sent);
                auto WriteWindow = std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Payload.data()),
                    WriteSize);
                std::error_code WriteError;
                const auto Written = co_await Client->async_write_some(
                    WriteWindow,
                    WriteError);
                if (WriteError || Written == 0 || Written > WriteSize)
                {
                    break;
                }
                Sent += Written;
                if (((Sent / Block) & 0x0F) == 0)
                {
                    const auto PostToken = Net::use_awaitable;
                    co_await Net::post(
                        IoContext.get_executor(),
                        PostToken);
                }
            }
            EXPECT_EQ(Sent, Total);
            Client->Close();

            const auto ServerCompleted =
                co_await Completion->async_receive(Net::use_awaitable);
            EXPECT_TRUE(ServerCompleted);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Ss2022ClientServer, ThroughputLatency)
    {
        Net::io_context IoContext;
        BenchReport ThroughputReport;
        BenchReport LatencyReport;
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            auto [ClientInput, ServerInput] =
                Preview::MakeMemoryPair(IoContext.get_executor());
            constexpr std::size_t ThroughputTotal = 64 * 1024 * 1024;
            const auto ThroughputCompletion =
                std::make_shared<CompletionChannel>(
                    IoContext.get_executor(),
                    1);
            ServerOptions ThroughputServer{
                std::make_shared<MemoryStream>(std::move(ServerInput)),
                MakeServerConfig(),
                ThroughputTotal,
                true,
                ThroughputCompletion};
            SpawnServer(IoContext, std::move(ThroughputServer));

            auto ClientResult = co_await Shadowsocks::Connect(
                std::make_shared<MemoryStream>(std::move(ClientInput)),
                MakeClientConfig(),
                MakeDestination());
            const auto HandshakeError = std::get<0>(ClientResult);
            auto Client = std::get<1>(std::move(ClientResult));
            EXPECT_EQ(HandshakeError, Error::None);
            EXPECT_NE(Client, nullptr);
            if (HandshakeError != Error::None || !Client)
            {
                co_return;
            }

            BenchOptions ThroughputOptions;
            ThroughputOptions.Total = ThroughputTotal;
            ThroughputOptions.Block = 64 * 1024;
            ThroughputReport = co_await Preview::BenchThroughputTx(
                *Client,
                *Client,
                ThroughputOptions);
            EXPECT_EQ(ThroughputReport.Bytes, ThroughputOptions.Total);
            Client->Close();
            const auto ThroughputCompleted = co_await ThroughputCompletion->async_receive(
                Net::use_awaitable);
            EXPECT_TRUE(ThroughputCompleted);

            auto [LatencyClientInput, LatencyServerInput] =
                Preview::MakeMemoryPair(IoContext.get_executor());
            constexpr std::size_t LatencyTotal = 1000 * 4 * 1024;
            const auto LatencyCompletion =
                std::make_shared<CompletionChannel>(
                    IoContext.get_executor(),
                    1);
            ServerOptions LatencyServer{
                std::make_shared<MemoryStream>(std::move(LatencyServerInput)),
                MakeServerConfig(),
                LatencyTotal,
                true,
                LatencyCompletion};
            SpawnServer(IoContext, std::move(LatencyServer));

            auto LatencyClientResult = co_await Shadowsocks::Connect(
                std::make_shared<MemoryStream>(std::move(LatencyClientInput)),
                MakeClientConfig(),
                MakeDestination());
            const auto LatencyHandshakeError =
                std::get<0>(LatencyClientResult);
            auto LatencyClient =
                std::get<1>(std::move(LatencyClientResult));
            EXPECT_EQ(LatencyHandshakeError, Error::None);
            EXPECT_NE(LatencyClient, nullptr);
            if (LatencyHandshakeError != Error::None || !LatencyClient)
            {
                co_return;
            }

            BenchOptions LatencyOptions;
            LatencyOptions.Total = LatencyTotal;
            LatencyOptions.Block = 4 * 1024;
            LatencyReport = co_await Preview::BenchThroughputTx(
                *LatencyClient,
                *LatencyClient,
                LatencyOptions);
            EXPECT_EQ(LatencyReport.Bytes, LatencyOptions.Total);
            LatencyClient->Close();
            const auto LatencyCompleted = co_await LatencyCompletion->async_receive(
                Net::use_awaitable);
            EXPECT_TRUE(LatencyCompleted);
        };
        RunCoroutine(IoContext, std::move(Coroutine));

        EXPECT_GT(ThroughputReport.Mbps, 0.0);
        EXPECT_GT(LatencyReport.Samples, 0u);
        std::printf(
            "ss2022 throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f "
            "p95 %.3f p99 %.3f (min %.3f max %.3f) samples=%zu\n",
            ThroughputReport.Mbps,
            LatencyReport.LatencyAvg,
            LatencyReport.LatencyP50,
            LatencyReport.LatencyP95,
            LatencyReport.LatencyP99,
            LatencyReport.LatencyMin,
            LatencyReport.LatencyMax,
            LatencyReport.Samples);
    }
} // namespace
