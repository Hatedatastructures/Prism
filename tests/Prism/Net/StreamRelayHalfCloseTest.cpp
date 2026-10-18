/**
 * @file StreamRelayHalfCloseTest.cpp
 * @brief 双向 StreamRelay 的半关闭和 EOF 顺序测试。
 * @details 保留小请求大响应、大请求小响应、双向 EOF 和单向半关闭后空闲超时四种输入场景。
 */

#include <gtest/gtest.h>

#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Relay/Relay.hpp>
#include <Prism/Transport/MemoryStream.hpp>

#include <boost/asio.hpp>

#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace
{

    namespace Net = boost::asio;

    constexpr std::size_t RelayBufferSize{4096U};
    constexpr std::chrono::seconds ScenarioTimeout{2};

    struct RelayConnections final
    {
        Prism::SharedTransmission Client;
        Prism::SharedTransmission Inbound;
        Prism::SharedTransmission Outbound;
        Prism::SharedTransmission Upstream;
    };

    enum class HalfCloseOrder
    {
        RequestThenResponse,
        UpstreamThenClient,
        BothBeforeRelay
    };

    struct HalfCloseScenario final
    {
        std::size_t RequestSize{0};
        std::size_t ResponseSize{0};
        std::byte RequestValue{0};
        std::byte ResponseValue{0};
        std::chrono::milliseconds IdleTimeout{0};
        HalfCloseOrder Order{HalfCloseOrder::RequestThenResponse};
    };

    struct ExchangeResult final
    {
        std::vector<std::byte> Request;
        std::vector<std::byte> Response;
    };

    struct ScenarioResult final
    {
        Prism::Network::Relay::Result Relay;
        ExchangeResult Exchange;
    };

    struct RelayTestRun final
    {
        RelayConnections Connections;
        HalfCloseScenario Scenario;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
        ScenarioResult Result;
    };

    [[nodiscard]] auto MakePayload(const std::size_t Size, const std::byte Value)
        -> std::vector<std::byte>
    {
        return std::vector<std::byte>(Size, Value);
    }

    [[nodiscard]] auto MakeConnections(Net::any_io_executor Executor) -> RelayConnections
    {
        auto [ClientValue, InboundValue] = Prism::MakeMemoryPair(Executor);
        auto [OutboundValue, UpstreamValue] = Prism::MakeMemoryPair(std::move(Executor));
        return RelayConnections{
            std::make_shared<Prism::MemoryStream>(std::move(ClientValue)),
            std::make_shared<Prism::MemoryStream>(std::move(InboundValue)),
            std::make_shared<Prism::MemoryStream>(std::move(OutboundValue)),
            std::make_shared<Prism::MemoryStream>(std::move(UpstreamValue))};
    }

    [[nodiscard]] auto MakeRelayRequest(const RelayTestRun &Run)
        -> Prism::Network::Relay::Request
    {
        return Prism::Network::Relay::Request{
            .Inbound = Run.Connections.Inbound,
            .Outbound = Run.Connections.Outbound,
            .BufferSize = RelayBufferSize,
            .IdleTimeout = Run.Scenario.IdleTimeout,
            .Bytes = Run.Bytes};
    }

    [[nodiscard]] auto WriteAll(
        const Prism::SharedTransmission &Carrier,
        const std::vector<std::byte> &Payload)
        -> Net::awaitable<void>
    {
        const auto Result = co_await Carrier->WriteExact(std::span<const std::byte>(Payload));
        if (Result.Failure.Failed() || Result.Bytes != Payload.size())
        {
            throw std::runtime_error("MemoryStream payload write failed");
        }
    }

    [[nodiscard]] auto ShutdownWrite(const Prism::SharedTransmission &Carrier)
        -> Net::awaitable<void>
    {
        const auto Result = co_await Carrier->WriteShutdown();
        if (!Result)
        {
            throw std::runtime_error("MemoryStream write half-close failed");
        }
    }

    [[nodiscard]] auto ReadUntilEof(const Prism::SharedTransmission &Carrier)
        -> Net::awaitable<std::vector<std::byte>>
    {
        std::vector<std::byte> Payload;
        std::array<std::byte, RelayBufferSize> Buffer{};
        while (true)
        {
            const auto Result = co_await Carrier->ReadSome(std::span<std::byte>(Buffer));
            if (Result.Bytes > Buffer.size())
            {
                throw std::runtime_error("MemoryStream reported an oversized read");
            }
            Payload.insert(Payload.end(), Buffer.begin(),
                Buffer.begin() + static_cast<std::ptrdiff_t>(Result.Bytes));
            if (Result.Failure.Code == Prism::Fault::Code::Eof)
            {
                co_return Payload;
            }
            if (Result.Failure.Failed() || Result.Bytes == 0U)
            {
                throw std::runtime_error("MemoryStream read ended before EOF");
            }
        }
    }

    [[nodiscard]] auto ReadPayload(
        const Prism::SharedTransmission &Carrier,
        const std::size_t ExpectedSize)
        -> Net::awaitable<std::vector<std::byte>>
    {
        std::vector<std::byte> Payload;
        std::array<std::byte, RelayBufferSize> Buffer{};
        while (Payload.size() < ExpectedSize)
        {
            const auto Result = co_await Carrier->ReadSome(std::span<std::byte>(Buffer));
            if (Result.Bytes > Buffer.size() || Result.Failure.Failed() || Result.Bytes == 0U)
            {
                throw std::runtime_error("MemoryStream payload read failed");
            }
            Payload.insert(Payload.end(), Buffer.begin(),
                Buffer.begin() + static_cast<std::ptrdiff_t>(Result.Bytes));
        }
        co_return Payload;
    }

    [[nodiscard]] auto RunRequestThenResponse(
        const RelayConnections &Connections,
        const HalfCloseScenario &Scenario)
        -> Net::awaitable<ExchangeResult>
    {
        const auto Request = MakePayload(Scenario.RequestSize, Scenario.RequestValue);
        const auto Response = MakePayload(Scenario.ResponseSize, Scenario.ResponseValue);
        co_await WriteAll(Connections.Client, Request);
        co_await ShutdownWrite(Connections.Client);

        auto ObservedRequest = co_await ReadUntilEof(Connections.Upstream);
        if (!Response.empty())
        {
            co_await WriteAll(Connections.Upstream, Response);
            co_await ShutdownWrite(Connections.Upstream);
        }
        auto ObservedResponse = co_await ReadUntilEof(Connections.Client);
        co_return ExchangeResult{std::move(ObservedRequest), std::move(ObservedResponse)};
    }

    [[nodiscard]] auto RunUpstreamThenClientHalfClose(
        const RelayConnections &Connections,
        const HalfCloseScenario &Scenario)
        -> Net::awaitable<ExchangeResult>
    {
        const auto Request = MakePayload(Scenario.RequestSize, Scenario.RequestValue);
        const auto Response = MakePayload(Scenario.ResponseSize, Scenario.ResponseValue);
        co_await WriteAll(Connections.Client, Request);
        auto ObservedRequest = co_await ReadPayload(Connections.Upstream, Request.size());
        co_await WriteAll(Connections.Upstream, Response);
        co_await ShutdownWrite(Connections.Upstream);
        co_await ShutdownWrite(Connections.Client);
        auto ObservedResponse = co_await ReadUntilEof(Connections.Client);
        co_return ExchangeResult{std::move(ObservedRequest), std::move(ObservedResponse)};
    }

    [[nodiscard]] auto PreparePreclosedDirections(
        const RelayConnections &Connections,
        const HalfCloseScenario &Scenario)
        -> Net::awaitable<void>
    {
        const auto Request = MakePayload(Scenario.RequestSize, Scenario.RequestValue);
        const auto Response = MakePayload(Scenario.ResponseSize, Scenario.ResponseValue);
        co_await WriteAll(Connections.Client, Request);
        co_await WriteAll(Connections.Upstream, Response);
        co_await ShutdownWrite(Connections.Client);
        co_await ShutdownWrite(Connections.Upstream);
    }

    [[nodiscard]] auto ReadPreclosedDirections(const RelayConnections &Connections)
        -> Net::awaitable<ExchangeResult>
    {
        using Net::experimental::awaitable_operators::operator&&;
        auto [Request, Response] = co_await (
            ReadUntilEof(Connections.Upstream) && ReadUntilEof(Connections.Client));
        co_return ExchangeResult{std::move(Request), std::move(Response)};
    }

    [[nodiscard]] auto CloseAndDrain(const Prism::SharedTransmission &Carrier)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        const auto Closed = Carrier->Close();
        if (!Closed)
        {
            co_return Closed.error();
        }
        const auto Activity = Carrier->Activity();
        if (!Activity)
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::Blocked};
        }
        const auto Drained = co_await Activity->Drain();
        if (!Drained)
        {
            co_return Drained.error();
        }
        co_return Prism::Fault::Failure{};
    }

    [[nodiscard]] auto RunScenario(RelayTestRun &Run)
        -> Net::awaitable<void>
    {
        using Net::experimental::awaitable_operators::operator&&;
        if (Run.Scenario.Order == HalfCloseOrder::BothBeforeRelay)
        {
            co_await PreparePreclosedDirections(Run.Connections, Run.Scenario);
            auto [RelayResult, Exchange] = co_await (
                Prism::Network::Relay::Run(MakeRelayRequest(Run)) &&
                ReadPreclosedDirections(Run.Connections));
            Run.Result.Relay = std::move(RelayResult);
            Run.Result.Exchange = std::move(Exchange);
        }
        else if (Run.Scenario.Order == HalfCloseOrder::UpstreamThenClient)
        {
            auto [RelayResult, Exchange] = co_await (
                Prism::Network::Relay::Run(MakeRelayRequest(Run)) &&
                RunUpstreamThenClientHalfClose(Run.Connections, Run.Scenario));
            Run.Result.Relay = std::move(RelayResult);
            Run.Result.Exchange = std::move(Exchange);
        }
        else
        {
            auto [RelayResult, Exchange] = co_await (
                Prism::Network::Relay::Run(MakeRelayRequest(Run)) &&
                RunRequestThenResponse(Run.Connections, Run.Scenario));
            Run.Result.Relay = std::move(RelayResult);
            Run.Result.Exchange = std::move(Exchange);
        }

        const auto ClientClose = co_await CloseAndDrain(Run.Connections.Client);
        const auto UpstreamClose = co_await CloseAndDrain(Run.Connections.Upstream);
        if (ClientClose.Failed() || UpstreamClose.Failed())
        {
            throw std::runtime_error("MemoryStream endpoint retirement failed");
        }
    }

    auto RunCoro(Net::io_context &Io, auto Coro) -> void
    {
        std::exception_ptr Failure;
        bool Completed = false;
        bool TimedOut = false;
        Net::steady_timer Deadline(Io);
        Deadline.expires_after(ScenarioTimeout);
        Deadline.async_wait([&](const boost::system::error_code &Error)
        {
            if (!Error && !Completed)
            {
                TimedOut = true;
                Io.stop();
            }
        });
        Net::co_spawn(Io, std::move(Coro), [&](std::exception_ptr Error)
        {
            Failure = std::move(Error);
            Completed = true;
            (void)Deadline.cancel();
        });
        Io.run();
        if (TimedOut)
        {
            throw std::runtime_error("StreamRelay scenario timed out");
        }
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    [[nodiscard]] auto RunHalfCloseScenario(const HalfCloseScenario &Scenario)
        -> ScenarioResult
    {
        Net::io_context Io;
        RelayTestRun Run{
            .Connections = MakeConnections(Io.get_executor()),
            .Scenario = Scenario,
            .Bytes = std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{RelayBufferSize, 2U})};
        RunCoro(Io, RunScenario(Run));
        return Run.Result;
    }

} // namespace

TEST(TunnelHalfClose, SmallRequestLargeResponse)
{
    const HalfCloseScenario Scenario{
        .RequestSize = 128U,
        .ResponseSize = 64U * 1024U,
        .RequestValue = std::byte{0x11},
        .ResponseValue = std::byte{0x22}};
    const auto Result = RunHalfCloseScenario(Scenario);

    EXPECT_FALSE(Result.Relay.Failure.Failed());
    EXPECT_EQ(Result.Relay.Total[0], Scenario.RequestSize);
    EXPECT_EQ(Result.Relay.Total[1], Scenario.ResponseSize);
    EXPECT_EQ(Result.Exchange.Request, MakePayload(Scenario.RequestSize, Scenario.RequestValue));
    EXPECT_EQ(Result.Exchange.Response, MakePayload(Scenario.ResponseSize, Scenario.ResponseValue));
}

TEST(TunnelHalfClose, LargeRequestSmallResponse)
{
    const HalfCloseScenario Scenario{
        .RequestSize = 64U * 1024U,
        .ResponseSize = 128U,
        .RequestValue = std::byte{0x33},
        .ResponseValue = std::byte{0x44},
        .Order = HalfCloseOrder::UpstreamThenClient};
    const auto Result = RunHalfCloseScenario(Scenario);

    EXPECT_FALSE(Result.Relay.Failure.Failed());
    EXPECT_EQ(Result.Relay.Total[0], Scenario.RequestSize);
    EXPECT_EQ(Result.Relay.Total[1], Scenario.ResponseSize);
    EXPECT_EQ(Result.Exchange.Request, MakePayload(Scenario.RequestSize, Scenario.RequestValue));
    EXPECT_EQ(Result.Exchange.Response, MakePayload(Scenario.ResponseSize, Scenario.ResponseValue));
}

TEST(TunnelHalfClose, BidirectionalEOF)
{
    const HalfCloseScenario Scenario{
        .RequestSize = 1U,
        .ResponseSize = 1U,
        .RequestValue = std::byte{0x01},
        .ResponseValue = std::byte{0x02},
        .Order = HalfCloseOrder::BothBeforeRelay};
    const auto Result = RunHalfCloseScenario(Scenario);

    EXPECT_FALSE(Result.Relay.Failure.Failed());
    EXPECT_EQ(Result.Relay.Total[0], 1U);
    EXPECT_EQ(Result.Relay.Total[1], 1U);
    EXPECT_EQ(Result.Exchange.Request, MakePayload(1U, std::byte{0x01}));
    EXPECT_EQ(Result.Exchange.Response, MakePayload(1U, std::byte{0x02}));
}

TEST(TunnelHalfClose, IdleTimeoutMidHalfClose)
{
    const HalfCloseScenario Scenario{
        .RequestSize = 10U,
        .RequestValue = std::byte{0x55},
        .IdleTimeout = std::chrono::milliseconds{250}};
    const auto Result = RunHalfCloseScenario(Scenario);

    EXPECT_EQ(Result.Relay.Failure.Code, Prism::Fault::Code::Timeout);
    EXPECT_EQ(Result.Relay.Total[0], Scenario.RequestSize);
    EXPECT_EQ(Result.Relay.Total[1], 0U);
    EXPECT_EQ(Result.Exchange.Request, MakePayload(Scenario.RequestSize, Scenario.RequestValue));
    EXPECT_TRUE(Result.Exchange.Response.empty());
}
