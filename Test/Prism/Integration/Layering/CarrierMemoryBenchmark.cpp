/**
 * @file CarrierMemoryBenchmark.cpp
 * @brief TLS 伪装方案 + 内层代理协议组合测试（联通性 + 数据一致性 + 性能）
 * @details 外层伪装（shadowtls/restls/anytls/trusttunnel/ws/gun/session-id-tool）
 *          内层套 vless/trojan/socks5：验证多层套接的正确性与开销。
 *          每用例：双端握手 → 64MB 传输 → 固定 payload 校验 → 吞吐/延迟。
 * @note Reality 组合仅测 SessionId/record 实验工具，不代表完整 TLS carrier；
 *       MemoryStream 结果不代表 TCP/QUIC 内核、背压或真实网络吞吐。
 */

#include "CarrierBenchmarkWsFactory.hpp"
#include "CarrierBenchResult.hpp"
#include "CarrierMemoryTestSupport.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <exception>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Protocols/Vless/Vless.hpp>
#include <Prism/Protocols/Anytls/Anytls.hpp>
#include <Prism/Protocols/Gun/Gun.hpp>
#include <Test/Experiments/Prism/Reality/Session/SessionIdBenchSupport.hpp>
#include <Prism/Protocols/Restls/Restls.hpp>
#include <Prism/Protocols/Shadowtls/Shadowtls.hpp>
#include <Prism/Protocols/Trusttunnel/Trusttunnel.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Anytls = Prism::Anytls;
    namespace Gun = Prism::Gun;
    namespace Restls = Prism::Restls;
    namespace Shadowtls = Prism::Shadowtls;
    namespace Socks5 = Prism::Socks5;
    namespace Trojan = Prism::Trojan;
    namespace Trusttunnel = Prism::Trusttunnel;
    namespace Vless = Prism::Vless;
    using Prism::Tests::Integration::Layering::CarrierBenchmarkWsFactory;
    using Prism::Tests::Integration::Layering::ToTransportResult;
    using Prism::Tests::Integration::Layering::TransportResult;
    using Prism::BenchOptions;
    using Prism::BenchReport;
    using Prism::BenchPrismThroughput;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::SharedTransmission;

    using Prism::Tests::Integration::Layering::CarrierMemorySupport::CompletionChannel;
    using Prism::Tests::Integration::Layering::CarrierMemorySupport::RunCoroutine;
    using Prism::Tests::Integration::Layering::CarrierMemorySupport::WaitForCompletion;

    struct NestedRunState
    {
        explicit NestedRunState(Net::any_io_executor Executor)
            : ServerCompletion(std::make_shared<CompletionChannel>(Executor, 1)),
              WatchdogCompletion(std::make_shared<CompletionChannel>(Executor, 1)),
              Watchdog(std::make_shared<Net::steady_timer>(Executor))
        {
        }

        SharedTransmission ClientEndpoint;
        SharedTransmission ClientConnection;
        SharedTransmission ServerEndpoint;
        std::shared_ptr<CompletionChannel> ServerCompletion;
        std::shared_ptr<CompletionChannel> WatchdogCompletion;
        std::shared_ptr<Net::steady_timer> Watchdog;
        std::exception_ptr ServerException;
        std::exception_ptr WatchdogException;
        BenchReport Report{};
        bool Linked{false};
        bool Failed{false};
        bool PayloadMismatch{false};
        bool TimedOut{false};
        bool Completed{false};
        bool ClientFin{false};
        bool ServerEof{false};
        bool ClientEof{false};
        bool ServerFin{false};
        bool ClientClosed{false};
        bool ServerClosed{false};
    };

    auto CloseNestedEndpoints(const std::shared_ptr<NestedRunState> &State) -> void
    {
        if (State->ClientEndpoint)
        {
            (void)State->ClientEndpoint->Close();
        }
        if (State->ServerEndpoint)
        {
            (void)State->ServerEndpoint->Close();
        }
    }



    auto MakeDestination() -> Vless::Address
    {
        Vless::Address Destination{};
        Destination.Type = Vless::AddressType::Ipv4;
        Destination.Host = "93.184.216.34";
        Destination.Port = 443;
        return Destination;
    }

    auto MakeUuid() -> std::array<std::uint8_t, Vless::UuidLen>
    {
        std::array<std::uint8_t, Vless::UuidLen> Uuid{};
        Uuid.fill(0x55);
        return Uuid;
    }

    auto MakeRandom32() -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> Random{};
        for (std::size_t Index = 0; Index < Random.size(); ++Index)
        {
            Random[Index] = static_cast<std::uint8_t>(Index * 3 + 1);
        }
        return Random;
    }

    template <typename Factory>
    struct NestedRunRequest final
    {
        Net::io_context &IoContext;
        Factory FactoryValue;
        std::shared_ptr<NestedRunState> State;
        const char *Name;
    };

    auto RunNestedWatchdog(const std::shared_ptr<NestedRunState> &State)
        -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        co_await State->Watchdog->async_wait(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode == Net::error::operation_aborted)
        {
            co_return;
        }
        if (ErrorCode)
        {
            State->WatchdogException = std::make_exception_ptr(
                std::system_error(ErrorCode));
            co_return;
        }
        if (!State->Completed)
        {
            State->TimedOut = true;
            State->Failed = true;
            CloseNestedEndpoints(State);
        }
    }

    auto CompleteNestedWatchdog(
        const std::shared_ptr<NestedRunState> &State,
        std::exception_ptr Exception) -> void
    {
        if (Exception)
        {
            State->WatchdogException = std::move(Exception);
            State->Failed = true;
            CloseNestedEndpoints(State);
        }
        (void)State->WatchdogCompletion->try_send(
            boost::system::error_code{});
    }

    template <typename Factory>
    auto RunNestedServer(NestedRunRequest<Factory> Request) -> Net::awaitable<void>
    {
        constexpr std::size_t TotalBytes = 64 * 1024 * 1024;
        auto State = Request.State;
        auto ServerResult = co_await Request.FactoryValue.ServerAccept(
            State->ServerEndpoint);
        if (!ServerResult)
        {
            State->Failed = true;
            EXPECT_TRUE(false)
                << Request.Name << ": stealth Accept Failed err="
                << static_cast<int>(ServerResult.error().Code);
            CloseNestedEndpoints(State);
            co_return;
        }
        if (!*ServerResult)
        {
            State->Failed = true;
            EXPECT_TRUE(*ServerResult);
            CloseNestedEndpoints(State);
            co_return;
        }
        auto ServerConnection = std::move(*ServerResult);
        auto InnerResult = co_await Vless::Accept(
            std::move(ServerConnection), Vless::ServerConfig{MakeUuid()});
        const auto ExpectedTarget = MakeDestination();
        if (!InnerResult)
        {
            State->Failed = true;
            EXPECT_TRUE(false) << Request.Name << ": vless Accept Failed code="
                               << static_cast<int>(InnerResult.error().Code);
            CloseNestedEndpoints(State);
            co_return;
        }
        if (!InnerResult->Connection)
        {
            State->Failed = true;
            EXPECT_TRUE(InnerResult->Connection);
            CloseNestedEndpoints(State);
            co_return;
        }
        auto RequestValue = std::move(InnerResult->Request);
        auto ServerConnectionValue = std::move(InnerResult->Connection);
        if (RequestValue.Target.Host != ExpectedTarget.Host ||
            RequestValue.Target.Port != ExpectedTarget.Port)
        {
            State->Failed = true;
            EXPECT_TRUE(false) << Request.Name << ": VLESS target mismatch";
            CloseNestedEndpoints(State);
            co_return;
        }
        State->Linked = true;
        std::array<std::byte, 128 * 1024> Buffer{};
        std::size_t Received = 0;
        while (true)
        {
            const auto Read = co_await ServerConnectionValue->ReadSome(Buffer);
            if (Read.Bytes > Buffer.size()) { State->Failed = true; break; }
            const auto Count = Read.Bytes;
            if (Count > 0)
            {
                Received += Count;
                if (Received > TotalBytes) { State->Failed = true; break; }
                for (std::size_t Index = 0; Index < Count; ++Index)
                {
                    if (Buffer[Index] != std::byte{0x5a})
                    { State->PayloadMismatch = true; State->Failed = true; break; }
                }
                if (State->Failed) break;
                std::size_t Offset = 0;
                while (Offset < Count)
                {
                    const auto WriteWindow = std::span<const std::byte>(Buffer).subspan(
                        Offset, Count - Offset);
                    const auto Write = co_await ServerConnectionValue->WriteSome(WriteWindow);
                    if (Write.Bytes > WriteWindow.size()) { State->Failed = true; break; }
                    Offset += Write.Bytes;
                    if (Write.Failure.Failed() || Write.Bytes == 0) { State->Failed = true; break; }
                }
            }
            if (State->Failed) break;
            if (Read.Failure.Code == Prism::Fault::Code::Eof)
            {
                State->ServerEof = Received == TotalBytes;
                if (!State->ServerEof) State->Failed = true;
                break;
            }
            if (Read.Failure.Failed() || Count == 0) { State->Failed = true; break; }
        }
        if (State->ServerEof && !State->Failed)
        {
            const auto ShutdownResult = co_await ServerConnectionValue->WriteShutdown();
            EXPECT_TRUE(ShutdownResult);
            State->ServerFin = ShutdownResult.has_value();
            if (!ShutdownResult) State->Failed = true;
        }
        const auto CloseResult = ServerConnectionValue->Close();
        EXPECT_TRUE(CloseResult);
        if (CloseResult)
        {
            const auto DrainResult = co_await ServerConnectionValue->Activity()->Drain();
            EXPECT_TRUE(DrainResult);
            State->ServerClosed = DrainResult.has_value();
            if (!DrainResult) State->Failed = true;
        }
        else State->Failed = true;
    }

    auto CompleteNestedServer(
        const std::shared_ptr<NestedRunState> &State,
        std::exception_ptr Exception) -> void
    {
        if (Exception)
        {
            State->ServerException = std::move(Exception);
            State->Failed = true;
            CloseNestedEndpoints(State);
        }
        (void)State->ServerCompletion->try_send(
            boost::system::error_code{});
    }

    auto CloseNestedClient(
        SharedTransmission ConnectionValue,
        std::shared_ptr<NestedRunState> State)
        -> Net::awaitable<bool>
    {
        const auto CloseOutcome = ConnectionValue->Close();
        if (!CloseOutcome) { State->Failed = true; co_return false; }
        const auto DrainOutcome = co_await ConnectionValue->Activity()->Drain();
        State->ClientClosed = DrainOutcome.has_value();
        if (!State->ClientClosed) State->Failed = true;
        co_return State->ClientClosed;
    }

    auto FinalizeNestedRun(const std::shared_ptr<NestedRunState> &State)
        -> Net::awaitable<void>
    {
        if (State->ClientConnection)
        {
            const auto Closed = co_await CloseNestedClient(
                State->ClientConnection, State);
            EXPECT_TRUE(Closed);
            if (Closed)
            {
                EXPECT_TRUE(State->ClientClosed);
            }
        }
        State->Completed = true;
        CloseNestedEndpoints(State);
        State->Watchdog->cancel();
        co_await WaitForCompletion(State->ServerCompletion);
        co_await WaitForCompletion(State->WatchdogCompletion);
        if (State->ServerException)
        {
            std::rethrow_exception(State->ServerException);
        }
        if (State->WatchdogException)
        {
            std::rethrow_exception(State->WatchdogException);
        }
    }

    template <typename Factory>
    auto RunNestedClient(NestedRunRequest<Factory> Request) -> Net::awaitable<void>
    {
        constexpr std::size_t TotalBytes = 64 * 1024 * 1024;
        constexpr std::size_t BlockBytes = 64 * 1024;
        auto State = Request.State;
        Net::co_spawn(
            Request.IoContext,
            RunNestedServer(Request),
            [State](std::exception_ptr Exception)
            { CompleteNestedServer(State, std::move(Exception)); });
        auto ClientResult = co_await Request.FactoryValue.ClientConnect(
            State->ClientEndpoint);
        if (!ClientResult)
        {
            State->Failed = true;
            EXPECT_TRUE(false)
                << Request.Name << ": stealth Connect Failed err="
                << static_cast<int>(ClientResult.error().Code);
            co_await FinalizeNestedRun(State);
            co_return;
        }
        auto ClientConnection = std::move(*ClientResult);
        auto InnerResult = co_await Vless::Connect(Vless::ConnectParameters{
            std::move(ClientConnection), Vless::ClientConfig{MakeUuid()}, MakeDestination()});
        if (!InnerResult)
        {
            State->Failed = true;
            EXPECT_TRUE(false)
                << Request.Name << ": vless Connect Failed err="
                << static_cast<int>(InnerResult.error().Code);
            co_await FinalizeNestedRun(State);
            co_return;
        }
        auto ClientConnectionValue = std::move(*InnerResult);
        State->ClientConnection = ClientConnectionValue;
        BenchOptions BenchValue;
        BenchValue.Total = TotalBytes;
        BenchValue.Block = BlockBytes;
        Prism::PrismBenchResult BenchResult;
        std::exception_ptr BenchException;
        try
        {
            BenchResult = co_await BenchPrismThroughput(
                *ClientConnectionValue, *ClientConnectionValue, BenchValue);
        }
        catch (...)
        {
            BenchException = std::current_exception();
        }
        if (BenchException)
        {
            State->Failed = true;
            co_await FinalizeNestedRun(State);
            std::rethrow_exception(BenchException);
        }
        EXPECT_TRUE(BenchResult.Failure.Succeeded())
            << "已写入字节=" << BenchResult.BytesWritten
            << " 已回读字节=" << BenchResult.BytesRead;
        if (!BenchResult.Failure.Succeeded())
        {
            State->Failed = true;
            co_await FinalizeNestedRun(State);
            co_return;
        }
        State->Report = BenchResult.Report;
        if (State->Report.Bytes != TotalBytes) State->Failed = true;
        const auto ShutdownResult = co_await ClientConnectionValue->WriteShutdown();
        EXPECT_TRUE(ShutdownResult);
        if (ShutdownResult)
        {
            State->ClientFin = true;
            std::array<std::byte, 1> Drain{};
            const auto Read = co_await ClientConnectionValue->ReadSome(Drain);
            State->ClientEof =
                Read.Bytes == 0 && Read.Failure.Code == Prism::Fault::Code::Eof;
            if (!State->ClientEof)
            {
                State->Failed = true;
            }
        }
        else
        {
            State->Failed = true;
        }
        co_await FinalizeNestedRun(State);
    }

    /**
     * @brief 组合测试运行器：伪装层套 VLESS，保持内存管道和协议输入不变。
     */
    template <typename Factory>
    auto RunNestedVless(Net::io_context &IoContext, Factory FactoryValue, const char *Name) -> void
    {
        constexpr std::size_t TotalBytes = 64 * 1024 * 1024;
        auto State = std::make_shared<NestedRunState>(IoContext.get_executor());
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        State->ClientEndpoint = std::make_shared<MemoryStream>(std::move(ClientMemory));
        State->ServerEndpoint = std::make_shared<MemoryStream>(std::move(ServerMemory));
        State->Watchdog->expires_after(std::chrono::seconds(10));
        Net::co_spawn(
            IoContext,
            RunNestedWatchdog(State),
            [State](std::exception_ptr Exception)
            { CompleteNestedWatchdog(State, std::move(Exception)); });
        RunCoroutine(IoContext, RunNestedClient(
            NestedRunRequest<Factory>{IoContext, std::move(FactoryValue), State, Name}));
        EXPECT_FALSE(State->TimedOut) << Name << ": watchdog timeout";
        EXPECT_TRUE(State->Completed) << Name << ": lifecycle did not complete";
        if (!State->Failed)
        {
            EXPECT_TRUE(State->Linked) << Name << ": 双层握手联通失败";
            EXPECT_EQ(State->Report.Bytes, TotalBytes) << Name << ": 传输字节数不一致";
            EXPECT_FALSE(State->PayloadMismatch) << Name << ": payload 内容不一致";
            EXPECT_TRUE(State->ServerEof) << Name << ": server 未观察到 client FIN";
            EXPECT_TRUE(State->ClientEof) << Name << ": client 未观察到 server FIN";
            EXPECT_TRUE(State->ClientFin) << Name << ": client 未发送 FIN";
            EXPECT_TRUE(State->ServerFin) << Name << ": server 未发送 FIN";
            EXPECT_TRUE(State->ClientClosed) << Name << ": client 未最终 Close";
            EXPECT_TRUE(State->ServerClosed) << Name << ": server 未最终 Close";
        }
        const char *Status = State->Linked && !State->Failed ? "OK" : "FAIL";
        std::printf("%-12s 联通=%s  Bytes=%zu(期望 %zu)  吞吐=%.1f MB/s  延迟(ms) avg=%.3f p50=%.3f p95=%.3f "
                    "p99=%.3f\n",
                    Name, Status, State->Report.Bytes, TotalBytes, State->Report.Mbps,
                    State->Report.LatencyAvg, State->Report.LatencyP50,
                    State->Report.LatencyP95, State->Report.LatencyP99);
    }

    // ---------- 各伪装层工厂 ----------

    struct ShadowtlsFactory
    {
        auto ClientConnect(SharedTransmission Upstream)
            -> Net::awaitable<TransportResult>
        {
            const auto ServerRandom = MakeRandom32();
            const auto ClientRandom = MakeRandom32();
            auto [ErrorCode, Connection] = co_await Shadowtls::Connect(
                {std::move(Upstream), Shadowtls::ClientConfig{"st_password"}, ServerRandom, ClientRandom});
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }
        auto ServerAccept(SharedTransmission Upstream)
            -> Net::awaitable<TransportResult>
        {
            auto [ErrorCode, Connection] = co_await Shadowtls::Accept(
                std::move(Upstream),
                Shadowtls::ServerConfig{"st_password"});
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }
    };

    struct RestlsFactory
    {
        auto ClientConnect(SharedTransmission Upstream)
            -> Net::awaitable<TransportResult>
        {
            const auto ServerRandom = MakeRandom32();
            auto Connection = co_await Restls::Connect(
                std::move(Upstream),
                Restls::ClientConfig{"rs_password"},
                ServerRandom);
            co_return ToTransportResult(std::move(Connection));
        }
        auto ServerAccept(SharedTransmission Upstream)
            -> Net::awaitable<TransportResult>
        {
            const auto ServerRandom = MakeRandom32();
            auto Connection = co_await Restls::Accept(
                std::move(Upstream),
                Restls::ServerConfig{"rs_password"},
                ServerRandom);
            co_return ToTransportResult(std::move(Connection));
        }
    };

    struct AnytlsFactory
    {
        auto ClientConnect(SharedTransmission Upstream)
            -> Net::awaitable<TransportResult>
        {
            auto [ErrorCode, Connection] = co_await Anytls::Connect(
                std::move(Upstream),
                Anytls::ClientConfig{"at_password"});
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }
        auto ServerAccept(SharedTransmission Upstream)
            -> Net::awaitable<TransportResult>
        {
            auto [ErrorCode, Connection] = co_await Anytls::Accept(
                std::move(Upstream),
                Anytls::ServerConfig{"at_password"});
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }
    };

    struct TrusttunnelFactory
    {
        auto ClientConnect(SharedTransmission Upstream)
            -> Net::awaitable<TransportResult>
        {
            auto [ErrorCode, Connection] = co_await Trusttunnel::Connect(
                {std::move(Upstream), Trusttunnel::ClientConfig{"tu_user", "tu_pass"}, "example.com", 443});
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }
        auto ServerAccept(SharedTransmission Upstream)
            -> Net::awaitable<TransportResult>
        {
            auto [ErrorCode, Target, Connection] = co_await Trusttunnel::Accept(
                std::move(Upstream),
                Trusttunnel::ServerConfig{"tu_user", "tu_pass"});
            (void)Target;
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }
    };


    struct GunFactory
    {
        auto ClientConnect(SharedTransmission Upstream)
            -> Net::awaitable<TransportResult>
        {
            auto [ErrorCode, Connection] = co_await Gun::Connect(
                std::move(Upstream), "example.com");
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }
        auto ServerAccept(SharedTransmission Upstream)
            -> Net::awaitable<TransportResult>
        {
            auto [ErrorCode, Host, Connection] = co_await Gun::Accept(
                std::move(Upstream));
            (void)Host;
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }
    };

    struct SessionIdToolFactory
        : Prism::Tests::Experiments::Reality::SessionIdToolBenchmarkFactory
    {
        SessionIdToolFactory()
            : Prism::Tests::Experiments::Reality::SessionIdToolBenchmarkFactory(
              [](Prism::Error ErrorCode, std::string_view)
              {
                  EXPECT_FALSE(ErrorCode);
              })
        {
        }
    };

    // ---------- 测试用例 ----------

    TEST(StealthNested, ShadowTlsVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, ShadowtlsFactory{}, "shadowtls");
    }

    TEST(StealthNested, RestlsVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, RestlsFactory{}, "restls");
    }

    TEST(StealthNested, AnyTlsVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, AnytlsFactory{}, "anytls");
    }

    TEST(StealthNested, TrustTunnelVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, TrusttunnelFactory{}, "trusttunnel");
    }

    TEST(StealthNested, WsVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, CarrierBenchmarkWsFactory{}, "ws");
    }

    TEST(StealthNested, GunVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, GunFactory{}, "gun");
    }

    TEST(StealthNested, SessionIdToolVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, SessionIdToolFactory{}, "session-id-tool");
    }

} // namespace
