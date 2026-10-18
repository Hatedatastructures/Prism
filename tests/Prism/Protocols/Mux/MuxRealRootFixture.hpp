#pragma once

/**
 * @file MuxRealRootFixture.hpp
 * @brief 真实 Mux Root 64MiB 请求、认证、后端和生命周期共享 fixture。
 * @details 由矩阵与失败收口测试共同消费，保留真实 listener、lease、drain、quota
 *          和诊断阶段；本头不承载 TEST 宏。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <malloc.h>
#include <psapi.h>
#endif

#include <TestSupport/Benchmark/Bench.hpp>
#include <TestSupport/Fixtures/MuxRoot.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include "MuxStreamAcceptInputTestSupport.hpp"
#include "MuxRealRootProcessMetrics.hpp"
#include "MuxRealRootWorkload.hpp"
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Mux/H2Mux/H2Mux.hpp>
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <Prism/Protocols/Mux/Yamux/Yamux.hpp>
#include <gtest/gtest.h>

#include "MuxPerfAllocation.hpp"

namespace Prism::Testing::MuxRealRoot
{
    namespace Net = boost::asio;
    namespace RootFixture = Prism::Testing::MuxRoot;
    namespace Smux = Prism::Mux::Smux;
    namespace Yamux = Prism::Mux::Yamux;
    using Tcp = Net::ip::tcp;
    using Code = Prism::Fault::Code;
    using Signal = Net::experimental::channel<void(boost::system::error_code)>;


    class RealRootEgress;

    enum class RealRootMode
    {
        Smux,
        Yamux,
        H2Mux,
    };

    enum class RealDiagnosticStage : std::uint32_t
    {
        Connect = 1U << 0U,
        Authenticate = 1U << 1U,
        Open = 1U << 2U,
        Literal = 1U << 3U,
        MeasureReady = 1U << 4U,
        MeasureGo = 1U << 5U,
        TransferComplete = 1U << 6U,
        RootFinished = 1U << 7U,
        Drained = 1U << 8U,
        ThreadJoined = 1U << 9U,
        WeakExpired = 1U << 10U,
        QuotaZero = 1U << 11U,
    };

    enum class RealMeasureTerminal : std::uint8_t
    {
        Pending,
        Complete,
        Failed,
    };

    enum class RealMatrixFailurePoint : std::uint8_t
    {
        None,
        BeforeReady,
        Start,
        Transfer,
        End,
        Close,
        ThreadCreation,
    };

    inline auto RealRootModeName(RealRootMode Mode) -> std::string_view;

    struct RealRootState final
    {
        explicit RealRootState(const RealRootMode ModeValue, Net::any_io_executor ExecutorValue)
            : Mode(ModeValue), Harness(std::make_shared<RootFixture::State>(ExecutorValue)), BackendDone(ExecutorValue, 1),
              RootDone(ExecutorValue, 1), MeasureGo(ExecutorValue, 1), MeasureEnd(ExecutorValue, 1),
              DrainStarted(ExecutorValue, 1)
        {
            Peer = std::make_shared<RootFixture::Peer>(ExecutorValue);
            Harness->Peers.push_back(Peer);
        }

        RealRootMode Mode;
        std::shared_ptr<RootFixture::State> Harness;
        std::shared_ptr<RootFixture::Peer> Peer;
        Signal BackendDone;
        Signal RootDone;
        Signal MeasureGo;
        Signal MeasureEnd;
        Signal DrainStarted;
        Prism::BenchReport Report{};
        std::exception_ptr Failure;
        std::string FailureMessage;
        std::size_t BackendBytes{0};
        std::uint64_t BackendHash{14695981039346656037ULL};
        std::uint64_t ExpectedHash{14695981039346656037ULL};
        bool LiteralValid{false};
        bool Authenticated{false};
        bool BackendPeerClosed{false};
        bool ClientPeerClosed{false};
        bool RootFinished{false};
        bool Drained{false};
        bool WeakExpired{false};
        bool QuotaZero{false};
        std::size_t Dials{0};
        std::size_t FirstConnections{0};
        std::size_t FirstStreams{0};
        std::size_t OrdinaryCalls{0};
        std::size_t OrdinaryBytes{0};
        std::size_t AlignedCalls{0};
        std::size_t AlignedBytes{0};
        std::shared_ptr<RealMeasureWindow> Window;
        std::atomic<bool> ReadyClaimed{false};
        std::atomic<bool> MeasureReady{false};
        std::atomic<RealMeasureTerminal> MeasureTerminal{RealMeasureTerminal::Pending};
        std::atomic<bool> ScenarioCompleted{false};
        std::atomic<bool> Exited{false};
        bool InvalidPassword{false};
        bool Diagnostic{false};
        std::size_t DiagnosticRound{0};
        std::size_t DiagnosticLane{0};
        std::atomic<std::uint32_t> DiagnosticStages{0};
        RealMatrixFailurePoint FailurePoint{RealMatrixFailurePoint::None};
    };

    inline auto ClaimRealMeasureReady(const std::shared_ptr<RealRootState> &State) -> bool
    {
        if (!State->Window)
        {
            return true;
        }
        bool Expected = false;
        if (!State->ReadyClaimed.compare_exchange_strong(
                Expected, true, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return false;
        }
        State->MeasureReady.store(true, std::memory_order_release);
        State->Window->Ready.fetch_add(1U, std::memory_order_acq_rel);
        State->Window->ReadyOrFailed.fetch_add(1U, std::memory_order_acq_rel);
        NotifyRealMeasureWindow(State->Window);
        return true;
    }

    inline auto ClaimRealMeasureFailureReadiness(const std::shared_ptr<RealRootState> &State) -> bool
    {
        if (!State->Window)
        {
            return true;
        }
        bool Expected = false;
        if (!State->ReadyClaimed.compare_exchange_strong(
                Expected, true, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return false;
        }
        State->Window->ReadyOrFailed.fetch_add(1U, std::memory_order_acq_rel);
        NotifyRealMeasureWindow(State->Window);
        return true;
    }

    inline auto ClaimRealMeasureTerminal(const std::shared_ptr<RealRootState> &State,
                                         const RealMeasureTerminal Terminal) -> bool
    {
        if (!State->Window)
        {
            return true;
        }
        auto Expected = RealMeasureTerminal::Pending;
        if (!State->MeasureTerminal.compare_exchange_strong(
                Expected, Terminal, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return false;
        }
        if (Terminal == RealMeasureTerminal::Complete)
        {
            State->Window->MeasureCompleted.fetch_add(1U, std::memory_order_acq_rel);
        }
        else
        {
            State->Window->MeasureFailed.fetch_add(1U, std::memory_order_acq_rel);
        }
        NotifyRealMeasureWindow(State->Window);
        return true;
    }

    [[nodiscard]] constexpr auto RealDiagnosticStageBit(const RealDiagnosticStage Stage) noexcept
        -> std::uint32_t
    {
        return static_cast<std::uint32_t>(Stage);
    }

    [[nodiscard]] inline auto RealDiagnosticStageName(const RealDiagnosticStage Stage) noexcept
        -> std::string_view
    {
        switch (Stage)
        {
        case RealDiagnosticStage::Connect: return "connect";
        case RealDiagnosticStage::Authenticate: return "auth";
        case RealDiagnosticStage::Open: return "open";
        case RealDiagnosticStage::Literal: return "literal";
        case RealDiagnosticStage::MeasureReady: return "measure-ready";
        case RealDiagnosticStage::MeasureGo: return "measure-go";
        case RealDiagnosticStage::TransferComplete: return "transfer-complete";
        case RealDiagnosticStage::RootFinished: return "root-finished";
        case RealDiagnosticStage::Drained: return "drain";
        case RealDiagnosticStage::ThreadJoined: return "thread-joined";
        case RealDiagnosticStage::WeakExpired: return "weak-expired";
        case RealDiagnosticStage::QuotaZero: return "quota-zero";
        }
        return "unknown";
    }

    inline auto MarkRealDiagnosticStage(const std::shared_ptr<RealRootState> &State,
                                 const RealDiagnosticStage Stage) -> void
    {
        if (!State->Diagnostic)
        {
            return;
        }
        const auto Bit = RealDiagnosticStageBit(Stage);
        const auto Previous = State->DiagnosticStages.fetch_or(Bit, std::memory_order_acq_rel);
        if ((Previous & Bit) != 0U)
        {
            return;
        }
        const auto Mode = RealRootModeName(State->Mode);
        const auto Name = RealDiagnosticStageName(Stage);
        std::printf("real-root-matrix diagnostic-only=1 mode=%.*s round=%zu lane=%zu stage=%.*s\n",
                    static_cast<int>(Mode.size()), Mode.data(), State->DiagnosticRound,
                    State->DiagnosticLane, static_cast<int>(Name.size()), Name.data());
        std::fflush(stdout);
    }

    struct RealH2Context final
    {
        std::shared_ptr<RealRootState> State;
        std::shared_ptr<Prism::Http2::Session> Session;
        std::int32_t StreamId{0};
        std::vector<std::byte> Received;
        bool StreamClosed{false};
        std::uint32_t StreamError{0};
    };

    class RealRootEgress final : public Prism::Contract::StreamEgress
    {
    public:
        explicit RealRootEgress(std::weak_ptr<RealRootState> State) : State_(std::move(State)) {}

        inline auto Connect(Prism::Network::Target Target)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>> override
        {
            const auto State = State_.lock();
            if (!State)
            {
                co_return std::unexpected(Prism::Fault::Failure{Code::Canceled});
            }
            ++State->Dials;
            Tcp::socket Socket(co_await Net::this_coro::executor);
            boost::system::error_code Error;
            co_await Socket.async_connect(
                Tcp::endpoint(*Prism::Network::IpAddress(Target.Host),
                    Target.Port),
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return std::unexpected(Prism::Fault::Failure{
                    Code::Unreachable, static_cast<std::error_code>(Error)});
            }
            co_return Prism::SharedTransmission{
                std::make_shared<Prism::Transport::Reliable>(std::move(Socket))};
        }

    private:
        std::weak_ptr<RealRootState> State_;
    };

    [[nodiscard]] inline auto MakeRealRootState(const RealRootMode Mode, const Net::any_io_executor Executor)
        -> std::shared_ptr<RealRootState>
    {
        auto State = std::make_shared<RealRootState>(Mode, Executor);
        const auto Wire = Mode == RealRootMode::Smux ? Prism::Mux::Mode::Smux
            : Mode == RealRootMode::Yamux ? Prism::Mux::Mode::Yamux : Prism::Mux::Mode::H2Mux;
        State->Harness->Binding = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{
            .Wire = Wire, .Services = {.Egress = std::make_shared<RealRootEgress>(State)},
            .GenerationUseState = State->Harness->UseState});
        return State;
    }

    inline auto InjectRealFailure(const std::shared_ptr<RealRootState> &State,
                                  const std::string_view Message,
                                  const bool CancelOperations) -> void;

    inline auto CancelRealState(const std::shared_ptr<RealRootState> &State,
                                const std::string_view Message) -> void;

    inline auto UpdateRealHash(std::uint64_t &Hash, std::span<const std::byte> Bytes) -> void
    {
        for (const auto Byte : Bytes)
        {
            Hash ^= std::to_integer<std::uint8_t>(Byte);
            Hash *= 1099511628211ULL;
        }
    }

    [[nodiscard]] inline auto RealTargetRequest(const std::uint16_t Port) -> std::vector<std::byte>
    {
        return {std::byte{0}, std::byte{0}, std::byte{1}, std::byte{127}, std::byte{0},
            std::byte{0}, std::byte{1}, std::byte{static_cast<std::uint8_t>(Port >> 8U)},
            std::byte{static_cast<std::uint8_t>(Port)}};
    }

    inline auto RunRealRoot(std::shared_ptr<RealRootState> State) -> Net::awaitable<void>
    {
        struct Completion final
        {
            std::shared_ptr<RealRootState> State;
            ~Completion()
            {
                if (!State->Authenticated) (void)State->Peer->Ready.try_send(boost::system::error_code{});
                (void)State->RootDone.try_send(boost::system::error_code{});
            }
        } Done{State};
        try
        {
            Prism::Trojan::ServerConfig Configuration;
            Configuration.AuthenticatorOwner =
                std::make_shared<Prism::DirectoryAuthenticator>(State->Harness->Accounts);
            Prism::Trojan::IngressFactory Factory({.Configuration = std::move(Configuration),
                .Mux = State->Harness->Binding});
            auto Plane = co_await Factory.Accept(
                Prism::Testing::MuxStreamAcceptInputTestSupport::MakeRealRootAcceptInput(
                    std::move(State->Peer->Server), std::move(State->Peer->Metadata)));
            if (!Plane || !Plane->Mux() || !Plane->Mux()->Session)
            {
                State->FailureMessage = "real root did not publish mux plane";
                State->Harness->Stop();
                co_return;
            }
            State->Peer->Server = Plane->Transport();
            State->Peer->Authenticated = bool(Plane->AccountLease);
            State->Authenticated = State->Peer->Authenticated;
            State->Peer->Root = Plane->Mux()->Session;
            State->Peer->WeakRoot = State->Peer->Root;
            if (State->FailurePoint == RealMatrixFailurePoint::BeforeReady)
            {
                State->Peer->Authenticated = false;
                State->Authenticated = false;
                State->Peer->Root.reset();
                (void)State->Peer->Ready.try_send(boost::system::error_code{});
                InjectRealFailure(State, "real root before-ready failure injection", true);
                co_return;
            }
            (void)State->Peer->Ready.try_send(boost::system::error_code{});
            Prism::Contract::MuxRootRequest Request;
            Request.Lease = std::move(Plane->AccountLease);
            Request.Metadata.TaskIdentity.SessionId = Prism::SessionId{7010};
            Request.Metadata.TaskIdentity.WorkerId = Prism::WorkerId{70};
            Request.Metadata.TaskIdentity.Generation = Prism::GenerationId{7};
            Request.GenerationUseState = State->Harness->UseState;
            State->Peer->Status = co_await State->Peer->Root->Run(std::move(Request));
            EXPECT_EQ(State->Harness->UseState->Outstanding(), 0U);
            State->Peer->Root.reset();
            State->RootFinished = true;
            MarkRealDiagnosticStage(State, RealDiagnosticStage::RootFinished);
        }
        catch (...)
        {
            State->Failure = std::current_exception();
            State->Harness->Stop();
        }
    }

    inline auto RunRealBackend(std::shared_ptr<RealRootState> State) -> Net::awaitable<void>
    {
        struct Completion final
        {
            std::shared_ptr<RealRootState> State;
            ~Completion()
            {
                if (!State->FailureMessage.empty()) State->Harness->Stop();
                (void)State->BackendDone.try_send(boost::system::error_code{});
            }
        } Done{State};
        try
        {
            auto Socket = std::make_shared<Tcp::socket>(State->Harness->Executor);
            boost::system::error_code Error;
            co_await State->Harness->Acceptor.async_accept(
                *Socket, Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                State->FailureMessage = "real benchmark backend accept failed";
                co_return;
            }
            State->Harness->Sockets.push_back(Socket);
            std::vector<std::byte> Literal(RealLiteral.size());
            const auto LiteralCount = co_await Net::async_read(
                *Socket, Net::buffer(Literal), Net::redirect_error(Net::use_awaitable, Error));
            const auto ExpectedLiteral = std::as_bytes(std::span(RealLiteral));
            State->LiteralValid = !Error && LiteralCount == Literal.size() &&
                std::equal(Literal.begin(), Literal.end(), ExpectedLiteral.begin(), ExpectedLiteral.end());
            if (!State->LiteralValid)
            {
                State->FailureMessage = "real benchmark literal request mismatch";
                co_return;
            }
            State->BackendBytes += LiteralCount;
            UpdateRealHash(State->BackendHash, Literal);
            co_await Net::async_write(*Socket, Net::buffer(Literal), Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                State->FailureMessage = "real benchmark literal echo failed";
                co_return;
            }
            std::array<std::byte, RealBlockBytes> Buffer{};
            while (State->BackendBytes < RealTotalBytes + RealLiteral.size())
            {
                const auto Count = co_await Socket->async_read_some(
                    Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, Error));
                if (Error || Count == 0U)
                {
                    break;
                }
                State->BackendBytes += Count;
                UpdateRealHash(State->BackendHash, std::span(Buffer).first(Count));
                co_await Net::async_write(*Socket, Net::buffer(Buffer.data(), Count),
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    break;
                }
            }
            std::array<std::byte, 1> Tail{};
            const auto TailCount = co_await Socket->async_read_some(
                Net::buffer(Tail), Net::redirect_error(Net::use_awaitable, Error));
            State->BackendPeerClosed = TailCount == 0U && Error == Net::error::eof;
            Socket->close(Error);
        }
        catch (...)
        {
            State->Failure = std::current_exception();
            State->Harness->Stop();
        }
    }

    inline auto AuthenticateRealRoot(const std::shared_ptr<RealRootState> &State) -> Net::awaitable<bool>
    {
        const auto Password = State->InvalidPassword
            ? std::string_view{"wrong-task4-consumer-password"}
            : RootFixture::Password;
        const auto Auth = Prism::Trojan::BuildRequest(
            Prism::Trojan::Credential(Password), Prism::Trojan::Command::Mux,
            {Prism::Trojan::AddressType::Domain, "root.test", 443});
        std::error_code Error;
        co_await State->Peer->Client->AsyncWrite(std::as_bytes(std::span(Auth)), Error);
        if (Error)
        {
            State->FailureMessage = "real root auth write failed";
            co_return false;
        }
        boost::system::error_code ReadyError;
        co_await State->Peer->Ready.async_receive(Net::redirect_error(Net::use_awaitable, ReadyError));
        if (ReadyError || !State->Peer->Authenticated)
        {
            State->FailureMessage = "real root auth did not complete";
            co_return false;
        }
        co_return true;
    }

    inline auto WriteRealLiteralRequest(
        const std::shared_ptr<RealRootState> &State,
        const Prism::SharedTransmission &Stream) -> Net::awaitable<bool>
    {
        auto Request = RealTargetRequest(State->Harness->Acceptor.local_endpoint().port());
        const auto Literal = std::as_bytes(std::span(RealLiteral));
        Request.insert(Request.end(), Literal.begin(), Literal.end());
        std::error_code Error;
        co_await Stream->AsyncWrite(Request, Error);
        if (Error)
        {
            State->FailureMessage = "real root literal request write failed";
            co_return false;
        }
        std::vector<std::byte> Reply(RealLiteral.size() + 1U);
        co_await Stream->AsyncRead(Reply, Error);
        if (Error || Reply.front() != std::byte{0} ||
            !std::equal(Reply.begin() + 1, Reply.end(), Literal.begin(), Literal.end()))
        {
            State->FailureMessage = "real root literal response was invalid";
            co_return false;
        }
        State->LiteralValid = true;
        State->FirstConnections = State->Harness->Record->Runtime()->ActiveConnections();
        State->FirstStreams = State->Harness->Record->Runtime()->ActiveStreams();
        co_return true;
    }

    inline auto RecordRealReportAllocations(const std::shared_ptr<RealRootState> &State) -> void
    {
        State->OrdinaryCalls = PrismMuxPerfAllocation::OrdinaryCalls.load(std::memory_order_relaxed);
        State->OrdinaryBytes = PrismMuxPerfAllocation::OrdinaryBytes.load(std::memory_order_relaxed);
        State->AlignedCalls = PrismMuxPerfAllocation::AlignedCalls.load(std::memory_order_relaxed);
        State->AlignedBytes = PrismMuxPerfAllocation::AlignedBytes.load(std::memory_order_relaxed);
    }

    enum class RealGate : std::uint8_t
    {
        Start,
        End,
    };

    struct RealGatePost final
    {
        std::shared_ptr<RealRootState> State;
        RealGate Gate;

        inline auto operator()() const -> void
        {
            const auto Sent = Gate == RealGate::Start
                ? State->MeasureGo.try_send(boost::system::error_code{})
                : State->MeasureEnd.try_send(boost::system::error_code{});
            if (!Sent && State->FailureMessage.empty())
            {
                State->FailureMessage = Gate == RealGate::Start
                    ? "real matrix start gate delivery failed"
                    : "real matrix end gate delivery failed";
            }
        }
    };

    inline auto PostRealGate(const std::shared_ptr<RealRootState> &State, const RealGate Gate) -> void
    {
        Net::post(State->Peer->Client->Executor(), RealGatePost{State, Gate});
    }

    inline auto MarkRealMeasureFailure(const std::shared_ptr<RealRootState> &State) -> void;

    inline auto AwaitRealMeasureStart(const std::shared_ptr<RealRootState> &State)
        -> Net::awaitable<bool>
    {
        if (!State->Window)
        {
            co_return true;
        }
        (void)ClaimRealMeasureReady(State);
        MarkRealDiagnosticStage(State, RealDiagnosticStage::MeasureReady);
        if (State->FailurePoint == RealMatrixFailurePoint::Start)
        {
            InjectRealFailure(State, "real root start-gate failure injection", true);
            co_return false;
        }
        boost::system::error_code Error;
        co_await State->MeasureGo.async_receive(Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            State->FailureMessage = "real matrix start gate receive failed";
            MarkRealMeasureFailure(State);
            co_return false;
        }
        MarkRealDiagnosticStage(State, RealDiagnosticStage::MeasureGo);
        co_return true;
    }

    inline auto AwaitRealMeasureEnd(const std::shared_ptr<RealRootState> &State)
        -> Net::awaitable<bool>
    {
        if (!State->Window)
        {
            co_return true;
        }
        boost::system::error_code Error;
        co_await State->MeasureEnd.async_receive(Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            State->FailureMessage = "real matrix end gate receive failed";
            MarkRealMeasureFailure(State);
            co_return false;
        }
        co_return true;
    }

    inline auto MarkRealMeasureComplete(const std::shared_ptr<RealRootState> &State) -> void
    {
        (void)ClaimRealMeasureTerminal(State, RealMeasureTerminal::Complete);
    }

    inline auto MarkRealMeasureFailure(const std::shared_ptr<RealRootState> &State) -> void
    {
        if (!State->Window)
        {
            return;
        }
        (void)ClaimRealMeasureFailureReadiness(State);
        (void)ClaimRealMeasureTerminal(State, RealMeasureTerminal::Failed);
    }

    inline auto InjectRealFailure(const std::shared_ptr<RealRootState> &State,
                                  const std::string_view Message,
                                  const bool CancelOperations) -> void
    {
        State->FailureMessage = std::string(Message);
        State->Failure = std::make_exception_ptr(std::runtime_error(State->FailureMessage));
        if (!CancelOperations)
        {
            return;
        }
        State->MeasureGo.cancel();
        State->MeasureEnd.cancel();
        State->Harness->Stop();
        MarkRealMeasureFailure(State);
    }

    inline auto CancelRealState(const std::shared_ptr<RealRootState> &State,
                                const std::string_view Message) -> void
    {
        State->FailureMessage = std::string(Message);
        State->Failure = std::make_exception_ptr(std::runtime_error(State->FailureMessage));
        State->MeasureGo.cancel();
        State->MeasureEnd.cancel();
        State->Harness->Stop();
        MarkRealMeasureFailure(State);
    }

    inline auto FinishRealReport(std::size_t Sent, std::chrono::steady_clock::time_point Started,
                          const std::vector<double> &Latencies) -> Prism::BenchReport;

} // namespace Prism::Testing::MuxRealRoot
