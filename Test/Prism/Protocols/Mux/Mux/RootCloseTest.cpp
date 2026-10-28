/** @file RootCloseTest.cpp @brief 验证活动 Mux root 的正常关闭、取消与物理退休。 */
#include <gtest/gtest.h>

#include <boost/asio.hpp>

#include <array>
#include <cstddef>
#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Mux/Root/Child.hpp>
#include <Prism/Protocols/Mux/Root/Retirement.hpp>
#include <Prism/Protocols/Mux/Root/Session.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include <Prism/Transport/MemoryStream.hpp>

#include "RootCloseTestSupport.hpp"

namespace
{
    namespace Net = boost::asio;

    struct RootRunCompletion final
    {
        explicit RootRunCompletion(Net::any_io_executor Executor)
            : Changed(std::move(Executor)) {}

        Net::steady_timer Changed;
        std::optional<std::expected<void, Prism::Fault::Failure>> Result;
        std::exception_ptr Exception;
    };

    struct RootRunCloseOutcome final
    {
        bool TimedOut{false};
        bool RunSucceeded{false};
        bool ActivityDrainSucceeded{false};
        bool ChildStarted{false};
        bool ChildActiveBeforeClose{false};
        bool ChildActiveAfterClose{false};
        bool ChildRetirementReleased{false};
        bool RootRetired{false};
        std::size_t OutstandingGenerationUses{0U};
        Prism::Fault::Failure RunFailure{};
        Prism::Fault::Failure DrainFailure{};
        Prism::Fault::Failure TerminalFailure{};
        std::exception_ptr Exception;
    };

    struct MuxTaskDrainScenario final
    {
        Prism::Fault::Failure DrainFailure;
        Prism::Fault::Failure CloseFailure;
        std::size_t ActiveTasks{0U};
        bool DrainBlocked{false};
        bool ExplicitCancel{false};
    };

    struct MuxTaskDrainOutcome final
    {
        bool Retired{false};
        Prism::Fault::Failure ReceiptFailure;
        Prism::Fault::Failure TerminalFailure;
    };

    struct FakeMuxTaskScope final
    {
        std::expected<void, Prism::Fault::Failure> Result;
        Prism::Lifecycle::TaskStats Statistics;

        auto Drain() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        { co_return Result; }
        [[nodiscard]] auto Stats() const noexcept -> Prism::Lifecycle::TaskStats
        { return Statistics; }
    };

    struct FakeMuxEngineSession final
    {
        std::shared_ptr<FakeMuxTaskScope> TaskScope;
        Prism::Fault::Failure CloseFailure;

        auto Close() -> Net::awaitable<void>
        {
            if (CloseFailure.Failed())
                throw std::system_error(Prism::Fault::ToNative(CloseFailure));
            co_return;
        }
        [[nodiscard]] auto Tasks() const noexcept -> std::shared_ptr<FakeMuxTaskScope>
        { return TaskScope; }
    };

    struct FakeMuxEngineServer final
    {
        std::shared_ptr<FakeMuxEngineSession> EngineSession;

        [[nodiscard]] auto Session() const noexcept -> std::shared_ptr<FakeMuxEngineSession>
        { return EngineSession; }
    };

    auto RunMuxTaskDrainScenario(
        Net::any_io_executor Executor, MuxTaskDrainScenario Scenario)
        -> Net::awaitable<MuxTaskDrainOutcome>
    {
        auto [PeerRaw, InboundRaw] = Prism::MakeMemoryPair(Executor);
        auto Peer = std::make_shared<Prism::MemoryStream>(std::move(PeerRaw));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(InboundRaw));
        auto State = std::make_shared<Prism::Mux::Detail::RootState>(
            Inbound, Prism::Mux::RootOptions{});
        State->Stopping.store(true, std::memory_order_release);
        if (Scenario.ExplicitCancel)
        {
            State->Phase.store(Prism::Mux::Detail::RootState::RunPhase::CancellationRequested,
                std::memory_order_release);
        }
        auto Scope = std::make_shared<FakeMuxTaskScope>();
        if (Scenario.DrainFailure.Failed())
            Scope->Result = std::unexpected(Scenario.DrainFailure);
        Scope->Statistics.Active = Scenario.ActiveTasks;
        Scope->Statistics.DrainBlocked = Scenario.DrainBlocked;
        auto Session = std::make_shared<FakeMuxEngineSession>();
        Session->TaskScope = std::move(Scope);
        Session->CloseFailure = Scenario.CloseFailure;
        auto Server = std::make_shared<FakeMuxEngineServer>();
        Server->EngineSession = std::move(Session);
        const auto Receipt = co_await Prism::Mux::Detail::DrainMuxServerTasks(State, Server);
        if (Receipt.Failure.Failed()) State->RecordTerminalFailure(Receipt.Failure);
        MuxTaskDrainOutcome Outcome{
            Receipt.Retired, Receipt.Failure, State->TerminalFailure.Load()};
        (void)Peer->Close();
        co_return Outcome;
    }

    auto RunMuxTaskDrainMatrix(Net::any_io_executor Executor)
        -> Net::awaitable<std::vector<MuxTaskDrainOutcome>>
    {
        const std::array Scenarios{
            MuxTaskDrainScenario{Prism::Fault::Failure{Prism::Fault::Code::Canceled}, {}, 0U, false, false},
            MuxTaskDrainScenario{Prism::Fault::Failure{Prism::Fault::Code::Canceled}, {}, 0U, false, true},
            MuxTaskDrainScenario{Prism::Fault::Failure{Prism::Fault::Code::Canceled}, {}, 1U, false, false},
            MuxTaskDrainScenario{Prism::Fault::Failure{Prism::Fault::Code::IoError}, {}, 0U, false, false},
            MuxTaskDrainScenario{Prism::Fault::Failure{Prism::Fault::Code::IoError},
                Prism::Fault::Failure{Prism::Fault::Code::Canceled}, 0U, false, false}};
        std::vector<MuxTaskDrainOutcome> Outcomes;
        Outcomes.reserve(Scenarios.size());
        for (const auto& Scenario : Scenarios)
            Outcomes.push_back(co_await RunMuxTaskDrainScenario(Executor, Scenario));
        co_return Outcomes;
    }

    auto RunRootCloseDuringActiveRun(
        Net::any_io_executor Executor, const bool ExplicitCancel)
        -> Net::awaitable<RootRunCloseOutcome>
    {
        RootRunCloseOutcome Outcome;
        auto [PeerRaw, InboundRaw] = Prism::MakeMemoryPair(Executor);
        auto Peer = std::make_shared<Prism::MemoryStream>(std::move(PeerRaw));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(InboundRaw));
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        auto Options = Prism::Mux::RootOptions{};
        Options.GenerationUseState = UseState;
        auto State = std::make_shared<Prism::Mux::Detail::RootState>(
            Inbound, std::move(Options));
        auto Generation = UseState->Acquire();
        if (!Generation)
        {
            Outcome.RunFailure = Generation.error();
            co_return Outcome;
        }
        State->GenerationLease = std::move(*Generation);
        auto Root = Prism::Mux::Testing::RootSessionStateFixture::CreateSession(State);
        auto Request = Prism::Contract::MuxRootRequest{};
        Request.GenerationUseState = UseState;
        auto Completion = std::make_shared<RootRunCompletion>(Executor);
        Completion->Changed.expires_after(std::chrono::seconds(5));
        Net::co_spawn(Executor, Root->Run(std::move(Request)), [Completion]
            (std::exception_ptr Error, std::expected<void, Prism::Fault::Failure> Result)
            {
                Completion->Exception = std::move(Error);
                Completion->Result = std::move(Result);
                (void)Completion->Changed.cancel();
            });

        co_await Net::post(Executor, Net::use_awaitable);
        if (ExplicitCancel) Root->Cancel();
        else Root->Close();
        if (!Completion->Result)
        {
            boost::system::error_code WaitError;
            co_await Completion->Changed.async_wait(
                Net::redirect_error(Net::use_awaitable, WaitError));
            Outcome.TimedOut = WaitError != Net::error::operation_aborted;
        }
        Outcome.Exception = Completion->Exception;
        if (Completion->Result)
        {
            Outcome.RunSucceeded = Completion->Result->has_value();
            if (!*Completion->Result) Outcome.RunFailure = Completion->Result->error();
        }
        if (!Outcome.TimedOut && Completion->Result)
        {
            const auto Activity = Root->Activity();
            const auto Drained = co_await Activity->Drain();
            Outcome.ActivityDrainSucceeded = Drained.has_value();
            if (!Drained) Outcome.DrainFailure = Drained.error();
        }
        Outcome.RootRetired = Root->IsRetired();
        Outcome.OutstandingGenerationUses = UseState->Outstanding();
        Outcome.TerminalFailure = State->TerminalFailure.Load();
        (void)Peer->Close();
        co_return Outcome;
    }

    auto WaitForActiveRootChild(
        const std::shared_ptr<Prism::Mux::Detail::RootState> &State,
        Net::any_io_executor Executor) -> Net::awaitable<bool>
    {
        Net::steady_timer Poll(Executor);
        const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < Deadline)
        {
            if (State->Children->Stats().Active != 0U) co_return true;
            Poll.expires_after(std::chrono::milliseconds(1));
            co_await Poll.async_wait(Net::use_awaitable);
        }
        co_return false;
    }

    auto RunRootCloseDuringActiveChild(
        Net::any_io_executor Executor, const bool ExplicitCancel)
        -> Net::awaitable<RootRunCloseOutcome>
    {
        RootRunCloseOutcome Outcome;
        auto [PeerRaw, InboundRaw] = Prism::MakeMemoryPair(Executor);
        auto Peer = std::make_shared<Prism::MemoryStream>(std::move(PeerRaw));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(InboundRaw));
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        auto Options = Prism::Mux::RootOptions{};
        Options.Wire = Prism::Mux::Mode::H2Mux;
        Options.GenerationUseState = UseState;
        auto State = std::make_shared<Prism::Mux::Detail::RootState>(
            Inbound, std::move(Options));
        auto Generation = UseState->Acquire();
        if (!Generation)
        {
            Outcome.RunFailure = Generation.error();
            co_return Outcome;
        }
        State->GenerationLease = std::move(*Generation);
        auto Root = Prism::Mux::Testing::RootSessionStateFixture::CreateSession(State);
        auto Request = Prism::Contract::MuxRootRequest{};
        Request.Metadata.TaskIdentity.SessionId = Prism::SessionId{501};
        Request.Metadata.TaskIdentity.WorkerId = Prism::WorkerId{31};
        Request.Metadata.TaskIdentity.Generation = Prism::GenerationId{9};
        Request.GenerationUseState = UseState;
        auto Completion = std::make_shared<RootRunCompletion>(Executor);
        Completion->Changed.expires_after(std::chrono::seconds(5));
        Net::co_spawn(Executor, Root->Run(std::move(Request)), [Completion]
            (std::exception_ptr Error, std::expected<void, Prism::Fault::Failure> Result)
            {
                Completion->Exception = std::move(Error);
                Completion->Result = std::move(Result);
                (void)Completion->Changed.cancel();
            });

        auto Client = std::make_shared<Prism::Http2::Session>(Peer->Executor(), false);
        Client->SendSettings();
        const auto Opened = Client->OpenStream(
            Prism::Http2::HeaderList{
                {":method", "CONNECT"}, {":authority", "root-close.test:443"}},
            false);
        if (Opened)
        {
            std::vector<std::byte> Wire;
            Outcome.ChildStarted = Client->Collect(Wire);
            if (Outcome.ChildStarted)
            {
                const std::array<std::byte, 2> Envelope{std::byte{0}, std::byte{2}};
                const auto EnvelopeWritten = co_await Peer->WriteSome(Envelope);
                Outcome.ChildStarted = !EnvelopeWritten.Failure.Failed() &&
                    EnvelopeWritten.Bytes == Envelope.size();
                if (Outcome.ChildStarted)
                {
                    const auto Written = co_await Peer->WriteSome(
                        std::span<const std::byte>(Wire));
                    Outcome.ChildStarted = !Written.Failure.Failed() &&
                        Written.Bytes == Wire.size();
                }
            }
        }
        if (Outcome.ChildStarted)
        {
            Outcome.ChildStarted = co_await WaitForActiveRootChild(State, Executor);
        }
        Outcome.ChildActiveBeforeClose = Outcome.ChildStarted &&
            State->Children->Stats().Active == 1U && State->HasOutstandingChildRetirement();
        co_await Net::post(State->Executor, Net::use_awaitable);
        if (ExplicitCancel) Root->Cancel();
        else Root->Close();
        if (!Completion->Result)
        {
            Completion->Changed.expires_after(std::chrono::seconds(5));
            boost::system::error_code WaitError;
            co_await Completion->Changed.async_wait(
                Net::redirect_error(Net::use_awaitable, WaitError));
            Outcome.TimedOut = WaitError != Net::error::operation_aborted;
        }
        Outcome.Exception = Completion->Exception;
        if (Completion->Result)
        {
            Outcome.RunSucceeded = Completion->Result->has_value();
            if (!*Completion->Result) Outcome.RunFailure = Completion->Result->error();
        }
        if (!Outcome.TimedOut && Completion->Result)
        {
            const auto Activity = Root->Activity();
            const auto Drained = co_await Activity->Drain();
            Outcome.ActivityDrainSucceeded = Drained.has_value();
            if (!Drained) Outcome.DrainFailure = Drained.error();
        }
        const auto Children = State->Children->Stats();
        Outcome.ChildActiveAfterClose = Children.Active != 0U || Children.DrainBlocked;
        Outcome.ChildRetirementReleased = !State->HasOutstandingChildRetirement();
        Outcome.RootRetired = Root->IsRetired();
        Outcome.OutstandingGenerationUses = UseState->Outstanding();
        Outcome.TerminalFailure = State->TerminalFailure.Load();
        (void)Peer->Close();
        co_return Outcome;
    }

    TEST(MuxRootClose, ActiveRunCloseStopsWithoutPublishingCancellation)
    {
        Net::io_context Io;
        RootRunCloseOutcome Outcome;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunRootCloseDuringActiveRun(Io.get_executor(), false),
            [&Outcome, &Exception](std::exception_ptr Error, RootRunCloseOutcome Result)
            {
                Exception = std::move(Error);
                Outcome = std::move(Result);
            });
        Io.run();

        EXPECT_FALSE(Exception);
        EXPECT_FALSE(Outcome.TimedOut);
        EXPECT_FALSE(Outcome.Exception);
        EXPECT_TRUE(Outcome.RunSucceeded);
        EXPECT_EQ(Outcome.RunFailure.Code, Prism::Fault::Code::Success);
        EXPECT_TRUE(Outcome.ActivityDrainSucceeded);
        EXPECT_TRUE(Outcome.RootRetired);
        EXPECT_FALSE(Outcome.TerminalFailure.Failed());
        EXPECT_EQ(Outcome.OutstandingGenerationUses, 0U);
    }

    TEST(MuxRootClose, MuxTaskDrainCancellationRequiresNormalCloseAndPhysicalRetirement)
    {
        Net::io_context Io;
        std::vector<MuxTaskDrainOutcome> Outcomes;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunMuxTaskDrainMatrix(Io.get_executor()),
            [&Outcomes, &Exception](std::exception_ptr Error,
                std::vector<MuxTaskDrainOutcome> Result)
            {
                Exception = std::move(Error);
                Outcomes = std::move(Result);
            });
        Io.run();

        ASSERT_FALSE(Exception);
        ASSERT_EQ(Outcomes.size(), 5U);
        EXPECT_TRUE(Outcomes[0].Retired);
        EXPECT_FALSE(Outcomes[0].ReceiptFailure.Failed());
        EXPECT_FALSE(Outcomes[0].TerminalFailure.Failed());
        EXPECT_TRUE(Outcomes[1].Retired);
        EXPECT_EQ(Outcomes[1].ReceiptFailure.Code, Prism::Fault::Code::Canceled);
        EXPECT_EQ(Outcomes[1].TerminalFailure.Code, Prism::Fault::Code::Canceled);
        EXPECT_FALSE(Outcomes[2].Retired);
        EXPECT_EQ(Outcomes[2].ReceiptFailure.Code, Prism::Fault::Code::Canceled);
        EXPECT_EQ(Outcomes[2].TerminalFailure.Code, Prism::Fault::Code::Canceled);
        EXPECT_TRUE(Outcomes[3].Retired);
        EXPECT_EQ(Outcomes[3].ReceiptFailure.Code, Prism::Fault::Code::IoError);
        EXPECT_EQ(Outcomes[3].TerminalFailure.Code, Prism::Fault::Code::IoError);
        EXPECT_TRUE(Outcomes[4].Retired);
        EXPECT_EQ(Outcomes[4].ReceiptFailure.Code, Prism::Fault::Code::IoError);
        EXPECT_EQ(Outcomes[4].TerminalFailure.Code, Prism::Fault::Code::IoError);
    }

    TEST(MuxRootClose, ChildDrainKeepsDurableFailureOverCancellation)
    {
        auto Failure = Prism::Fault::Failure{Prism::Fault::Code::Canceled};
        Prism::Mux::Detail::PreserveChildDrainFailure(
            Failure, Prism::Fault::Failure{Prism::Fault::Code::IoError});

        EXPECT_EQ(Failure.Code, Prism::Fault::Code::IoError);
    }

    TEST(MuxRootClose, NormalCloseH2RunCancellationDoesNotRecordTerminalFailure)
    {
        Net::io_context Io;
        auto [PeerRaw, InboundRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto Peer = std::make_shared<Prism::MemoryStream>(std::move(PeerRaw));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(InboundRaw));
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        auto Options = Prism::Mux::RootOptions{};
        Options.GenerationUseState = UseState;
        auto State = std::make_shared<Prism::Mux::Detail::RootState>(Inbound, std::move(Options));
        State->Stopping.store(true, std::memory_order_release);

        Prism::Mux::Testing::RootSessionStateFixture::RecordHttp2RunFailure(
            State, Prism::Fault::Failure{Prism::Fault::Code::Canceled});

        EXPECT_FALSE(State->TerminalFailure.Load().Failed());
        (void)Peer->Close();
    }

    TEST(MuxRootClose, ExpectedRetirementCancellationRequiresNormalCloseAndRetirement)
    {
        Net::io_context Io;
        auto [PeerRaw, InboundRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto Peer = std::make_shared<Prism::MemoryStream>(std::move(PeerRaw));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(InboundRaw));
        auto State = std::make_shared<Prism::Mux::Detail::RootState>(
            Inbound, Prism::Mux::RootOptions{});
        State->Stopping.store(true, std::memory_order_release);
        const auto Canceled = Prism::Fault::Failure{Prism::Fault::Code::Canceled};

        EXPECT_TRUE(State->IsExpectedRetirementCancellation(Canceled, true));
        EXPECT_FALSE(State->IsExpectedRetirementCancellation(Canceled, false));
        State->Phase.store(Prism::Mux::Detail::RootState::RunPhase::CancellationRequested,
            std::memory_order_release);
        EXPECT_FALSE(State->IsExpectedRetirementCancellation(Canceled, true));
        EXPECT_FALSE(State->IsExpectedRetirementCancellation(
            Prism::Fault::Failure{Prism::Fault::Code::IoError}, true));
        (void)Peer->Close();
    }

    TEST(MuxRootClose, ExplicitCancelKeepsH2RunCancellation)
    {
        Net::io_context Io;
        auto [PeerRaw, InboundRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto Peer = std::make_shared<Prism::MemoryStream>(std::move(PeerRaw));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(InboundRaw));
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        auto Options = Prism::Mux::RootOptions{};
        Options.GenerationUseState = UseState;
        auto State = std::make_shared<Prism::Mux::Detail::RootState>(Inbound, std::move(Options));
        State->Stopping.store(true, std::memory_order_release);
        State->Phase.store(Prism::Mux::Detail::RootState::RunPhase::CancellationRequested,
            std::memory_order_release);

        Prism::Mux::Testing::RootSessionStateFixture::RecordHttp2RunFailure(
            State, Prism::Fault::Failure{Prism::Fault::Code::Canceled});

        EXPECT_EQ(State->TerminalFailure.Load().Code, Prism::Fault::Code::Canceled);
        (void)Peer->Close();
    }

    TEST(MuxRootClose, ActiveRunCancelKeepsCancellationButPhysicallyRetires)
    {
        Net::io_context Io;
        RootRunCloseOutcome Outcome;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunRootCloseDuringActiveRun(Io.get_executor(), true),
            [&Outcome, &Exception](std::exception_ptr Error, RootRunCloseOutcome Result)
            {
                Exception = std::move(Error);
                Outcome = std::move(Result);
            });
        Io.run();

        EXPECT_FALSE(Exception);
        EXPECT_FALSE(Outcome.TimedOut);
        EXPECT_FALSE(Outcome.Exception);
        EXPECT_FALSE(Outcome.RunSucceeded);
        EXPECT_EQ(Outcome.RunFailure.Code, Prism::Fault::Code::Canceled);
        EXPECT_TRUE(Outcome.ActivityDrainSucceeded);
        EXPECT_EQ(Outcome.DrainFailure.Code, Prism::Fault::Code::Success);
        EXPECT_TRUE(Outcome.RootRetired);
        EXPECT_EQ(Outcome.TerminalFailure.Code, Prism::Fault::Code::Canceled);
        EXPECT_EQ(Outcome.OutstandingGenerationUses, 0U);
    }

    TEST(MuxRootClose, ActiveChildCloseRetiresWithoutPublishingCancellation)
    {
        Net::io_context Io;
        RootRunCloseOutcome Outcome;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunRootCloseDuringActiveChild(Io.get_executor(), false),
            [&Outcome, &Exception](std::exception_ptr Error, RootRunCloseOutcome Result)
            {
                Exception = std::move(Error);
                Outcome = std::move(Result);
            });
        Io.run();

        EXPECT_FALSE(Exception);
        EXPECT_FALSE(Outcome.TimedOut);
        EXPECT_FALSE(Outcome.Exception);
        EXPECT_TRUE(Outcome.ChildStarted);
        EXPECT_TRUE(Outcome.ChildActiveBeforeClose);
        EXPECT_FALSE(Outcome.ChildActiveAfterClose);
        EXPECT_TRUE(Outcome.ChildRetirementReleased);
        EXPECT_TRUE(Outcome.RunSucceeded);
        EXPECT_EQ(Outcome.RunFailure.Code, Prism::Fault::Code::Success);
        EXPECT_TRUE(Outcome.ActivityDrainSucceeded);
        EXPECT_TRUE(Outcome.RootRetired);
        EXPECT_FALSE(Outcome.TerminalFailure.Failed());
        EXPECT_EQ(Outcome.OutstandingGenerationUses, 0U);
    }

    TEST(MuxRootClose, ActiveChildCancelKeepsCancellationAndPhysicallyRetires)
    {
        Net::io_context Io;
        RootRunCloseOutcome Outcome;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunRootCloseDuringActiveChild(Io.get_executor(), true),
            [&Outcome, &Exception](std::exception_ptr Error, RootRunCloseOutcome Result)
            {
                Exception = std::move(Error);
                Outcome = std::move(Result);
            });
        Io.run();

        EXPECT_FALSE(Exception);
        EXPECT_FALSE(Outcome.TimedOut);
        EXPECT_FALSE(Outcome.Exception);
        EXPECT_TRUE(Outcome.ChildStarted);
        EXPECT_TRUE(Outcome.ChildActiveBeforeClose);
        EXPECT_FALSE(Outcome.ChildActiveAfterClose);
        EXPECT_TRUE(Outcome.ChildRetirementReleased);
        EXPECT_FALSE(Outcome.RunSucceeded);
        EXPECT_EQ(Outcome.RunFailure.Code, Prism::Fault::Code::Canceled);
        EXPECT_TRUE(Outcome.ActivityDrainSucceeded);
        EXPECT_TRUE(Outcome.RootRetired);
        EXPECT_EQ(Outcome.TerminalFailure.Code, Prism::Fault::Code::Canceled);
        EXPECT_EQ(Outcome.OutstandingGenerationUses, 0U);
    }
}
