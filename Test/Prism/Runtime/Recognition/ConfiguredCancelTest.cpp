/**
 * @file ConfiguredCancelTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ModeSupport.hpp"

namespace
{

    using CompletionSignal = boost::asio::experimental::channel<void(boost::system::error_code)>;

    auto CommitCancellation(
        const std::shared_ptr<CompletionSignal> &Gate,
        const std::shared_ptr<Calls> &CallsState,
        rec::CommitContext Context) -> Net::awaitable<rec::CommitResult>
    {
        ++CallsState->Commit;
        co_await Gate->async_receive(Net::use_awaitable);
        CallsState->CommitCompleted = true;
        auto Result = AcceptedCommit(Context.Candidate);
        Result.Status = rec::RecognitionStatus::IoError;
        Result.Error = std::make_error_code(std::errc::operation_canceled);
        if (CallsState->ReturnedTransport)
        {
            Result.Transport = CallsState->ReturnedTransport;
        }
        else
        {
            Result.Transport = std::move(Context.Inbound);
        }
        co_return Result;
    }

    auto PrepareAfterCancellationDelay(
        const std::shared_ptr<Calls> &CallsState,
        rec::PrepareContext Context) -> Net::awaitable<rec::PrepareResult>
    {
        ++CallsState->Prepare;
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Timer(Executor);
        Timer.expires_after(std::chrono::milliseconds(50));
        co_await Timer.async_wait(Net::use_awaitable);
        CallsState->PrepareCompleted = true;
        co_return AcceptedPrepare(Context.Candidate);
    }

}

TEST(ConfiguredModeTest, ControlledCommitCleansIndependentSuccessorAndInboundExactlyOnce)
    {
        Net::io_context Io;
        auto Gate = std::make_shared<boost::asio::experimental::channel<void(boost::system::error_code)>>(Io, 1);
        auto CommitEntered = std::make_shared<boost::asio::experimental::channel<void(
            boost::system::error_code)>>(Io, 1);
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        CallsState->PendingCommit = true;
        CallsState->CommitGate = Gate;
        CallsState->CommitEntered = CommitEntered;
        auto Decoy = std::make_shared<ScriptedTransport>(Io.get_executor());
        CallsState->ReturnedTransport = Decoy;
        auto Profile = MakeConfiguredProfile(
            {CallsState, AcceptedPrepare(7), AcceptedCommit(7), 3, std::chrono::milliseconds::zero()});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Profile);
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Wait = [CommitEntered, WaitCalls]() -> Net::awaitable<rec::RecognitionControlEvent>
        {
            ++*WaitCalls;
            co_await CommitEntered->async_receive(Net::use_awaitable);
            co_return rec::RecognitionControlEvent::TimedOut;
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Gate, Transport]
        {
            Gate->try_send(boost::system::error_code{});
            Transport->Cancel();
            Transport->Close();
        };
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::TimedOut);
        EXPECT_EQ(Result.transport, nullptr);
        EXPECT_TRUE(CallsState->CommitCompleted);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_EQ(Decoy->Cancels(), 1U);
        EXPECT_EQ(Decoy->Closes(), 1U);
    }

TEST(ConfiguredModeTest, PrepareCancellationIsNormalized)
    {
        Net::io_context Io;
        auto Gate = std::make_shared<boost::asio::experimental::channel<void(boost::system::error_code)>>(Io, 1);
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 7;
        Spec.Budget.MaxProbeBytes = 32;
        rec::CandidateSpec Candidate;
        Candidate.Id = 7;
        Candidate.Name = "pending-prepare";
        Candidate.Protocol = Prism::Contract::ProtocolType::Vless;
        Candidate.Kind = rec::CandidateKind::Opaque;
        Candidate.RequiresAuthentication = true;
        Candidate.FirstBytes = {0xA1};
        Candidate.MinimumBytes = 3;
        Candidate.Inspect = [](const rec::ProbeSnapshot &) { return rec::MatchState::Structural; };
        Candidate.Prepare = [Gate, CallsState](rec::PrepareContext Context) -> Net::awaitable<rec::PrepareResult>
        {
            ++CallsState->Prepare;
            co_await Gate->async_receive(Net::use_awaitable);
            CallsState->PrepareCompleted = true;
            auto Result = AcceptedPrepare(Context.Candidate);
            Result.Status = rec::RecognitionStatus::IoError;
            Result.Error = std::make_error_code(std::errc::operation_canceled);
            co_return Result;
        };
        Candidate.Commit = [CallsState](rec::CommitContext Context) -> Net::awaitable<rec::CommitResult>
        {
            ++CallsState->Commit;
            auto Result = AcceptedCommit(Context.Candidate);
            Result.Transport = std::move(Context.Inbound);
            co_return Result;
        };
        Spec.Candidates.push_back(std::move(Candidate));
        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Compiled.has_value());
        rec::ProbeBuffer Buffer(32, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Compiled.value());
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::milliseconds(1), rec::RecognitionControlEvent::Cancelled, WaitCalls);
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Gate]
        {
            Gate->try_send(boost::system::error_code{});
        };
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(Result.Cancelled);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::operation_canceled));
        EXPECT_EQ(CallsState->Prepare, 1U);
        EXPECT_TRUE(CallsState->PrepareCompleted);
        EXPECT_EQ(CallsState->Commit, 0U);
    }

TEST(ConfiguredModeTest, CommitCancellationIsNormalizedAndReturnsNoSuccessor)
    {
        Net::io_context Io;
        auto Gate = std::make_shared<boost::asio::experimental::channel<void(boost::system::error_code)>>(Io, 1);
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Decoy = std::make_shared<ScriptedTransport>(Io.get_executor());
        CallsState->ReturnedTransport = Decoy;
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 7;
        Spec.Budget.MaxProbeBytes = 32;
        rec::CandidateSpec Candidate;
        Candidate.Id = 7;
        Candidate.Name = "pending-commit";
        Candidate.Protocol = Prism::Contract::ProtocolType::Vless;
        Candidate.Kind = rec::CandidateKind::Opaque;
        Candidate.RequiresAuthentication = true;
        Candidate.FirstBytes = {0xA1};
        Candidate.MinimumBytes = 3;
        Candidate.Inspect = [](const rec::ProbeSnapshot &) { return rec::MatchState::Structural; };
        Candidate.Prepare = [CallsState](rec::PrepareContext Context) -> Net::awaitable<rec::PrepareResult>
        {
            ++CallsState->Prepare;
            co_return AcceptedPrepare(Context.Candidate);
        };
        Candidate.Commit = [Gate, CallsState](rec::CommitContext Context)
        { return CommitCancellation(Gate, CallsState, std::move(Context)); };
        Spec.Candidates.push_back(std::move(Candidate));
        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Compiled.has_value());
        rec::ProbeBuffer Buffer(32, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Compiled.value());
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::milliseconds(1), rec::RecognitionControlEvent::Cancelled, WaitCalls);
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Gate, Transport]
        {
            Gate->try_send(boost::system::error_code{});
            Transport->Cancel();
            Transport->Close();
        };
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(Result.Cancelled);
        EXPECT_EQ(Result.Error, std::make_error_code(std::errc::operation_canceled));
        EXPECT_EQ(CallsState->Commit, 1U);
        EXPECT_TRUE(CallsState->CommitCompleted);
        EXPECT_EQ(*WaitCalls, 3U);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_EQ(Decoy->Cancels(), 1U);
        EXPECT_EQ(Decoy->Closes(), 1U);
        EXPECT_EQ(Result.transport, nullptr);
    }

TEST(ConfiguredModeTest, CancellationWaitsForCancelResistantPrepare)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1U, 0x02U, 0x03U}));
        auto CallsState = std::make_shared<Calls>();
        rec::ProfileSpec Spec;
        Spec.Mode = rec::RecognitionMode::Configured;
        Spec.ConfiguredCandidate = 7;
        Spec.Budget.MaxProbeBytes = 32;

        rec::CandidateSpec Candidate;
        Candidate.Id = 7;
        Candidate.Name = "cancel-resistant-prepare";
        Candidate.Protocol = Prism::Contract::ProtocolType::Vless;
        Candidate.Kind = rec::CandidateKind::Opaque;
        Candidate.RequiresAuthentication = true;
        Candidate.FirstBytes = {0xA1U};
        Candidate.MinimumBytes = 3;
        Candidate.Inspect = [](const rec::ProbeSnapshot &) -> rec::MatchState
        {
            return rec::MatchState::Structural;
        };
        Candidate.Prepare = [CallsState](rec::PrepareContext Context)
        { return PrepareAfterCancellationDelay(CallsState, std::move(Context)); };
        Candidate.Commit = [](rec::CommitContext Context)
            -> Net::awaitable<rec::CommitResult>
        {
            auto Result = AcceptedCommit(Context.Candidate);
            Result.Transport = std::move(Context.Inbound);
            co_return Result;
        };
        Spec.Candidates.push_back(std::move(Candidate));
        const auto Compiled = rec::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Compiled.has_value());

        rec::ProbeBuffer Buffer(32, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Compiled.value());
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::milliseconds(1),
                                rec::RecognitionControlEvent::Cancelled, WaitCalls);
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [] {};
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_TRUE(Result.Cancelled);
        EXPECT_EQ(CallsState->Prepare, 1U);
        EXPECT_TRUE(CallsState->PrepareCompleted);
        EXPECT_GE(*WaitCalls, 2U);
    }

TEST(ConfiguredModeTest, OperationWinningNearCancellationIsOverriddenBeforeCommit)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        auto CallsState = std::make_shared<Calls>();
        auto Cancelled = std::make_shared<bool>(false);
        CallsState->CancelAfterPrepare = Cancelled;
        auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        rec::ConfiguredMode Mode(Profile);
        auto WaitCalls = std::make_shared<std::size_t>(0);
        rec::RecognitionControl Control;
        Control.Cancelled = [Cancelled] { return *Cancelled; };
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::hours(1), rec::RecognitionControlEvent::TimedOut, WaitCalls);
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Transport]
        {
            Transport->Cancel();
            Transport->Close();
        };
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(Result.Cancelled);
        EXPECT_EQ(CallsState->Prepare, 1U);
        EXPECT_EQ(CallsState->Commit, 0U);
        EXPECT_EQ(*WaitCalls, 2U);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);

        Io.restart();
        Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(Bytes({0xA1, 0x02, 0x03}));
        CallsState = std::make_shared<Calls>();
        Cancelled = std::make_shared<bool>(false);
        CallsState->CancelAfterCommit = Cancelled;
        Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
        Buffer = rec::ProbeBuffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        Mode = rec::ConfiguredMode(Profile);
        Control = rec::RecognitionControl{};
        Control.Cancelled = [Cancelled] { return *Cancelled; };
        WaitCalls = std::make_shared<std::size_t>(0);
        Control.Wait = [WaitCalls]
        {
            return WaitForEvent(std::chrono::hours(1), rec::RecognitionControlEvent::TimedOut, WaitCalls);
        };
        Control.WaitCancellationSafe = true;
        Control.CancelTransport = [Transport]
        {
            Transport->Cancel();
            Transport->Close();
        };
        Result = {};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer, Control);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        EXPECT_TRUE(Result.Cancelled);
        EXPECT_EQ(CallsState->Commit, 1U);
        EXPECT_EQ(Transport->Cancels(), 1U);
        EXPECT_EQ(Transport->Closes(), 1U);
        EXPECT_EQ(Result.transport, nullptr);
        EXPECT_EQ(*WaitCalls, 3U);
    }

TEST(ConfiguredModeTest, CandidateHandleOwnsProfileAcrossAsyncPrepareAndCommit)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        auto CallsState = std::make_shared<Calls>();
        rec::CandidateHandle Handle;
        {
            auto Profile = MakeConfiguredProfile({CallsState, AcceptedPrepare(7), AcceptedCommit(7)});
            Handle = Profile->FindCandidate(7);
        }

        rec::PrepareContext PrepareContext;
        PrepareContext.Candidate = 7;
        PrepareContext.Budget.MaxProbeBytes = 32;
        rec::PrepareResult PreparedResult;
        rec::CommitResult CommitResult;
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    PreparedResult = co_await Handle.Prepare(std::move(PrepareContext));
                    rec::PreparedCandidate Prepared(Handle, std::move(PreparedResult));
                    rec::CommitContext CommitContext;
                    CommitContext.Inbound = Transport;
                    CommitResult = co_await Prepared.Commit(std::move(CommitContext));
                });

        EXPECT_EQ(CommitResult.Status, rec::RecognitionStatus::Accepted);
        EXPECT_EQ(CommitResult.Candidate, 7U);
        EXPECT_NE(CommitResult.Transport, nullptr);
        EXPECT_TRUE(CallsState->CommitSawPreparedState);
        EXPECT_TRUE(Handle.IsValid());
    }

TEST(ConfiguredModeTest, UsesMatchingSniRouteBeforePrepare)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = Prism::Testing::RecognitionWire::MakeTlsClientHello("configured.example");
        auto State = std::make_shared<Calls>();
        ConfiguredProfileRequest Request{State, AcceptedPrepare(7), AcceptedCommit(7)};
        Request.MinimumBytes = 5;
        Request.Routes.emplace_back("configured.example", 7);
        Request.Timeout = std::chrono::milliseconds(250);
        Request.MaxProbeBytes = 128;
        Request.Protocol = Prism::Contract::ProtocolType::Tls;
        Request.Kind = rec::CandidateKind::TlsCarrier;
        auto Profile = MakeConfiguredProfile(std::move(Request));
        ASSERT_NE(Profile, nullptr);
        ASSERT_TRUE(Profile->Budget().MaxProbeBytes >= Wire.size());
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        ASSERT_TRUE(Buffer.Seed(Wire));
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Candidate, 7);
        EXPECT_EQ(State->Inspect, 1U);
        EXPECT_EQ(State->Prepare, 1U);
        EXPECT_EQ(State->Commit, 1U);
    }

TEST(ConfiguredModeTest, RejectsUnmatchedSniWithoutPrepare)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = Prism::Testing::RecognitionWire::MakeTlsClientHello("other.example");
        auto State = std::make_shared<Calls>();
        ConfiguredProfileRequest Request{State, AcceptedPrepare(7), AcceptedCommit(7)};
        Request.MinimumBytes = 5;
        Request.Routes.emplace_back("configured.example", 7);
        Request.Timeout = std::chrono::milliseconds(250);
        Request.MaxProbeBytes = 128;
        Request.Protocol = Prism::Contract::ProtocolType::Tls;
        Request.Kind = rec::CandidateKind::TlsCarrier;
        auto Profile = MakeConfiguredProfile(std::move(Request));
        ASSERT_NE(Profile, nullptr);
        ASSERT_TRUE(Profile->Budget().MaxProbeBytes >= Wire.size());
        rec::ProbeBuffer Buffer(Profile->Budget().MaxProbeBytes, MakeConfiguredProbeBytePool());
        ASSERT_TRUE(Buffer.Seed(Wire));
        rec::ConfiguredMode Mode(Profile);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Mode.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::NoMatch);
        EXPECT_EQ(State->Inspect, 1U);
        EXPECT_EQ(State->Prepare, 0U);
        EXPECT_EQ(State->Commit, 0U);
    }
