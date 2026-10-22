/**
 * @file ListenerWorkerTest.cpp
 * @brief 验证 listener admission 在 worker executor 上创建 session 并保留身份。
 */

#include "ListenerTestSupport.hpp"

namespace
{
    struct WorkerAdmissionState final
    {
        explicit WorkerAdmissionState(Prism::Runtime::WorkerGroup &GroupValue)
            : Workers(&GroupValue)
        {
        }

        // ProcessValue 和 WorkerGroupRunner 在 RunCoro 完整等待期间持有 Workers。
        Prism::Runtime::WorkerGroup *Workers;
        Prism::Fault::Code StartResult{Prism::Fault::Code::GenericError};
        std::atomic<bool> FactoryOnWorker{false};
        std::atomic<bool> SessionOnWorker{false};
        std::atomic<std::uint64_t> FactoryThread{0};
        std::atomic<std::uint64_t> SessionThread{0};
        std::atomic<std::uint64_t> ObservedSession{0};
        std::atomic<std::uint64_t> ObservedWorker{0};
        std::atomic<std::uint64_t> ObservedGeneration{0};
    };

    auto AcceptWorkerAdmission(
        std::shared_ptr<WorkerAdmissionState> State,
        Prism::Runtime::Worker *Selected,
        Prism::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        State->SessionOnWorker.store(Selected && Selected->IsOnExecutor(),
                                     std::memory_order_release);
        State->SessionThread.store(
            static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id())),
            std::memory_order_release);
        State->ObservedSession.store(Input.Metadata.TaskIdentity.SessionId.Value(),
                                     std::memory_order_release);
        State->ObservedWorker.store(Input.Metadata.TaskIdentity.WorkerId.Value(),
                                    std::memory_order_release);
        State->ObservedGeneration.store(Input.Metadata.TaskIdentity.Generation.Value(),
                                        std::memory_order_release);
        co_return std::unexpected(Prism::Contract::FailureFromProtocolError(Prism::Error::BadMessage));
    }

    struct WorkerAdmissionAcceptFactory final
    {
        std::shared_ptr<WorkerAdmissionState> State;
        Prism::Runtime::Worker *Selected;

        auto operator()(Prism::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Prism::Contract::AcceptOutcome>
        {
            return AcceptWorkerAdmission(
                State, Selected, std::move(Input));
        }
    };

    auto MakeWorkerAdmissionSession(std::shared_ptr<WorkerAdmissionState> State,
        Prism::Runtime::Worker *Selected, const std::size_t WorkerIndex) -> std::shared_ptr<Prism::Runtime::Session>
    {
        auto Options = MakeListenerWorkerSessionOptions(State->Workers, WorkerIndex);
        Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
            WorkerAdmissionAcceptFactory{State, Selected});
        return std::make_shared<Prism::Runtime::Session>(std::move(Options));
    }

    struct WorkerAdmissionSessionFactory final
    {
        std::shared_ptr<WorkerAdmissionState> State;

        auto operator()(Prism::Runtime::SessionAdmission Admission) const
            -> Prism::Runtime::SessionAdmissionResult
        {
            const auto WorkerIndex = static_cast<std::size_t>(Admission.Worker.Value() - 1U);
            auto *Selected = State->Workers->Find(Admission.Worker);
            State->FactoryOnWorker.store(Selected && Selected->IsOnExecutor(),
                                         std::memory_order_release);
            State->FactoryThread.store(
                static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id())),
                std::memory_order_release);
            return MakeWorkerAdmissionSession(State, Selected, WorkerIndex);
        }
    };

    struct WorkerAdmissionProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Prism::Runtime::TcpListener> Listener;
        std::shared_ptr<WorkerAdmissionState> State;
    };

    auto RunWorkerAdmissionProbe(WorkerAdmissionProbeRequest Request) -> Net::awaitable<void>
    {
        Request.State->StartResult = co_await Request.Listener->Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Request.State->StartResult, Prism::Fault::Code::Success);
        if (Request.State->StartResult != Prism::Fault::Code::Success)
        {
            co_return;
        }

        std::error_code Error;
        Prism::Network::Dialer::Dialer Dialer(Request.Executor);
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        Prism::SharedTransmission Client;
        if (Dialed)
        {
            Client = std::move(*Dialed);
            Error.clear();
        }
        else
        {
            Error = Prism::Fault::ToNative(Dialed.error());
        }
        EXPECT_FALSE(Error);
        EXPECT_NE(Client, nullptr);
        if (Error || !Client)
        {
            co_return;
        }

        const auto Greeting = Socks5Greeting();
        const auto Write = co_await Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                       Greeting.size()));
        Error = Prism::Fault::ToNative(Write.Failure);
        EXPECT_FALSE(Error);

        for (int Attempt = 0; Attempt < 100 &&
                                !Request.State->SessionOnWorker.load(std::memory_order_acquire);
             ++Attempt)
        {
            Net::steady_timer Tick(Request.Executor);
            Tick.expires_after(std::chrono::milliseconds(1));
            co_await Tick.async_wait(Net::use_awaitable);
        }
        co_await Request.Listener->Shutdown();
        (void)Client->Close();
    }
}

TEST(TcpListener, AdmissionUsesWorkerExecutorAndPreservesIdentity)
    {
        Net::io_context ListenerIo;
        Prism::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Prism::ProcessId{31};
        ProcessOptions.Generation = Prism::GenerationId{47};
        ProcessOptions.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        ProcessOptions.WorkerCount = 1;
        ProcessOptions.MailboxCapacity = 4;
        Prism::Runtime::Process ProcessValue(ProcessOptions);
        auto &Workers = ProcessValue.Workers();
        auto *WorkerValue = Workers.Find(Prism::WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);
        WorkerGroupRunner Runner(Workers);

        const auto ListenerThread =
            static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
        auto State = std::make_shared<WorkerAdmissionState>(Workers);

        Prism::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = ListenerIo.get_executor();
        ListenerOptions.Workers = &Workers;
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.Factory = WorkerAdmissionSessionFactory{State};
        auto Listener = std::make_shared<Prism::Runtime::TcpListener>(
            std::move(ListenerOptions));

        RunCoro(ListenerIo, RunWorkerAdmissionProbe(WorkerAdmissionProbeRequest{
                                     ListenerIo.get_executor(), Listener, State}));

        EXPECT_EQ(State->StartResult, Prism::Fault::Code::Success);
        EXPECT_TRUE(State->FactoryOnWorker.load(std::memory_order_acquire));
        EXPECT_TRUE(State->SessionOnWorker.load(std::memory_order_acquire));
        EXPECT_NE(State->FactoryThread.load(std::memory_order_acquire), ListenerThread);
        EXPECT_NE(State->SessionThread.load(std::memory_order_acquire), ListenerThread);
        EXPECT_GT(State->ObservedSession.load(std::memory_order_acquire), std::uint64_t{0});
        EXPECT_EQ(State->ObservedWorker.load(std::memory_order_acquire), std::uint64_t{1});
        EXPECT_EQ(State->ObservedGeneration.load(std::memory_order_acquire), std::uint64_t{47});
    }
