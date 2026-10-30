#include <gtest/gtest.h>
#include "../Listener/ListenerTestSupport.hpp"
#include "WorkerTestSupport.hpp"

#include <Prism/Runtime/Process.hpp>
#include <Prism/Runtime/ListenerAdmissionOwner.hpp>
#include <Prism/Runtime/Session/Control.hpp>
#include <Prism/Runtime/Worker.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>
#include <Prism/Runtime/WorkerDispatchResult.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <chrono>
#include <functional>
#include <memory>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <Prism/Foundation/Executor/ContextOwner.hpp>

namespace
{

    using Prism::GenerationId;
    using Prism::ProcessId;
    using Prism::WorkerId;
    using Prism::Runtime::Process;
    using Prism::Runtime::Worker;
    using Prism::Runtime::WorkerDispatchResult;
    using Prism::Runtime::WorkerTestAccess;

    /** @brief 两 worker 回环链路的 executor、上游端口与工厂调用计数。 */
    struct WorkerDrainEchoState final
    {
        Net::any_io_executor Executor;
        std::uint16_t EchoPort{0};
        std::array<std::atomic<std::size_t>, 2> SessionFactories{};
    };

    struct WorkerDrainAcceptRequest final
    {
        std::shared_ptr<WorkerDrainEchoState> State;
        Prism::Contract::StreamAcceptInput Input;
    };

    /** @brief 把真实 listener 入站流装配成指向本地 echo 的 Forward plane。 */
    auto AcceptWorkerDrainEcho(WorkerDrainAcceptRequest Request)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Root = Prism::Contract::StreamDataPlane{std::move(Request.Input.Inbound)};
        Plane.Target.Route = Prism::Network::RouteKind::Forward;
        Plane.Target.Host = *Prism::Network::ParseHost("127.0.0.1");
        Plane.Target.Port = Request.State->EchoPort;
        co_return Plane;
    }

    struct WorkerDrainDialRequest final
    {
        std::shared_ptr<WorkerDrainEchoState> State;
        Prism::Network::Target Target;
    };

    /** @brief 通过真实 TCP dialer 建立 echo 上游。 */
    auto DialWorkerDrainEcho(WorkerDrainDialRequest Request)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
    {
        Prism::Network::Dialer::Dialer Dialer(Request.State->Executor);
        auto Dialed = co_await Dialer.Connect(Request.Target);
        if (!Dialed) co_return std::unexpected(Dialed.error());
        co_return std::move(*Dialed);
    }

    /** @brief 为测试 session 固定 echo dial owner。 */
    struct WorkerDrainDialFactory final
    {
        std::shared_ptr<WorkerDrainEchoState> State;

        auto operator()(const Prism::Network::Target &Target) const
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            return DialWorkerDrainEcho(WorkerDrainDialRequest{State, Target});
        }
    };

    /** @brief 为每个 listener admission 建立实际 worker-owned Forward Session。 */
    struct WorkerDrainSessionFactory final
    {
        std::shared_ptr<WorkerDrainEchoState> State;
        Prism::Runtime::WorkerGroup *Workers{nullptr};

        auto operator()(Prism::Runtime::SessionAdmission Admission) const -> std::shared_ptr<Prism::Runtime::Session>
        {
            const auto WorkerIndex = static_cast<std::size_t>(Admission.Worker.Value() - 1U);
            if (WorkerIndex < State->SessionFactories.size())
            {
                State->SessionFactories[WorkerIndex].fetch_add(1, std::memory_order_relaxed);
            }
            auto Options = MakeListenerWorkerSessionOptions(Workers, WorkerIndex);
            Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
                [State = State](Prism::Contract::StreamAcceptInput Input)
                {
                    return AcceptWorkerDrainEcho(
                        WorkerDrainAcceptRequest{State, std::move(Input)});
                });
            Options.Services->Dial = WorkerDrainDialFactory{State};
            Options.Services->RelayIdleTimeout = std::chrono::seconds(2);
            return std::make_shared<Prism::Runtime::Session>(std::move(Options));
        }
    };

    /** @brief 找到会被 affinity balancer 稳定映射到目标 worker 的回环源地址。 */
    [[nodiscard]] auto LocalAddressForWorker(
        const Prism::Runtime::AffinityBalancer &Balancer,
        const WorkerId Id) -> std::optional<Net::ip::address_v4>
    {
        for (unsigned int Host = 1; Host < 255; ++Host)
        {
            const auto Text = std::string("127.0.0.") + std::to_string(Host);
            const auto Address = Net::ip::make_address_v4(Text);
            if (Balancer.Select(Address.to_string()) + 1U == Id.Value()) return Address;
        }
        return {};
    }

    /** @brief 绑定指定回环源地址后连接 listener。 */
    [[nodiscard]] auto ConnectFromAddress(
        Tcp::socket &Socket,
        const Net::ip::address_v4 LocalAddress,
        const Tcp::endpoint Remote) -> Net::awaitable<bool>
    {
        boost::system::error_code Error;
        Socket.open(Tcp::v4(), Error);
        if (Error) co_return false;
        Socket.bind(Tcp::endpoint(LocalAddress, 0), Error);
        if (Error) co_return false;
        co_await Socket.async_connect(Remote, Net::redirect_error(Net::use_awaitable, Error));
        co_return !Error;
    }

    /** @brief 保存一次定长读取的回显、超时或关闭观察。 */
    struct SocketReadProbe final
    {
        bool ReadCompleted{false};
        bool EchoMatched{false};
        bool Closed{false};
    };

    /** @brief 在绝对等待窗口内读取固定 payload 或确认 peer 关闭。 */
    [[nodiscard]] auto ReadEchoOrClose(
        Tcp::socket &Socket,
        const std::string &Expected,
        const std::chrono::milliseconds Timeout) -> Net::awaitable<SocketReadProbe>
    {
        std::array<char, 64> Buffer{};
        if (Expected.size() > Buffer.size()) co_return SocketReadProbe{};
        boost::system::error_code ReadError;
        Net::steady_timer Timer(co_await Net::this_coro::executor);
        Timer.expires_after(Timeout);
        auto Read = [&]() -> Net::awaitable<std::size_t>
        {
            co_return co_await Net::async_read(
                Socket, Net::buffer(Buffer.data(), Expected.size()),
                Net::transfer_exactly(Expected.size()),
                Net::redirect_error(Net::use_awaitable, ReadError));
        };
        auto Wait = [&]() -> Net::awaitable<void>
        {
            boost::system::error_code TimerError;
            co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, TimerError));
        };
        using Net::experimental::awaitable_operators::operator||;
        const auto Result = co_await (Read() || Wait());
        if (Result.index() != 0U) co_return SocketReadProbe{};
        const auto Count = std::get<0>(Result);
        if (ReadError) co_return SocketReadProbe{true, false, true};
        const auto Echo = std::string_view(Buffer.data(), Count);
        co_return SocketReadProbe{true, Echo == std::string_view(Expected), false};
    }

    /** @brief 两 worker admission、活动 session 与 listener 关闭的 owning probe。 */
    struct WorkerDrainEchoProbe final
    {
        Prism::Runtime::Process &Process;
        Prism::Runtime::TcpListener &Listener;
        Net::io_context &Io;
        std::shared_ptr<Tcp::acceptor> EchoAcceptor;
        std::shared_ptr<WorkerDrainEchoState> State;
        std::shared_ptr<SessionIdentityEvents> EchoStopped;
        std::shared_ptr<Tcp::socket> Worker1Client;
        std::optional<Net::ip::address_v4> Worker1Address;
        std::optional<Net::ip::address_v4> Worker2Address;
        std::string Payload;
        std::expected<void, Prism::Fault::Failure> Drain{
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked})};
        bool ListenerStarted{false};
        bool Worker1Echoed{false};
        bool Worker1Closed{false};
        bool Worker1Fenced{false};
        bool Worker1Rejected{false};
        bool Worker2Echoed{false};
        bool Worker1SessionsEmpty{false};
        bool Worker1TasksDrained{false};
        bool Worker2Accepting{false};
        bool GroupStillAccepting{false};
        bool ListenerDrained{false};
    };

    /** @brief Prepare 后尚未成为 Session 的 carrier 与其 worker drain receipt。 */
    struct WorkerAdmissionReceiptProbe final
    {
        Process &ProcessValue;
        Net::io_context &Io;
        Tcp::acceptor &Acceptor;
        Tcp::socket &Client;
        std::shared_ptr<Prism::Runtime::Detail::ListenerConnectionGate::Quota> Quota;
        Prism::Runtime::AffinityBalancer &Balancer;
        std::shared_ptr<Prism::Runtime::GenerationPublication> Publication;
        const std::function<void(Prism::Fault::Code)> &OnFailure;
        std::shared_ptr<SessionIdentityEvents> DrainCompleted;
        WorkerId Worker{1};
        Net::ip::address_v4 WorkerAddress;
        std::optional<Prism::Runtime::Detail::PreparedListenerAdmission> Prepared;
        std::expected<void, Prism::Fault::Failure> Drain{
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked})};
        bool PrepareSucceeded{false};
        bool DrainFinished{false};
        bool DrainWaitedForReceipt{false};
        bool DrainWaitTimedOut{false};
    };

    /** @brief 并发运行 Worker drain 并通过 owning channel 发布真实 typed 结果。 */
    auto RunWorkerAdmissionReceiptDrain(WorkerAdmissionReceiptProbe &Probe)
        -> Net::awaitable<void>
    {
        Probe.Drain = co_await Probe.ProcessValue.Workers().DrainWorker(
            Probe.Worker, Probe.ProcessValue.Generation());
        Probe.DrainFinished = true;
        (void)Probe.DrainCompleted->try_send(boost::system::error_code{});
    }

    /** @brief 先保留未注册 admission，再验证 worker fence 等待真实拒绝 carrier 退役。 */
    auto RunWorkerAdmissionReceiptProbe(WorkerAdmissionReceiptProbe &Probe)
        -> Net::awaitable<void>
    {
        const auto Connected = co_await ConnectFromAddress(
            Probe.Client, Probe.WorkerAddress,
            Probe.Acceptor.local_endpoint());
        if (!Connected) co_return;
        boost::system::error_code AcceptError;
        auto Accepted = co_await Probe.Acceptor.async_accept(
            Net::redirect_error(Net::use_awaitable, AcceptError));
        if (AcceptError) co_return;
        auto Prepared = Prism::Runtime::Detail::ListenerAdmissionOwner::Prepare(
            std::move(Accepted), Prism::Runtime::Detail::ListenerAdmissionOwner::Dependencies{
                Probe.Io.get_executor(), Probe.Quota, Probe.Balancer,
                &Probe.ProcessValue.Workers(), Probe.Publication, Probe.OnFailure});
        if (!Prepared) co_return;
        Probe.Prepared.emplace(std::move(*Prepared));
        Probe.PrepareSucceeded = Probe.Prepared->Worker == Probe.Worker;
        if (!Probe.PrepareSucceeded) co_return;

        Net::co_spawn(Probe.Io, RunWorkerAdmissionReceiptDrain(Probe), Net::detached);
        Net::steady_timer AdmissionWindow(Probe.Io);
        AdmissionWindow.expires_after(std::chrono::milliseconds(20));
        co_await AdmissionWindow.async_wait(Net::use_awaitable);
        Probe.DrainWaitedForReceipt = !Probe.DrainFinished;

        Probe.Prepared->ConnectionSlot->ReleaseTransport();
        Probe.Prepared->RejectionDrain->Start();
        Net::steady_timer Deadline(Probe.Io);
        Deadline.expires_after(std::chrono::seconds(2));
        const auto Wait = [&]() -> Net::awaitable<void>
        {
            boost::system::error_code Error;
            co_await Probe.DrainCompleted->async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
        };
        const auto Timeout = [&]() -> Net::awaitable<void>
        {
            boost::system::error_code Error;
            co_await Deadline.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        };
        using Net::experimental::awaitable_operators::operator||;
        const auto Result = co_await (Wait() || Timeout());
        Probe.DrainWaitTimedOut = Result.index() != 0U;
    }

    /** @brief 接受所有 echo 上游连接，并在 acceptor 关闭后交付停止回执。 */
    auto RunWorkerDrainEchoAcceptor(
        const std::shared_ptr<Tcp::acceptor> &Acceptor,
        const Net::any_io_executor Executor,
        const std::shared_ptr<SessionIdentityEvents> &Stopped)
        -> Net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code Error;
            auto Socket = co_await Acceptor->async_accept(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error) break;
            Net::co_spawn(Executor, TcpEchoServer(std::move(Socket)), Net::detached);
        }
        (void)Stopped->try_send(boost::system::error_code{});
    }

    /** @brief 在 Worker1 建立实际 session，再等待 target worker 根 scope 退休。 */
    auto RunWorker1SessionDrain(WorkerDrainEchoProbe &Probe,
                                const Tcp::endpoint Endpoint) -> Net::awaitable<void>
    {
        Probe.Worker1Client = std::make_shared<Tcp::socket>(Probe.Io);
        const auto Connected = co_await ConnectFromAddress(
            *Probe.Worker1Client, *Probe.Worker1Address, Endpoint);
        if (!Connected) co_return;
        boost::system::error_code WriteError;
        co_await Net::async_write(*Probe.Worker1Client, Net::buffer(Probe.Payload),
            Net::redirect_error(Net::use_awaitable, WriteError));
        if (WriteError) co_return;
        const auto Echo = co_await ReadEchoOrClose(
            *Probe.Worker1Client, Probe.Payload, std::chrono::seconds(2));
        Probe.Worker1Echoed = Echo.EchoMatched;
        if (!Echo.EchoMatched) co_return;
        Probe.Drain = co_await Probe.Process.Workers().DrainWorker(
            WorkerId{1}, Probe.Process.Generation());
        if (!Probe.Drain) co_return;
        const auto Closed = co_await ReadEchoOrClose(
            *Probe.Worker1Client, Probe.Payload, std::chrono::seconds(2));
        Probe.Worker1Closed = Closed.Closed;
        auto *Worker1 = Probe.Process.Workers().Find(WorkerId{1});
        auto *Worker2 = Probe.Process.Workers().Find(WorkerId{2});
        if (Worker1 && Worker2)
        {
            const auto Worker1Snapshot = Worker1->Snapshot();
            Probe.Worker2Accepting = Worker2->IsAccepting();
            Probe.Worker1Fenced = !Worker1Snapshot.Accepting;
            Probe.Worker1TasksDrained = Worker1Snapshot.ActiveTasks == 0U &&
                Worker1Snapshot.MailboxSize == 0U;
            Probe.GroupStillAccepting = !Probe.Process.Workers().IsStopping();
        }
        if (Probe.Listener.Registry().Size() == 0U)
        {
            Probe.Worker1SessionsEmpty = true;
        }
        else
        {
            const auto Sessions = Probe.Listener.Registry().Snapshot();
            Probe.Worker1SessionsEmpty = true;
            for (const auto &[Id, Session] : *Sessions)
            {
                (void)Id;
                if (Session.Worker == WorkerId{1}) Probe.Worker1SessionsEmpty = false;
            }
        }
    }

    /** @brief 新的 Worker1 affinity 连接必须在工厂前被 admission fence 拒绝。 */
    auto ProbeFencedWorker1(WorkerDrainEchoProbe &Probe,
                            const Tcp::endpoint Endpoint) -> Net::awaitable<void>
    {
        Tcp::socket Client(Probe.Io);
        const auto Connected = co_await ConnectFromAddress(
            Client, *Probe.Worker1Address, Endpoint);
        if (!Connected)
        {
            Probe.Worker1Rejected = true;
            co_return;
        }
        boost::system::error_code WriteError;
        co_await Net::async_write(Client, Net::buffer(Probe.Payload),
            Net::redirect_error(Net::use_awaitable, WriteError));
        if (WriteError)
        {
            Probe.Worker1Rejected = true;
            co_return;
        }
        const auto Rejected = co_await ReadEchoOrClose(
            Client, Probe.Payload, std::chrono::seconds(1));
        Probe.Worker1Rejected = Rejected.Closed ||
            (Rejected.ReadCompleted && !Rejected.EchoMatched);
    }

    /** @brief Worker2 在同一 listener 上继续接受并回显相同 payload。 */
    auto ProbeHealthyWorker2(WorkerDrainEchoProbe &Probe,
                             const Tcp::endpoint Endpoint) -> Net::awaitable<void>
    {
        Tcp::socket Client(Probe.Io);
        const auto Connected = co_await ConnectFromAddress(
            Client, *Probe.Worker2Address, Endpoint);
        if (!Connected) co_return;
        boost::system::error_code WriteError;
        co_await Net::async_write(Client, Net::buffer(Probe.Payload),
            Net::redirect_error(Net::use_awaitable, WriteError));
        if (WriteError) co_return;
        const auto Echo = co_await ReadEchoOrClose(
            Client, Probe.Payload, std::chrono::seconds(2));
        Probe.Worker2Echoed = Echo.EchoMatched;
    }

    /** @brief 运行单 worker drain、另一 worker 回显及 listener 最终排空场景。 */
    auto RunWorkerDrainEchoProbe(WorkerDrainEchoProbe &Probe) -> Net::awaitable<void>
    {
        const auto Start = co_await Probe.Listener.Start(
            Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        Probe.ListenerStarted = Start == Prism::Fault::Code::Success;
        if (Probe.ListenerStarted && Probe.Worker1Address && Probe.Worker2Address)
        {
            const auto Endpoint = Probe.Listener.LocalEndpoint();
            co_await RunWorker1SessionDrain(Probe, Endpoint);
            if (Probe.Drain)
            {
                boost::system::error_code CloseError;
                if (Probe.Worker1Client) Probe.Worker1Client->close(CloseError);
                co_await ProbeFencedWorker1(Probe, Endpoint);
                co_await ProbeHealthyWorker2(Probe, Endpoint);
            }
        }
        if (Probe.ListenerStarted)
        {
            const auto Drained = co_await Probe.Listener.Shutdown();
            Probe.ListenerDrained = static_cast<bool>(Drained);
        }
        else
        {
            Probe.Listener.Stop();
        }
        boost::system::error_code CloseError;
        Probe.EchoAcceptor->close(CloseError);
        boost::system::error_code StoppedError;
        co_await Probe.EchoStopped->async_receive(
            Net::redirect_error(Net::use_awaitable, StoppedError));
    }

    static_assert(!std::is_copy_constructible_v<Process>);
    static_assert(!std::is_copy_constructible_v<Worker>);

    TEST(WorkerGroup, OwnsWorkersAndDispatchesOnWorkerExecutor)
    {
        Process::Options Options;
        Options.Id = ProcessId{3};
        Options.Generation = GenerationId{9};
        Options.WorkerCount = 2;
        Options.MailboxCapacity = 2;
        Process ProcessValue(Options);

        auto &Group = ProcessValue.Workers();
        ASSERT_EQ(Group.Size(), 2U);
        auto *WorkerValue = Group.Find(WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);

        bool OnExecutor = false;
        EXPECT_EQ(Group.Dispatch(WorkerId{1}, GenerationId{9}, [&OnExecutor, WorkerValue]
                                 { OnExecutor = WorkerValue->IsOnExecutor(); }),
                  WorkerDispatchResult::Accepted);
        EXPECT_GE(WorkerValue->Pump(), 1U);
        EXPECT_TRUE(OnExecutor);
    }

    TEST(WorkerGroup, PropagatesBytePoolOptionsToProcessAndAllWorkers)
    {
        Process::Options Options;
        Options.Id = ProcessId{31};
        Options.Generation = GenerationId{51};
        Options.WorkerCount = 2;
        Options.Bytes = Prism::Memory::BytePoolOptions{
            .BlockSize = 64U,
            .BlockCount = 8U,
            .InitialBlockCount = 2U,
            .GrowthBlockCount = 2U};
        Process ProcessValue(Options);

        const auto ProcessSnapshot = ProcessValue.Resources().Bytes->Snapshot();
        EXPECT_EQ(ProcessSnapshot.CapacityBytes, 128U);
        EXPECT_EQ(ProcessSnapshot.LimitBytes, 512U);
        for (std::uint64_t Index = 1; Index <= Options.WorkerCount; ++Index)
        {
            auto *WorkerValue = ProcessValue.Workers().Find(WorkerId{Index});
            ASSERT_NE(WorkerValue, nullptr);
            const auto WorkerSnapshot = WorkerValue->Resources().Bytes->Snapshot();
            EXPECT_EQ(WorkerSnapshot.CapacityBytes, 128U);
            EXPECT_EQ(WorkerSnapshot.LimitBytes, 512U);
        }
    }

    TEST(WorkerGroup, DrainsOneWorkerWhileAnotherWorkerContinuesEchoing)
    {
        Net::io_context Io;
        Process::Options Options;
        Options.Id = ProcessId{41};
        Options.Generation = GenerationId{61};
        Options.WorkerCount = 2;
        Options.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            Options.Generation);
        Process ProcessValue(Options);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        auto State = std::make_shared<WorkerDrainEchoState>();
        State->Executor = Io.get_executor();
        auto EchoAcceptor = std::make_shared<Tcp::acceptor>(
            Io, Tcp::endpoint(Tcp::v4(), 0));
        State->EchoPort = EchoAcceptor->local_endpoint().port();
        auto EchoStopped = std::make_shared<SessionIdentityEvents>(Io.get_executor(), 1U);
        Net::co_spawn(Io, RunWorkerDrainEchoAcceptor(
            EchoAcceptor, Io.get_executor(), EchoStopped), Net::detached);

        Prism::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Io.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = Options.Publication;
        ListenerOptions.Factory = WorkerDrainSessionFactory{State, &ProcessValue.Workers()};
        auto Listener = std::make_shared<Prism::Runtime::TcpListener>(
            std::move(ListenerOptions));
        const Prism::Runtime::AffinityBalancer Balancer(2);
        const auto Worker1Address = LocalAddressForWorker(Balancer, WorkerId{1});
        const auto Worker2Address = LocalAddressForWorker(Balancer, WorkerId{2});
        ASSERT_TRUE(Worker1Address);
        ASSERT_TRUE(Worker2Address);

        WorkerDrainEchoProbe Probe{
            ProcessValue, *Listener, Io, EchoAcceptor, State, EchoStopped,
            {}, Worker1Address, Worker2Address, "worker-drain-echo"};
        RunCoro(Io, RunWorkerDrainEchoProbe(Probe));

        EXPECT_TRUE(Probe.ListenerStarted);
        EXPECT_TRUE(Probe.Worker1Echoed);
        ASSERT_TRUE(Probe.Drain);
        EXPECT_TRUE(Probe.Worker1Closed);
        EXPECT_TRUE(Probe.Worker1Fenced);
        EXPECT_TRUE(Probe.Worker1TasksDrained);
        EXPECT_TRUE(Probe.Worker1SessionsEmpty);
        EXPECT_TRUE(Probe.Worker1Rejected);
        EXPECT_TRUE(Probe.Worker2Accepting);
        EXPECT_TRUE(Probe.GroupStillAccepting);
        EXPECT_TRUE(Probe.Worker2Echoed);
        EXPECT_EQ(State->SessionFactories[0].load(std::memory_order_acquire), 1U);
        EXPECT_EQ(State->SessionFactories[1].load(std::memory_order_acquire), 1U);
        EXPECT_TRUE(Probe.ListenerDrained);
    }

    TEST(WorkerGroup, PreparedRejectedAdmissionHoldsWorkerReceiptUntilCarrierRetires)
    {
        Net::io_context Io;
        Process::Options Options;
        Options.Id = ProcessId{42};
        Options.Generation = GenerationId{62};
        Options.WorkerCount = 2;
        Options.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            Options.Generation);
        Process ProcessValue(Options);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Tcp::acceptor Acceptor(
            Io, Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        Tcp::socket Client(Io);
        auto Quota = std::make_shared<Prism::Runtime::Detail::ListenerConnectionGate::Quota>(
            0, Io.get_executor());
        Prism::Runtime::AffinityBalancer Balancer(2);
        const auto WorkerAddress = LocalAddressForWorker(Balancer, WorkerId{1});
        ASSERT_TRUE(WorkerAddress);
        const std::function<void(Prism::Fault::Code)> OnFailure =
            [](Prism::Fault::Code) {};
        auto DrainCompleted = std::make_shared<SessionIdentityEvents>(Io.get_executor(), 1U);
        WorkerAdmissionReceiptProbe Probe{
            ProcessValue, Io, Acceptor, Client, Quota, Balancer, Options.Publication, OnFailure,
            DrainCompleted, WorkerId{1}, *WorkerAddress};

        RunCoro(Io, RunWorkerAdmissionReceiptProbe(Probe));

        EXPECT_TRUE(Probe.PrepareSucceeded);
        EXPECT_TRUE(Probe.DrainWaitedForReceipt);
        EXPECT_FALSE(Probe.DrainWaitTimedOut);
        ASSERT_TRUE(Probe.Prepared);
        ASSERT_TRUE(Probe.Drain);
        EXPECT_TRUE(Probe.Prepared->RejectionDrain->IsRetired());
        auto *Worker1 = ProcessValue.Workers().Find(WorkerId{1});
        auto *Worker2 = ProcessValue.Workers().Find(WorkerId{2});
        ASSERT_NE(Worker1, nullptr);
        ASSERT_NE(Worker2, nullptr);
        EXPECT_FALSE(Worker1->IsAccepting());
        EXPECT_EQ(Worker1->Snapshot().ActiveTasks, 0U);
        EXPECT_TRUE(Worker2->IsAccepting());
        EXPECT_FALSE(ProcessValue.Workers().IsStopping());
    }

    TEST(WorkerGroup, RejectsStaleGenerationAndStoppedWorker)
    {
        Process::Options Options;
        Options.Id = ProcessId{4};
        Options.Generation = GenerationId{12};
        Options.WorkerCount = 1;
        Process ProcessValue(Options);

        auto *WorkerValue = ProcessValue.Workers().Find(WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);
        EXPECT_EQ(ProcessValue.Workers().Dispatch(WorkerId{1}, GenerationId{13}, [] {}),
                  WorkerDispatchResult::GenerationRejected);

        WorkerValue->Stop();
        EXPECT_EQ(ProcessValue.Workers().Dispatch(WorkerId{1}, GenerationId{12}, [] {}),
                  WorkerDispatchResult::WorkerUnavailable);
    }

    TEST(WorkerGroup, PublishesWorkerSnapshot)
    {
        Process::Options Options;
        Options.Id = ProcessId{5};
        Options.Generation = GenerationId{15};
        Options.WorkerCount = 1;
        Options.MailboxCapacity = 3;
        Process ProcessValue(Options);

        auto *WorkerValue = ProcessValue.Workers().Find(WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);
        EXPECT_EQ(WorkerValue->Dispatch(GenerationId{15}, [] {}), WorkerDispatchResult::Accepted);
        EXPECT_GE(WorkerValue->Pump(), 1U);

        const auto Snapshot = WorkerValue->Snapshot();
        EXPECT_EQ(Snapshot.Id, WorkerId{1});
        EXPECT_EQ(Snapshot.Generation, GenerationId{15});
        EXPECT_EQ(Snapshot.MailboxCapacity, 3U);
        EXPECT_EQ(Snapshot.MailboxSize, 0U);
        EXPECT_EQ(Snapshot.DispatchAccepted, 1U);
        EXPECT_EQ(Snapshot.CommandsExecuted, 1U);

        const auto GroupSnapshot = ProcessValue.Workers().Snapshot();
        ASSERT_EQ(GroupSnapshot.size(), 1U);
        EXPECT_EQ(GroupSnapshot.front().Id, WorkerId{1});
    }

    TEST(WorkerGroup, PreservesBoundedMailboxAdmissionResults)
    {
        Process::Options Options;
        Options.Id = ProcessId{6};
        Options.Generation = GenerationId{18};
        Options.WorkerCount = 1;
        Options.MailboxCapacity = 1;
        Process ProcessValue(Options);

        auto *WorkerValue = ProcessValue.Workers().Find(WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);

        EXPECT_EQ(WorkerValue->Dispatch(GenerationId{18}, [] {}), WorkerDispatchResult::Accepted);
        EXPECT_EQ(WorkerValue->Dispatch(GenerationId{18}, [] {}), WorkerDispatchResult::Full);

        WorkerTestAccess::CloseMailbox(*WorkerValue);
        EXPECT_EQ(WorkerValue->Dispatch(GenerationId{18}, [] {}), WorkerDispatchResult::Closed);

        WorkerValue->Stop();
        EXPECT_EQ(WorkerValue->Dispatch(GenerationId{18}, [] {}),
                  WorkerDispatchResult::WorkerUnavailable);
    }

    TEST(WorkerGroup, SessionControlObservesWorkerRegistryCancellation)
    {
        Process::Options Options;
        Options.Id = ProcessId{8};
        Options.Generation = GenerationId{24};
        Options.WorkerCount = 1;
        Process ProcessValue(Options);

        auto *WorkerValue = ProcessValue.Workers().Find(WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);
        Prism::Runtime::SessionControl Control;
        ASSERT_TRUE(Control.Bind(WorkerValue->Executor(), WorkerValue->TaskRegistry()));
        EXPECT_FALSE(Control.IsCancelled());

        WorkerValue->Stop();
        EXPECT_TRUE(Control.IsCancelled());
        Prism::Lifecycle::TaskRequest FollowUp;
        EXPECT_FALSE(Control.Start(
            std::move(FollowUp),
            []() -> boost::asio::awaitable<void> { co_return; }()));
    }

    TEST(WorkerGroup, SessionScopesIsolateCancelAndShareWorkerShutdown)
    {
        Process::Options Options;
        Options.Id = ProcessId{7};
        Options.Generation = GenerationId{21};
        Options.WorkerCount = 1;
        Process ProcessValue(Options);

        auto *WorkerValue = ProcessValue.Workers().Find(WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);
        EXPECT_EQ(&WorkerValue->TaskRegistry(), WorkerValue->Resources().Tasks.get());
        Prism::Runtime::SessionControl FirstControl;
        Prism::Runtime::SessionControl SecondControl;
        ASSERT_TRUE(FirstControl.Bind(WorkerValue->Executor(), WorkerValue->TaskRegistry()));
        ASSERT_TRUE(SecondControl.Bind(WorkerValue->Executor(), WorkerValue->TaskRegistry()));

        Prism::Lifecycle::TaskRequest FirstRequest;
        FirstRequest.Context.SessionId = Prism::SessionId{101};
        FirstRequest.Context.WorkerId = WorkerId{1};
        FirstRequest.Context.Generation = GenerationId{21};
        Prism::Lifecycle::TaskRequest SecondRequest = FirstRequest;
        SecondRequest.Context.SessionId = Prism::SessionId{102};

        EXPECT_TRUE(FirstControl.Start(
            std::move(FirstRequest),
            []() -> boost::asio::awaitable<void> { co_return; }()));
        EXPECT_TRUE(SecondControl.Start(
            std::move(SecondRequest),
            []() -> boost::asio::awaitable<void> { co_return; }()));
        EXPECT_NE(FirstControl.CurrentIdentity().TaskId, SecondControl.CurrentIdentity().TaskId);
        EXPECT_EQ(WorkerValue->Snapshot().ActiveTasks, 2U);

        FirstControl.Cancel();
        EXPECT_TRUE(FirstControl.IsCancelled());
        EXPECT_FALSE(SecondControl.IsCancelled());

        Prism::Lifecycle::TaskRequest FollowUp;
        FollowUp.Context.SessionId = Prism::SessionId{103};
        FollowUp.Context.WorkerId = WorkerId{1};
        FollowUp.Context.Generation = GenerationId{21};
        EXPECT_TRUE(SecondControl.Start(
            std::move(FollowUp),
            []() -> boost::asio::awaitable<void> { co_return; }()));

        WorkerValue->Stop();
        EXPECT_TRUE(SecondControl.IsCancelled());
    }

    TEST(WorkerResources, EmptyStopAndDestructorReleaseExecutionAndPmrOwner)
    {
        std::weak_ptr<Prism::Executor::ContextOwner> Weak;
        {
            Worker Value;
            Weak = Value.Resources().Execution;
            ASSERT_EQ(Value.TaskRegistry().Stats().Active, 0);
            std::pmr::vector<std::byte> Buffer(Value.Resources().MemoryResource);
            Buffer.resize(256);
            Value.Stop();
        }
        EXPECT_TRUE(Weak.expired());
        EXPECT_EQ(Prism::Executor::ClosingStorage::ProcessStorage()->Pending(), 0);
    }

    TEST(WorkerResources, QueuedNotificationAndEmptyStopDoNotPinDestroyedWorkerContext)
    {
        std::weak_ptr<Prism::Executor::ContextOwner> Weak;
        {
            Worker Value;
            Weak = Value.Resources().Execution;
            EXPECT_EQ(Value.Dispatch(Value.Generation(), [] {}), WorkerDispatchResult::Accepted);
            Value.Stop();
        }
        EXPECT_TRUE(Weak.expired());
        EXPECT_EQ(Prism::Executor::ClosingStorage::ProcessStorage()->Pending(), 0);
    }
} // namespace
