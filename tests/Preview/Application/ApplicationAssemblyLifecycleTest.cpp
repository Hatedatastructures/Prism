/**
 * @file ApplicationAssemblyLifecycleTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ApplicationTestSupport.hpp"
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Application/Shutdown/DrainStages.hpp>
#include <Preview/Application/Shutdown/GenerationRetirement.hpp>
#include <Preview/Application/Startup/Start.hpp>
#include <Preview/Composition/Provider/ProviderCatalog.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/deferred.hpp>
#include <atomic>

namespace
{
/**
 * @brief 验证空闲数据转发超时后双方传输都已关闭。
 */
auto VerifyIdleRelayClosesBothTransports() -> void
{
    Net::io_context Io;
    auto Inbound = std::make_shared<Preview::PreviewMockTransport>(Net::make_strand(Io.get_executor()));
    auto Outbound = std::make_shared<Preview::PreviewMockTransport>(Net::make_strand(Io.get_executor()));
    auto Relay = std::make_shared<Preview::Network::StreamRelayService>(
        Preview::Network::StreamRelayOptions{
            .BufferSize = 64,
            .IdleTimeout = std::chrono::milliseconds(20),
            .Bytes = std::make_shared<Preview::Memory::BytePool>(Preview::Memory::BytePoolOptions{.BlockCount = 8})});
    bool Done = false;
    std::exception_ptr Failure;
    Preview::Fault::Failure BusinessFailure;
    Net::co_spawn(
        Io,
        Relay->Run({Inbound, Outbound}),
        [&](std::exception_ptr Error, std::expected<void, Preview::Fault::Failure> Result)
        {
            if (!Result) BusinessFailure = Result.error();
            Failure = Error;
            Done = true;
        });
    std::thread WorkerA([&Io] { Io.run(); });
    std::thread WorkerB([&Io] { Io.run(); });
    WorkerA.join();
    WorkerB.join();
    EXPECT_TRUE(Done);
    EXPECT_EQ(Failure, nullptr);
    EXPECT_FALSE(Inbound->IsOpen());
    EXPECT_FALSE(Outbound->IsOpen());
}

class FailOnceOnCloseTransport final : public Preview::Transmission
{
public:
    FailOnceOnCloseTransport(std::shared_ptr<Preview::PreviewMockTransport> Inner,
        std::shared_ptr<std::atomic<unsigned>> CloseAttempts)
        : Preview::Transmission(Inner->Executor()), Inner_(std::move(Inner)),
          CloseAttempts_(std::move(CloseAttempts)) {}

    [[nodiscard]] auto Executor() const -> Net::any_io_executor override
    {
        return Inner_->Executor();
    }

    auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
    {
        Inner_->ReadSome(Buffer, std::move(Handler));
    }

    auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
    {
        Inner_->WriteSome(Buffer, std::move(Handler));
    }

    auto StartWriteShutdown(Completion Handler) -> void override
    {
        Inner_->WriteShutdown(std::move(Handler));
    }

    [[nodiscard]] auto OnClose() -> ControlResult override
    {
        if (CloseAttempts_->fetch_add(1, std::memory_order_acq_rel) == 0)
        {
            (void)Inner_->Close();
            return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::IoError});
        }
        return Inner_->Close();
    }

    [[nodiscard]] auto OnCancel() -> ControlResult override
    {
        (void)Inner_->Cancel();
        return {};
    }

private:
    std::shared_ptr<Preview::PreviewMockTransport> Inner_;
    std::shared_ptr<std::atomic<unsigned>> CloseAttempts_;
};
}

TEST(PreviewApplication, ProfileFailureReleasesBackendWhileFailedApplicationLives)
{
    TemporaryConfiguration Invalid(FindFreePort(),
        ConfigurationShape{.Recognition = R"({"Mode":"Configured","ConfiguredCandidate":127})",
            .OperationsPort = FindFreePort()});
    std::ostringstream Output;
    Preview::Application::Application Failed(MakeOptions(Invalid.Path(), &Output));
    const auto Rejected = Failed.Start();
    ASSERT_FALSE(Rejected.has_value());
    EXPECT_FALSE(Failed.IsReady());
    EXPECT_TRUE(Output.str().empty());
    EXPECT_EQ(Rejected.error().Code, Preview::Application::StartupErrorCode::Generation);
    EXPECT_EQ(Rejected.error().Path, "Protocols");
    EXPECT_NE(Rejected.error().Message.find("profile build failed"), std::string::npos);

    TemporaryConfiguration Valid(FindFreePort(), ConfigurationShape{.OperationsPort = FindFreePort()});
    Preview::Application::Application Success(MakeOptions(Valid.Path()));
    const auto Started = Success.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    Success.Stop();
    EXPECT_EQ(Success.Run(), 0);
    EXPECT_TRUE(Success.IsStopped());
}

TEST(PreviewApplicationMux, StreamHandlerRetainsDomainServicesWithoutRetainingRoot)
{
    auto Services = std::make_shared<Preview::Runtime::SessionServices>();
    const auto WeakRoot = std::weak_ptr<Preview::Runtime::SessionServices>(Services);
    auto Egress = std::make_shared<Preview::Testing::StreamEgress>(Services->Dial);
    const auto WeakEgress = std::weak_ptr<Preview::Contract::StreamEgress>(Egress);
    auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
    const auto WeakUseState = std::weak_ptr<Preview::Foundation::GenerationUseState>(UseState);
    auto Binding = std::make_shared<Preview::Mux::RootBinding>(Preview::Mux::RootOptions{
        .Services = {.Egress = std::move(Egress), .Traffic = Services->Traffic},
        .GenerationUseState = UseState});
    UseState.reset();
    Services.reset();
    EXPECT_TRUE(WeakRoot.expired());
    EXPECT_FALSE(WeakEgress.expired());
    Binding->Close();
    Binding.reset();
    EXPECT_TRUE(WeakEgress.expired());
    EXPECT_TRUE(WeakUseState.expired());
}

TEST(PreviewApplicationMux, ProductionAssemblyReleasesRootAndMuxServiceAfterRollback)
{
    TemporaryConfiguration Config(FindFreePort(), ConfigurationShape{.OperationsPort = FindFreePort()});
    const auto Phase = Preview::Application::Startup::GenerationPhase::Build({Config.Path(), {}});
    ASSERT_TRUE(Phase.has_value());
    std::weak_ptr<Preview::Runtime::SessionServices> WeakServices;
    std::weak_ptr<Preview::Foundation::TrafficSink> WeakTraffic;
    std::weak_ptr<Preview::Network::Dns::Resolver> WeakResolver;
    {
        auto Runtime =
            std::make_shared<Preview::Application::Application::RuntimeState>(2, Phase->Generation->Id(),
                Preview::Application::Assembly::MakeDnsConfig(Phase->Generation->Configuration().Dns));
        Preview::Application::Startup::StartupTransaction Transaction(Runtime);
        Runtime->Generation = Phase->Generation;
        Runtime->Accounts = Phase->Accounts;
        ASSERT_TRUE(Preview::Application::Startup::ProcessServices::Build(Runtime, *Phase).has_value());
        ASSERT_TRUE(
            Preview::Application::Startup::ProtocolServices::Prepare(Runtime, Config.Path()).has_value());
        ASSERT_TRUE(Preview::Application::Startup::ProtocolServices::Bind(Runtime, *Phase).has_value());
        ASSERT_TRUE(Runtime->ProviderBindings);
        WeakServices = Runtime->Services;
        WeakTraffic = Runtime->Services->Traffic;
        WeakResolver = Runtime->DnsResolver;
        EXPECT_FALSE(WeakServices.expired());
    }
    EXPECT_TRUE(WeakServices.expired());
    EXPECT_TRUE(WeakTraffic.expired());
    EXPECT_TRUE(WeakResolver.expired());
}

TEST(PreviewApplicationStatistics, DisabledConfigurationInstallsNoObserverOrTimer)
{
    TemporaryConfiguration Config(FindFreePort(), ConfigurationShape{
        .OperationsPort = FindFreePort(), .StatisticsEnabled = false});
    const auto Phase = Preview::Application::Startup::GenerationPhase::Build({Config.Path(), {}});
    ASSERT_TRUE(Phase);
    auto Runtime = std::make_shared<Preview::Application::Application::RuntimeState>(
        2, Phase->Generation->Id(), Preview::Network::Dns::Config{});
    Preview::Application::Startup::StartupTransaction Transaction(Runtime);
    Runtime->Generation = Phase->Generation;
    Runtime->Accounts = Phase->Accounts;
    const auto OriginalExpiry = Runtime->StatisticsFlushTimer.expiry();
    ASSERT_TRUE(Preview::Application::Startup::ProcessServices::Build(Runtime, *Phase));
    EXPECT_FALSE(Runtime->Traffic);
    EXPECT_FALSE(Runtime->Services->Traffic);
    EXPECT_FALSE(Runtime->Services->RecognitionLatency);
    EXPECT_EQ(Runtime->StatisticsFlushTimer.expiry(), OriginalExpiry);
    EXPECT_EQ(Runtime->StatisticsFlushArmedIntervalMilliseconds.load(), 0);
}

TEST(PreviewApplicationStatistics, ConfiguredIntervalFlushesTheSameOperationsCounters)
{
    TemporaryConfiguration Config(FindFreePort(), ConfigurationShape{
        .OperationsPort = FindFreePort(), .StatisticsInterval = 10});
    const auto Phase = Preview::Application::Startup::GenerationPhase::Build({Config.Path(), {}});
    ASSERT_TRUE(Phase);
    ASSERT_TRUE(Phase->Accounts.Identities);
    const auto& Configuration = Phase->Generation->Configuration();
    auto Runtime = std::make_shared<Preview::Application::Application::RuntimeState>(
        Configuration.Runtime.WorkerCount, Phase->Generation->Id(),
        Preview::Application::Assembly::MakeDnsConfig(Configuration.Dns));
    const auto AdmissionAuthority = Phase->Accounts.Identities->RuntimeRegistry()->AttachAdmissionAuthority(
        Runtime->GenerationPublisher);
    ASSERT_TRUE(AdmissionAuthority);
    Preview::Application::ObserveClosingFailures(Runtime);
    Preview::Application::Startup::StartupTransaction Transaction(Runtime);
    Runtime->Generation = Phase->Generation;
    Runtime->Accounts = Phase->Accounts;
    const auto Started = Preview::Application::StartupRuntime(Runtime, *Phase, Config.Path());
    ASSERT_TRUE(Started.has_value()) << Started.error().Path << ": " << Started.error().Message;
    ASSERT_TRUE(Runtime->GenerationPublisher->Contains(Phase->Generation->Id()));
    ASSERT_TRUE(Runtime->Traffic);
    EXPECT_EQ(Runtime->Services->Traffic.get(), Runtime->Traffic.get());
    EXPECT_EQ(Runtime->Services->RecognitionLatency.get(), Runtime->Traffic.get());
    EXPECT_EQ(Runtime->StatisticsFlushInterval, std::chrono::milliseconds{10});
    EXPECT_EQ(Runtime->StatisticsFlushArmedIntervalMilliseconds.load(), 10);
    Runtime = Transaction.Commit();
    Runtime->Services->Traffic->Report({.Generation = Phase->Generation->Id(),
        .Worker = Preview::WorkerId{1}, .Session = Preview::SessionId{22},
        .Account = Preview::AccountId{11}, .Up = 37, .Down = 41});
    EXPECT_EQ(Runtime->Traffic->Accepted(), 1U);
    EXPECT_EQ(Runtime->Traffic->Dropped(), 0U);
    EXPECT_EQ(Runtime->Traffic->Value(Preview::Statistics::Scope::Account, 11).UpBytes, 0U);
    std::exception_ptr Failure;
    Net::co_spawn(Runtime->Io, ObserveTrafficInterval(Runtime),
        [&Failure](std::exception_ptr Error) { Failure = Error; });
    Runtime->Io.run();
    EXPECT_FALSE(Failure);
    EXPECT_TRUE(Runtime->StopCompleted.load());
    EXPECT_EQ(Runtime->ExitCode, 0);
    EXPECT_TRUE(Runtime->Traffic->IsSealed());
    EXPECT_EQ(Runtime->Traffic->Value(Preview::Statistics::Scope::Session, 22).UpBytes, 37U);
    Preview::Application::Shutdown::FinalizeRuntimeResources(Runtime);
    EXPECT_FALSE(Runtime->Generation);
}

TEST(PreviewApplicationStatistics, ShutdownConsumesPendingBytesBeforeReleasingGeneration)
{
    TemporaryConfiguration Config(FindFreePort(), ConfigurationShape{
        .OperationsPort = FindFreePort(), .StatisticsInterval = 60000});
    const auto Phase = Preview::Application::Startup::GenerationPhase::Build({Config.Path(), {}});
    ASSERT_TRUE(Phase);
    ASSERT_TRUE(Phase->Accounts.Identities);
    const auto& Configuration = Phase->Generation->Configuration();
    auto Runtime = std::make_shared<Preview::Application::Application::RuntimeState>(
        Configuration.Runtime.WorkerCount, Phase->Generation->Id(),
        Preview::Application::Assembly::MakeDnsConfig(Configuration.Dns));
    const auto AdmissionAuthority = Phase->Accounts.Identities->RuntimeRegistry()->AttachAdmissionAuthority(
        Runtime->GenerationPublisher);
    ASSERT_TRUE(AdmissionAuthority);
    Preview::Application::ObserveClosingFailures(Runtime);
    Preview::Application::Startup::StartupTransaction Transaction(Runtime);
    Runtime->Generation = Phase->Generation;
    Runtime->Accounts = Phase->Accounts;
    const auto Started = Preview::Application::StartupRuntime(Runtime, *Phase, Config.Path());
    ASSERT_TRUE(Started.has_value()) << Started.error().Path << ": " << Started.error().Message;
    auto Counter = Runtime->Traffic;
    ASSERT_TRUE(Counter);
    Runtime = Transaction.Commit();
    Counter->Report({.Generation = Phase->Generation->Id(), .Worker = Preview::WorkerId{2},
        .Session = Preview::SessionId{22}, .Account = Preview::AccountId{11}, .Up = 13, .Down = 17});
    EXPECT_EQ(Counter->ConsumedObservations(), 0U);
    EXPECT_EQ(Counter->Accepted(), 1U);
    EXPECT_EQ(Counter->Dropped(), 0U);
    Preview::Application::Shutdown::ScheduleShutdown(Runtime);
    Runtime->Io.run();
    EXPECT_TRUE(Runtime->StopCompleted.load());
    EXPECT_EQ(Runtime->ExitCode, 0);
    EXPECT_TRUE(Runtime->Generation);
    EXPECT_TRUE(Counter->IsSealed());
    EXPECT_EQ(Counter->ConsumedObservations(), 1U);
    EXPECT_EQ(Counter->Value(Preview::Statistics::Scope::Account, 11).DownBytes, 17U);
    Counter->Finish();
    EXPECT_EQ(Counter->Value(Preview::Statistics::Scope::Account, 11).Events, 1U);
    Preview::Application::Shutdown::FinalizeRuntimeResources(Runtime);
    EXPECT_FALSE(Runtime->Generation);
    EXPECT_FALSE(Runtime->Services);
    EXPECT_FALSE(Runtime->Traffic);
    EXPECT_EQ(Counter->Value(Preview::Statistics::Scope::Worker, 2).UpBytes, 13U);
}

TEST(PreviewApplicationMux, ChildCoroutineOwnsSnapshotUntilActualHandlerDrains)
{
    class Traffic final : public Preview::Foundation::TrafficSink
    {
    public:
        auto Report(Preview::Foundation::TrafficEvent) noexcept -> void override {}
        auto Retire(Preview::Foundation::TrafficRetirement Owner)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Preview::Fault::Failure>{}; }
    };
    Net::io_context Io;
    auto Services = std::make_shared<Preview::Runtime::SessionServices>();
    Services->Traffic = std::make_shared<Traffic>();
    const auto WeakTraffic = std::weak_ptr<Preview::Foundation::TrafficSink>(Services->Traffic);
    const auto WeakRoot = std::weak_ptr<Preview::Runtime::SessionServices>(Services);
    auto Stream = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
    auto Outbound = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
    auto Relay = std::make_shared<Preview::Network::StreamRelayService>(
        Preview::Network::StreamRelayOptions{.Traffic = Services->Traffic,
            .Bytes = std::make_shared<Preview::Memory::BytePool>(Preview::Memory::BytePoolOptions{.BlockCount = 8})});
    Preview::Contract::StreamRelayRequest Request;
    Request.Inbound=Stream; Request.Outbound=Outbound;
    auto Operation = Relay->Run(std::move(Request));
    Services.reset();
    EXPECT_TRUE(WeakRoot.expired());
    EXPECT_FALSE(WeakTraffic.expired());
    bool Completed = false, OwnerObservedDuringRead = false;
    std::exception_ptr Failure;
    Preview::Fault::Failure BusinessFailure;
    Net::co_spawn(Io, std::move(Operation), [&](std::exception_ptr Error, std::expected<void, Preview::Fault::Failure> Result)
        { Failure = Error; if (!Result) BusinessFailure = Result.error(); Completed = true; });
    const auto Driver = [&]() -> Net::awaitable<void>
    {
        Net::steady_timer Timer(Io, std::chrono::milliseconds(10));
        co_await Timer.async_wait(Net::use_awaitable);
        Relay.reset();
        OwnerObservedDuringRead = !WeakTraffic.expired() && Stream->ReadsDone > 0;
        (void)Stream->Close(); (void)Outbound->Close();
    };
    Net::co_spawn(Io, Driver(), [](std::exception_ptr Error) { EXPECT_FALSE(Error); });
    Io.run();
    EXPECT_TRUE(Completed); EXPECT_EQ(Failure, nullptr); EXPECT_TRUE(OwnerObservedDuringRead);
    EXPECT_TRUE(WeakTraffic.expired()); EXPECT_FALSE(Stream->IsOpen()); EXPECT_FALSE(Outbound->IsOpen());
}

TEST(PreviewApplicationMux, SingMuxHandlerRelaysBothDirectionsAndReleasesTrafficAfterDrain)
{
    struct Totals final
    {
        using Signal = Net::experimental::channel<void(boost::system::error_code)>;
        explicit Totals(Net::any_io_executor Executor) : WritesCompleted(std::move(Executor), 1) {}
        std::size_t Up{0}, Down{0}, Calls{0}, ByteCalls{0};
        Signal WritesCompleted;
    };
    class Traffic final : public Preview::Foundation::TrafficSink
    {
    public:
        explicit Traffic(std::shared_ptr<Totals> Result) : Result_(std::move(Result)) {}
        auto Report(Preview::Foundation::TrafficEvent Event) noexcept -> void override
        {
            Result_->Up += Event.Up; Result_->Down += Event.Down;
            if (Event.Kind == Preview::Foundation::TrafficEventKind::Completed) ++Result_->Calls;
            else ++Result_->ByteCalls;
            if (Result_->Up >= 2 && Result_->Down >= 4)
                (void)Result_->WritesCompleted.try_send(boost::system::error_code{});
        }
        auto Retire(Preview::Foundation::TrafficRetirement Owner)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Preview::Fault::Failure>{}; }
    private:
        std::shared_ptr<Totals> Result_;
    };
    Net::io_context Io;
    auto Result = std::make_shared<Totals>(Io.get_executor());
    auto Services = std::make_shared<Preview::Runtime::SessionServices>();
    Services->Traffic = std::make_shared<Traffic>(Result);
    const auto WeakRoot = std::weak_ptr<Preview::Runtime::SessionServices>(Services);
    const auto WeakTraffic = std::weak_ptr<Preview::Foundation::TrafficSink>(Services->Traffic);
    auto Inbound = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
    auto Outbound = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
    Inbound->ToRead = {'U', 'P'};
    Outbound->ToRead = {'D', 'O', 'W', 'N'};
    Preview::Network::Target Target;
    Target.Host = *Preview::Network::ParseHost("echo"); Target.Port = 80;
    auto Relay = std::make_shared<Preview::Network::StreamRelayService>(
        Preview::Network::StreamRelayOptions{.Traffic = Services->Traffic,
            .Bytes = std::make_shared<Preview::Memory::BytePool>(Preview::Memory::BytePoolOptions{.BlockCount = 8})});
    auto Operation = Relay->Run({std::make_shared<Preview::Mux::SingMux::ServerStream>(Inbound, Target),
        Outbound, Target});
    Services.reset();
    EXPECT_TRUE(WeakRoot.expired()); EXPECT_FALSE(WeakTraffic.expired());
    bool Completed = false, OwnerObservedDuringRelay = false;
    Preview::Fault::Code Code = Preview::Fault::Code::IoError;
    std::exception_ptr Failure;
    Net::co_spawn(Io, std::move(Operation), [&](std::exception_ptr Error, std::expected<void, Preview::Fault::Failure> Result)
        { Failure = Error; if (Result) Code = Preview::Fault::Code::Success; else Code = Result.error().Code; Completed = true; });
    const auto Driver = [&]() -> Net::awaitable<void>
    {
        co_await Result->WritesCompleted.async_receive(Net::use_awaitable);
        Relay.reset();
        OwnerObservedDuringRelay = !WeakTraffic.expired() && Result->Up == 2 && Result->Down == 4;
        Inbound->InjectPeerEof();
        Outbound->InjectPeerEof();
    };
    Net::co_spawn(Io, Driver(), Net::detached);
    Io.run();
    EXPECT_TRUE(Completed);
    EXPECT_EQ(Failure, nullptr);
    EXPECT_EQ(Code, Preview::Fault::Code::Success);
    EXPECT_TRUE(OwnerObservedDuringRelay);
    EXPECT_EQ(Outbound->Written, (std::vector<std::uint8_t>{'U', 'P'}));
    EXPECT_EQ(Inbound->Written, (std::vector<std::uint8_t>{0, 'D', 'O', 'W', 'N'}));
    EXPECT_EQ(Result->Up, 2U);
    EXPECT_EQ(Result->Down, 4U);
    EXPECT_EQ(Result->Calls, 1U);
    EXPECT_TRUE(WeakTraffic.expired());
}

TEST(PreviewApplicationMux, RelayStrandDrainsIdleAndWriteErrorOnTwoWorkers)
{
    VerifyIdleRelayClosesBothTransports();

    Net::io_context Io;
    auto RunWorkers = [&Io]
    {
        std::thread WorkerA([&Io] { Io.run(); });
        std::thread WorkerB([&Io] { Io.run(); });
        WorkerA.join();
        WorkerB.join();
    };

    auto CloseInboundRaw = std::make_shared<Preview::PreviewMockTransport>(Net::make_strand(Io.get_executor()));
    const auto CloseAttempts = std::make_shared<std::atomic<unsigned>>(0);
    auto CloseInbound = std::make_shared<FailOnceOnCloseTransport>(CloseInboundRaw, CloseAttempts);
    auto CloseOutbound = std::make_shared<Preview::PreviewMockTransport>(Net::make_strand(Io.get_executor()));
    const auto Storage = Preview::Executor::ContextOwner::Storage(Io.get_executor());
    Preview::Network::Relay::Result CloseResult;
    bool CloseDone = false;
    bool RetryTimedOut = false;
    std::exception_ptr CloseFailure;
    Net::co_spawn(
        Io,
        Preview::Network::Relay::Run(
            {CloseInbound, CloseOutbound, 64, std::chrono::milliseconds(20), {},
             std::make_shared<Preview::Memory::BytePool>(Preview::Memory::BytePoolOptions{.BlockCount = 8})}),
        [&](std::exception_ptr Error, Preview::Network::Relay::Result Result)
        {
            CloseFailure = Error;
            CloseResult = std::move(Result);
            CloseDone = true;
        });
    const auto RetryClose = [&]() -> Net::awaitable<void>
    {
        Net::steady_timer Timer(Io);
        for (std::size_t Attempt = 0;
            Attempt < 5000 && CloseAttempts->load(std::memory_order_acquire) < 2; ++Attempt)
        {
            Storage->Retry();
            Timer.expires_after(std::chrono::milliseconds(1));
            co_await Timer.async_wait(Net::use_awaitable);
        }
        RetryTimedOut = CloseAttempts->load(std::memory_order_acquire) < 2;
        if (RetryTimedOut) Io.stop();
    };
    Net::co_spawn(Io, RetryClose(), Net::detached);
    RunWorkers();
    ASSERT_FALSE(RetryTimedOut);
    EXPECT_TRUE(CloseDone);
    EXPECT_EQ(CloseFailure, nullptr);
    EXPECT_EQ(CloseResult.Failure.Code, Preview::Fault::Code::Timeout);
    EXPECT_EQ(CloseAttempts->load(std::memory_order_acquire), 2U);
    EXPECT_TRUE(CloseInbound->Activity()->IsRetired());
    EXPECT_FALSE(CloseInboundRaw->IsOpen());
    EXPECT_FALSE(CloseOutbound->IsOpen());

    Io.restart();
    auto ErrorInbound = std::make_shared<Preview::PreviewMockTransport>(Net::make_strand(Io.get_executor()));
    auto ErrorOutbound = std::make_shared<Preview::PreviewMockTransport>(Net::make_strand(Io.get_executor()));
    ErrorInbound->ToRead = {0x01U, 0x02U, 0x03U};
    ErrorInbound->EofOnDrain = true;
    ErrorOutbound->FailNextWrite = true;
    auto ErrorRelay = std::make_shared<Preview::Network::StreamRelayService>(
        Preview::Network::StreamRelayOptions{.BufferSize = 64,
            .Bytes = std::make_shared<Preview::Memory::BytePool>(Preview::Memory::BytePoolOptions{.BlockCount = 8})});
    bool ErrorDone = false;
    std::exception_ptr ErrorFailure;
    Preview::Fault::Failure ErrorBusinessFailure;
    Net::co_spawn(
        Io,
        ErrorRelay->Run({ErrorInbound, ErrorOutbound}),
        [&](std::exception_ptr Error, std::expected<void, Preview::Fault::Failure> Result)
        {
            if (!Result) ErrorBusinessFailure = Result.error();
            ErrorFailure = Error;
            ErrorDone = true;
        });
    RunWorkers();
    EXPECT_TRUE(ErrorDone);
    EXPECT_EQ(ErrorFailure, nullptr);
    EXPECT_TRUE(ErrorInbound->IsOpen() == false);
    EXPECT_TRUE(ErrorOutbound->IsOpen() == false);
}
