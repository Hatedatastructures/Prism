/**
 * @file AssemblyLifecycleTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "StartupSupport.hpp"
#include <Prism/Account/Policy.hpp>
#include <Prism/Account/UsagePersistence.hpp>
#include <Prism/Application/Reload/Transaction/Detail/Publication.hpp>
#include <Prism/Application/Shutdown/Detail/ClosingFailure.hpp>
#include <Prism/Application/Configuration/GenerationBuilder.hpp>
#include <Prism/Application/Storage/Detail/Lifecycle.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Application/Shutdown/Detail/DrainStages.hpp>
#include <Prism/Application/Shutdown/Detail/GenerationRetirement.hpp>
#include <Prism/Application/Startup/Detail/Runtime.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/deferred.hpp>
#include <atomic>
#include <optional>

namespace
{
/**
 * @brief 验证空闲数据转发超时后双方传输都已关闭。
 */
auto VerifyIdleRelayClosesBothTransports() -> void
{
    Net::io_context Io;
    auto Inbound = std::make_shared<Prism::PrismMockTransport>(Net::make_strand(Io.get_executor()));
    auto Outbound = std::make_shared<Prism::PrismMockTransport>(Net::make_strand(Io.get_executor()));
    auto Relay = std::make_shared<Prism::Network::StreamRelayService>(
        Prism::Network::StreamRelayOptions{
            .BufferSize = 64,
            .IdleTimeout = std::chrono::milliseconds(20),
            .Bytes = std::make_shared<Prism::Memory::BytePool>(Prism::Memory::BytePoolOptions{.BlockCount = 8})});
    bool Done = false;
    std::exception_ptr Failure;
    Prism::Fault::Failure BusinessFailure;
    Net::co_spawn(
        Io,
        Relay->Run({Inbound, Outbound}),
        [&](std::exception_ptr Error, std::expected<void, Prism::Fault::Failure> Result)
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

/** @brief 请求关闭 owner 再试一次，并在同一 timer 上安排下一次检查。 */
template <typename StorageValue>
auto ScheduleCloseRetry(const std::shared_ptr<StorageValue> &Storage,
                       Net::steady_timer &Timer) -> void
{
    Storage->Retry();
    Timer.expires_after(std::chrono::milliseconds(1));
}

/** @brief 发布关闭重试是否耗尽；超时时停止测试执行器。 */
auto FinishCloseRetryWait(Net::io_context &Io,
                          const std::shared_ptr<std::atomic<unsigned>> &CloseAttempts,
                          bool &RetryTimedOut) -> void
{
    RetryTimedOut = CloseAttempts->load(std::memory_order_acquire) < 2;
    if (RetryTimedOut) Io.stop();
}

class FailOnceOnCloseTransport final : public Prism::Transmission
{
public:
    FailOnceOnCloseTransport(std::shared_ptr<Prism::PrismMockTransport> Inner,
        std::shared_ptr<std::atomic<unsigned>> CloseAttempts)
        : Prism::Transmission(Inner->Executor()), Inner_(std::move(Inner)),
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
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }
        return Inner_->Close();
    }

    [[nodiscard]] auto OnCancel() -> ControlResult override
    {
        (void)Inner_->Cancel();
        return {};
    }

private:
    std::shared_ptr<Prism::PrismMockTransport> Inner_;
    std::shared_ptr<std::atomic<unsigned>> CloseAttempts_;
};

class ReloadPolicySource final : public Prism::Account::PolicySource
{
public:
    ReloadPolicySource()
        : Policy_(std::make_shared<const Prism::Account::PolicySnapshot>(
              Prism::Account::PolicySnapshot::CreateRequest{
                  Prism::Account::PolicyVersion{1U},
                  Prism::Account::PolicySettings{
                      {}, {}, Prism::Account::TransferPolicy{
                          std::optional<std::uint64_t>{1024U}, {}, {}, {}}},
                  {}}))
    {
    }

    [[nodiscard]] auto Load(Prism::AccountId) const noexcept
        -> std::shared_ptr<const Prism::Account::PolicySnapshot> override
    {
        return Policy_;
    }

private:
    std::shared_ptr<const Prism::Account::PolicySnapshot> Policy_;
};

class ReloadUsagePersistence final : public Prism::Account::UsagePersistence
{
public:
    auto ResolveCycle(Prism::Account::UsageCycleRequest)
        -> Net::awaitable<std::expected<Prism::Account::UsageCycle,
            Prism::Fault::Failure>> override
    {
        co_return Prism::Account::UsageCycle{1000, std::nullopt};
    }

    auto Read(Prism::Account::UsageReadRequest)
        -> Net::awaitable<std::expected<Prism::Account::UsageSnapshot,
            Prism::Fault::Failure>> override
    {
        co_return std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
    }

    auto Reserve(Prism::Account::UsageReservationRequest)
        -> Net::awaitable<std::expected<Prism::Account::UsageReservation,
            Prism::Fault::Failure>> override
    {
        co_return std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
    }

    auto Settle(Prism::Account::UsageSettlementRequest)
        -> Net::awaitable<std::expected<Prism::Account::UsageSnapshot,
            Prism::Fault::Failure>> override
    {
        co_return std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
    }

    auto Adjust(Prism::Account::UsageAdjustmentRequest)
        -> Net::awaitable<std::expected<Prism::Account::UsageSnapshot,
            Prism::Fault::Failure>> override
    {
        co_return std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
    }
};

[[nodiscard]] auto MakeReloadAccount(
    const Prism::AccountId Id,
    const std::string_view CredentialIdentity)
    -> Prism::Account::AccountDefinition
{
    std::vector<Prism::Account::CredentialMaterial> Credentials;
    Credentials.push_back({Prism::Account::CredentialScope{1U},
        std::string(CredentialIdentity),
        Prism::Account::Credential::Password(std::string(CredentialIdentity))});
    auto Materials = std::make_shared<const Prism::Account::AccountMaterials>(
        Prism::Account::AccountMaterials::CreateRequest{
            Id, "reload-stable-account", std::move(Credentials)});
    return {std::move(Materials), {}};
}
}

TEST(PrismApplication, ProfileFailureReleasesBackendWhileFailedApplicationLives)
{
    TemporaryConfiguration Invalid(FindFreePort(),
        ConfigurationShape{.Recognition = R"({"Mode":"Configured","ConfiguredCandidate":127})",
            .OperationsPort = FindFreePort()});
    std::ostringstream Output;
    Prism::Application::Application Failed(MakeOptions(Invalid.Path(), &Output));
    const auto Rejected = Failed.Start();
    ASSERT_FALSE(Rejected.has_value());
    EXPECT_FALSE(Failed.IsReady());
    EXPECT_TRUE(Output.str().empty());
    EXPECT_EQ(Rejected.error().Code, Prism::Application::StartupErrorCode::Generation);
    EXPECT_EQ(Rejected.error().Path, "Protocols");
    EXPECT_NE(Rejected.error().Message.find("profile build failed"), std::string::npos);

    TemporaryConfiguration Valid(FindFreePort(), ConfigurationShape{.OperationsPort = FindFreePort()});
    Prism::Application::Application Success(MakeOptions(Valid.Path()));
    const auto Started = Success.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    Success.Stop();
    EXPECT_EQ(Success.Run(), 0);
    EXPECT_TRUE(Success.IsStopped());
}

TEST(PrismApplicationMux, StreamHandlerRetainsDomainServicesWithoutRetainingRoot)
{
    auto Services = std::make_shared<Prism::Runtime::SessionServices>();
    const auto WeakRoot = std::weak_ptr<Prism::Runtime::SessionServices>(Services);
    auto Egress = std::make_shared<Prism::Testing::StreamEgress>(Services->Dial);
    const auto WeakEgress = std::weak_ptr<Prism::Contract::StreamEgress>(Egress);
    auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
    const auto WeakUseState = std::weak_ptr<Prism::Foundation::GenerationUseState>(UseState);
    auto Binding = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{
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

TEST(PrismApplicationMux, ProductionAssemblyReleasesRootAndMuxServiceAfterRollback)
{
    TemporaryConfiguration Config(FindFreePort(), ConfigurationShape{.OperationsPort = FindFreePort()});
    const auto Phase = Prism::Application::Startup::GenerationPhase::Build({Config.Path(), {}});
    ASSERT_TRUE(Phase.has_value());
    std::weak_ptr<Prism::Runtime::SessionServices> WeakServices;
    std::weak_ptr<Prism::Foundation::TrafficSink> WeakTraffic;
    std::weak_ptr<Prism::Network::Dns::Resolver> WeakResolver;
    {
        auto Runtime =
            std::make_shared<Prism::Application::Application::RuntimeState>(2, Phase->Generation->Id(),
                Prism::Application::Assembly::MakeDnsConfig(Phase->Generation->Configuration().Dns));
        Prism::Application::Startup::StartupTransaction Transaction(Runtime);
        Runtime->Generation = Phase->Generation;
        Runtime->Accounts = Phase->Accounts;
        ASSERT_TRUE(Prism::Application::Startup::ProcessServices::Build(Runtime, *Phase).has_value());
        ASSERT_TRUE(
            Prism::Application::Startup::ProtocolServices::Prepare(Runtime, Config.Path()).has_value());
        ASSERT_TRUE(Prism::Application::Startup::ProtocolServices::Bind(Runtime, *Phase).has_value());
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

TEST(PrismApplicationStatistics, DisabledConfigurationInstallsNoObserverOrTimer)
{
    TemporaryConfiguration Config(FindFreePort(), ConfigurationShape{
        .OperationsPort = FindFreePort(), .StatisticsEnabled = false});
    const auto Phase = Prism::Application::Startup::GenerationPhase::Build({Config.Path(), {}});
    ASSERT_TRUE(Phase);
    auto Runtime = std::make_shared<Prism::Application::Application::RuntimeState>(
        2, Phase->Generation->Id(), Prism::Network::Dns::Config{});
    Prism::Application::Startup::StartupTransaction Transaction(Runtime);
    Runtime->Generation = Phase->Generation;
    Runtime->Accounts = Phase->Accounts;
    const auto OriginalExpiry = Runtime->StatisticsFlushTimer.expiry();
    ASSERT_TRUE(Prism::Application::Startup::ProcessServices::Build(Runtime, *Phase));
    EXPECT_FALSE(Runtime->Traffic);
    EXPECT_FALSE(Runtime->Services->Traffic);
    EXPECT_FALSE(Runtime->Services->RecognitionLatency);
    EXPECT_EQ(Runtime->StatisticsFlushTimer.expiry(), OriginalExpiry);
    EXPECT_EQ(Runtime->StatisticsFlushArmedIntervalMilliseconds.load(), 0);
}

TEST(PrismApplicationStatistics, ConfiguredIntervalFlushesTheSameOperationsCounters)
{
    TemporaryConfiguration Config(FindFreePort(), ConfigurationShape{
        .OperationsPort = FindFreePort(), .StatisticsInterval = 10});
    const auto Phase = Prism::Application::Startup::GenerationPhase::Build({Config.Path(), {}});
    ASSERT_TRUE(Phase);
    ASSERT_TRUE(Phase->Accounts.Identities);
    const auto& Configuration = Phase->Generation->Configuration();
    auto Runtime = std::make_shared<Prism::Application::Application::RuntimeState>(
        Configuration.Runtime.WorkerCount, Phase->Generation->Id(),
        Prism::Application::Assembly::MakeDnsConfig(Configuration.Dns));
    const auto AdmissionAuthority = Phase->Accounts.Identities->RuntimeRegistry()->AttachAdmissionAuthority(
        Runtime->GenerationPublisher);
    ASSERT_TRUE(AdmissionAuthority);
    const auto PolicySource = Phase->Accounts.Identities->RuntimeRegistry()->AttachPolicySource(
        std::make_shared<ReloadPolicySource>());
    ASSERT_TRUE(PolicySource);
    Prism::Application::ObserveClosingFailures(Runtime);
    Prism::Application::Startup::StartupTransaction Transaction(Runtime);
    Runtime->Generation = Phase->Generation;
    Runtime->Accounts = Phase->Accounts;
    const auto StorageOpened =
        Prism::Application::StorageLifecycle::Open(Runtime, Config.Path());
    ASSERT_TRUE(StorageOpened) << StorageOpened.error().Path
                               << ": " << StorageOpened.error().Message;
    const auto Started = Prism::Application::Startup::RunStartup(Runtime, *Phase, Config.Path());
    ASSERT_TRUE(Started.has_value()) << Started.error().Path << ": " << Started.error().Message;
    ASSERT_TRUE(Runtime->GenerationPublisher->Contains(Phase->Generation->Id()));
    ASSERT_TRUE(Runtime->Traffic);
    EXPECT_EQ(Runtime->Services->Traffic.get(), Runtime->Traffic.get());
    EXPECT_EQ(Runtime->Services->RecognitionLatency.get(), Runtime->Traffic.get());
    EXPECT_EQ(Runtime->StatisticsFlushInterval, std::chrono::milliseconds{10});
    EXPECT_EQ(Runtime->StatisticsFlushArmedIntervalMilliseconds.load(), 10);
    Runtime = Transaction.Commit();
    Runtime->Services->Traffic->Report({.Generation = Phase->Generation->Id(),
        .Worker = Prism::WorkerId{1}, .Session = Prism::SessionId{22},
        .Account = Prism::AccountId{11}, .Up = 37, .Down = 41});
    EXPECT_EQ(Runtime->Traffic->Accepted(), 1U);
    EXPECT_EQ(Runtime->Traffic->Dropped(), 0U);
    EXPECT_EQ(Runtime->Traffic->Value(Prism::Statistics::Scope::Account, 11).UpBytes, 0U);
    std::exception_ptr Failure;
    Net::co_spawn(Runtime->Io, ObserveTrafficInterval(Runtime),
        [&Failure](std::exception_ptr Error) { Failure = Error; });
    Runtime->Io.run();
    EXPECT_FALSE(Failure);
    EXPECT_TRUE(Runtime->StopCompleted.load());
    EXPECT_EQ(Runtime->ExitCode, 0);
    EXPECT_TRUE(Runtime->Traffic->IsSealed());
    EXPECT_EQ(Runtime->Traffic->Value(Prism::Statistics::Scope::Session, 22).UpBytes, 37U);
    Prism::Application::Shutdown::FinalizeRuntimeResources(Runtime);
    EXPECT_FALSE(Runtime->Generation);
}

TEST(PrismApplicationStatistics, ShutdownConsumesPendingBytesBeforeReleasingGeneration)
{
    TemporaryConfiguration Config(FindFreePort(), ConfigurationShape{
        .OperationsPort = FindFreePort(), .StatisticsInterval = 60000});
    const auto Phase = Prism::Application::Startup::GenerationPhase::Build({Config.Path(), {}});
    ASSERT_TRUE(Phase);
    ASSERT_TRUE(Phase->Accounts.Identities);
    const auto& Configuration = Phase->Generation->Configuration();
    auto Runtime = std::make_shared<Prism::Application::Application::RuntimeState>(
        Configuration.Runtime.WorkerCount, Phase->Generation->Id(),
        Prism::Application::Assembly::MakeDnsConfig(Configuration.Dns));
    const auto AdmissionAuthority = Phase->Accounts.Identities->RuntimeRegistry()->AttachAdmissionAuthority(
        Runtime->GenerationPublisher);
    ASSERT_TRUE(AdmissionAuthority);
    const auto PolicySource = Phase->Accounts.Identities->RuntimeRegistry()->AttachPolicySource(
        std::make_shared<ReloadPolicySource>());
    ASSERT_TRUE(PolicySource);
    Prism::Application::ObserveClosingFailures(Runtime);
    Prism::Application::Startup::StartupTransaction Transaction(Runtime);
    Runtime->Generation = Phase->Generation;
    Runtime->Accounts = Phase->Accounts;
    const auto StorageOpened =
        Prism::Application::StorageLifecycle::Open(Runtime, Config.Path());
    ASSERT_TRUE(StorageOpened) << StorageOpened.error().Path
                               << ": " << StorageOpened.error().Message;
    const auto Started = Prism::Application::Startup::RunStartup(Runtime, *Phase, Config.Path());
    ASSERT_TRUE(Started.has_value()) << Started.error().Path << ": " << Started.error().Message;
    auto Counter = Runtime->Traffic;
    ASSERT_TRUE(Counter);
    Runtime = Transaction.Commit();
    Counter->Report({.Generation = Phase->Generation->Id(), .Worker = Prism::WorkerId{2},
        .Session = Prism::SessionId{22}, .Account = Prism::AccountId{11}, .Up = 13, .Down = 17});
    EXPECT_EQ(Counter->ConsumedObservations(), 0U);
    EXPECT_EQ(Counter->Accepted(), 1U);
    EXPECT_EQ(Counter->Dropped(), 0U);
    Prism::Application::Shutdown::ScheduleShutdown(Runtime);
    Runtime->Io.run();
    EXPECT_TRUE(Runtime->StopCompleted.load());
    EXPECT_EQ(Runtime->ExitCode, 0);
    EXPECT_TRUE(Runtime->Generation);
    EXPECT_TRUE(Counter->IsSealed());
    EXPECT_EQ(Counter->ConsumedObservations(), 1U);
    EXPECT_EQ(Counter->Value(Prism::Statistics::Scope::Account, 11).DownBytes, 17U);
    Counter->Finish();
    EXPECT_EQ(Counter->Value(Prism::Statistics::Scope::Account, 11).Events, 1U);
    Prism::Application::Shutdown::FinalizeRuntimeResources(Runtime);
    EXPECT_FALSE(Runtime->Generation);
    EXPECT_FALSE(Runtime->Services);
    EXPECT_FALSE(Runtime->Traffic);
    EXPECT_EQ(Counter->Value(Prism::Statistics::Scope::Worker, 2).UpBytes, 13U);
}

TEST(PrismApplicationMux, ChildCoroutineOwnsSnapshotUntilActualHandlerDrains)
{
    class Traffic final : public Prism::Foundation::TrafficSink
    {
    public:
        auto Report(Prism::Foundation::TrafficEvent) noexcept -> void override {}
        auto Retire(Prism::Foundation::TrafficRetirement Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Prism::Fault::Failure>{}; }
    };
    Net::io_context Io;
    auto Services = std::make_shared<Prism::Runtime::SessionServices>();
    Services->Traffic = std::make_shared<Traffic>();
    const auto WeakTraffic = std::weak_ptr<Prism::Foundation::TrafficSink>(Services->Traffic);
    const auto WeakRoot = std::weak_ptr<Prism::Runtime::SessionServices>(Services);
    auto Stream = std::make_shared<Prism::PrismMockTransport>(Io.get_executor());
    auto Outbound = std::make_shared<Prism::PrismMockTransport>(Io.get_executor());
    auto Relay = std::make_shared<Prism::Network::StreamRelayService>(
        Prism::Network::StreamRelayOptions{.Traffic = Services->Traffic,
            .Bytes = std::make_shared<Prism::Memory::BytePool>(Prism::Memory::BytePoolOptions{.BlockCount = 8})});
    Prism::Contract::StreamRelayRequest Request;
    Request.Inbound=Stream; Request.Outbound=Outbound;
    auto Operation = Relay->Run(std::move(Request));
    Services.reset();
    EXPECT_TRUE(WeakRoot.expired());
    EXPECT_FALSE(WeakTraffic.expired());
    bool Completed = false, OwnerObservedDuringRead = false;
    std::exception_ptr Failure;
    Prism::Fault::Failure BusinessFailure;
    Net::co_spawn(Io, std::move(Operation), [&](std::exception_ptr Error, std::expected<void, Prism::Fault::Failure> Result)
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

TEST(PrismApplicationMux, SingMuxHandlerRelaysBothDirectionsAndReleasesTrafficAfterDrain)
{
    struct Totals final
    {
        using Signal = Net::experimental::channel<void(boost::system::error_code)>;
        explicit Totals(Net::any_io_executor Executor) : WritesCompleted(std::move(Executor), 1) {}
        std::size_t Up{0}, Down{0}, Calls{0}, ByteCalls{0};
        Signal WritesCompleted;
    };
    class Traffic final : public Prism::Foundation::TrafficSink
    {
    public:
        explicit Traffic(std::shared_ptr<Totals> Result) : Result_(std::move(Result)) {}
        auto Report(Prism::Foundation::TrafficEvent Event) noexcept -> void override
        {
            Result_->Up += Event.Up; Result_->Down += Event.Down;
            if (Event.Kind == Prism::Foundation::TrafficEventKind::Completed) ++Result_->Calls;
            else ++Result_->ByteCalls;
            if (Result_->Up >= 2 && Result_->Down >= 4)
                (void)Result_->WritesCompleted.try_send(boost::system::error_code{});
        }
        auto Retire(Prism::Foundation::TrafficRetirement Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Prism::Fault::Failure>{}; }
    private:
        std::shared_ptr<Totals> Result_;
    };
    Net::io_context Io;
    auto Result = std::make_shared<Totals>(Io.get_executor());
    auto Services = std::make_shared<Prism::Runtime::SessionServices>();
    Services->Traffic = std::make_shared<Traffic>(Result);
    const auto WeakRoot = std::weak_ptr<Prism::Runtime::SessionServices>(Services);
    const auto WeakTraffic = std::weak_ptr<Prism::Foundation::TrafficSink>(Services->Traffic);
    auto Inbound = std::make_shared<Prism::PrismMockTransport>(Io.get_executor());
    auto Outbound = std::make_shared<Prism::PrismMockTransport>(Io.get_executor());
    Inbound->ToRead = {'U', 'P'};
    Outbound->ToRead = {'D', 'O', 'W', 'N'};
    Prism::Network::Target Target;
    Target.Host = *Prism::Network::ParseHost("echo"); Target.Port = 80;
    auto Relay = std::make_shared<Prism::Network::StreamRelayService>(
        Prism::Network::StreamRelayOptions{.Traffic = Services->Traffic,
            .Bytes = std::make_shared<Prism::Memory::BytePool>(Prism::Memory::BytePoolOptions{.BlockCount = 8})});
    auto Operation = Relay->Run({std::make_shared<Prism::Mux::SingMux::ServerStream>(
        Inbound, Target, std::optional<Prism::Fault::Failure>{}), Outbound, Target});
    Services.reset();
    EXPECT_TRUE(WeakRoot.expired()); EXPECT_FALSE(WeakTraffic.expired());
    bool Completed = false, OwnerObservedDuringRelay = false;
    Prism::Fault::Code Code = Prism::Fault::Code::IoError;
    std::exception_ptr Failure;
    Net::co_spawn(Io, std::move(Operation), [&](std::exception_ptr Error, std::expected<void, Prism::Fault::Failure> Result)
        { Failure = Error; if (Result) Code = Prism::Fault::Code::Success; else Code = Result.error().Code; Completed = true; });
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
    EXPECT_EQ(Code, Prism::Fault::Code::Success);
    EXPECT_TRUE(OwnerObservedDuringRelay);
    EXPECT_EQ(Outbound->Written, (std::vector<std::uint8_t>{'U', 'P'}));
    EXPECT_EQ(Inbound->Written, (std::vector<std::uint8_t>{0, 'D', 'O', 'W', 'N'}));
    EXPECT_EQ(Result->Up, 2U);
    EXPECT_EQ(Result->Down, 4U);
    EXPECT_EQ(Result->Calls, 1U);
    EXPECT_TRUE(WeakTraffic.expired());
}

TEST(PrismApplicationMux, RelayStrandDrainsIdleAndWriteErrorOnTwoWorkers)
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

    auto CloseInboundRaw = std::make_shared<Prism::PrismMockTransport>(Net::make_strand(Io.get_executor()));
    const auto CloseAttempts = std::make_shared<std::atomic<unsigned>>(0);
    auto CloseInbound = std::make_shared<FailOnceOnCloseTransport>(CloseInboundRaw, CloseAttempts);
    auto CloseOutbound = std::make_shared<Prism::PrismMockTransport>(Net::make_strand(Io.get_executor()));
    const auto Storage = Prism::Executor::ContextOwner::Storage(Io.get_executor());
    Prism::Network::Relay::Result CloseResult;
    bool CloseDone = false;
    bool RetryTimedOut = false;
    std::exception_ptr CloseFailure;
    Net::co_spawn(
        Io,
        Prism::Network::Relay::Run(
            {CloseInbound, CloseOutbound, 64, std::chrono::milliseconds(20), {},
             std::make_shared<Prism::Memory::BytePool>(Prism::Memory::BytePoolOptions{.BlockCount = 8})}),
        [&](std::exception_ptr Error, Prism::Network::Relay::Result Result)
        {
            CloseFailure = Error;
            CloseResult = std::move(Result);
            CloseDone = true;
        });
    const auto RetryClose = [&]() -> Net::awaitable<void>
    {
        Net::steady_timer Timer(Io);
        for (std::size_t Attempt = 0; Attempt < 5000 && CloseAttempts->load(std::memory_order_acquire) < 2; ++Attempt)
        {
            ScheduleCloseRetry(Storage, Timer);
            co_await Timer.async_wait(Net::use_awaitable);
        }
        FinishCloseRetryWait(Io, CloseAttempts, RetryTimedOut);
    };
    Net::co_spawn(Io, RetryClose(), Net::detached);
    RunWorkers();
    ASSERT_FALSE(RetryTimedOut);
    EXPECT_TRUE(CloseDone);
    EXPECT_EQ(CloseFailure, nullptr);
    EXPECT_EQ(CloseResult.Failure.Code, Prism::Fault::Code::Timeout);
    EXPECT_EQ(CloseAttempts->load(std::memory_order_acquire), 2U);
    EXPECT_TRUE(CloseInbound->Activity()->IsRetired());
    EXPECT_FALSE(CloseInboundRaw->IsOpen());
    EXPECT_FALSE(CloseOutbound->IsOpen());

    Io.restart();
    auto ErrorInbound = std::make_shared<Prism::PrismMockTransport>(Net::make_strand(Io.get_executor()));
    auto ErrorOutbound = std::make_shared<Prism::PrismMockTransport>(Net::make_strand(Io.get_executor()));
    ErrorInbound->ToRead = {0x01U, 0x02U, 0x03U};
    ErrorInbound->EofOnDrain = true;
    ErrorOutbound->FailNextWrite = true;
    auto ErrorRelay = std::make_shared<Prism::Network::StreamRelayService>(
        Prism::Network::StreamRelayOptions{.BufferSize = 64,
            .Bytes = std::make_shared<Prism::Memory::BytePool>(Prism::Memory::BytePoolOptions{.BlockCount = 8})});
    bool ErrorDone = false;
    std::exception_ptr ErrorFailure;
    Prism::Fault::Failure ErrorBusinessFailure;
    Net::co_spawn(
        Io,
        ErrorRelay->Run({ErrorInbound, ErrorOutbound}),
        [&](std::exception_ptr Error, std::expected<void, Prism::Fault::Failure> Result)
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

TEST(PrismApplicationReload, RuntimePublishFailurePreservesGenerationBeforeCas)
{
    TemporaryConfiguration Config(FindFreePort(),
        ConfigurationShape{.OperationsPort = FindFreePort()});
    const auto Phase = Prism::Application::Startup::GenerationPhase::Build(
        {Config.Path(), {}});
    ASSERT_TRUE(Phase);
    const auto Id = Prism::AccountId{324U};

    auto State = std::make_shared<Prism::Application::Application::RuntimeState>(
        1, Prism::GenerationId{1}, Prism::Network::Dns::Config{});
    State->Phase.store(Prism::Application::RuntimePhase::Ready);
    const auto CurrentGeneration = Phase->Generation;
    Prism::Application::Configuration::GenerationBuildOptions CandidateOptions;
    CandidateOptions.Configuration = Phase->Generation->Configuration();
    CandidateOptions.Builtins = Phase->Generation->Builtins();
    CandidateOptions.AvailableCapabilities = Phase->Generation->Capabilities();
    CandidateOptions.Generation = Prism::GenerationId{2};
    const auto CandidateGeneration =
        Prism::Application::Configuration::GenerationBuilder::Build(
            std::move(CandidateOptions));
    ASSERT_TRUE(CandidateGeneration) << CandidateGeneration.error().Message;
    auto InitialToken = State->GenerationPublisher->Prepare({}, CurrentGeneration, {Id});
    ASSERT_TRUE(InitialToken);
    ASSERT_TRUE(State->GenerationPublisher->Publish(*InitialToken));
    ASSERT_TRUE(State->GenerationPublisher->Load()->IsAdmitted(Id));
    auto CandidateToken = State->GenerationPublisher->Prepare(
        CurrentGeneration, *CandidateGeneration, {});
    ASSERT_TRUE(CandidateToken);

    auto Identities = std::make_shared<Prism::Application::AccountIdentityRegistry>();
    const auto IdentityPreparation = Identities->BeginPreparation();
    ASSERT_TRUE(IdentityPreparation);
    const auto &RuntimeRegistry = Identities->RuntimeRegistry();
    ASSERT_TRUE(RuntimeRegistry->AttachAdmissionAuthority(State->GenerationPublisher));
    ASSERT_TRUE(RuntimeRegistry->AttachPolicySource(std::make_shared<ReloadPolicySource>()));
    ASSERT_TRUE(RuntimeRegistry->AttachUsagePersistence(
        std::make_shared<ReloadUsagePersistence>(), "reload-publication"));

    auto OldStore = std::make_shared<Prism::Account::AccountStore>(
        Prism::Account::StoreOptions{.WorkerCount = 1U,
            .RuntimeRegistry = RuntimeRegistry, .RevokeRuntimesOnSeal = false});
    const auto OldDefinition = MakeReloadAccount(Id, "reload-old-identity");
    auto OldPrepared = OldStore->PrepareUpsert(OldDefinition);
    ASSERT_TRUE(OldPrepared);
    ASSERT_TRUE(OldStore->Commit(*OldPrepared));
    const auto OldBinding = OldStore->FindById(Id);
    ASSERT_TRUE(OldBinding);
    const auto OldRuntime = OldBinding->Runtime();
    const auto OldTransfer = OldRuntime->Transfer();
    ASSERT_TRUE(OldTransfer);

    auto CandidateStore = std::make_shared<Prism::Account::AccountStore>(
        Prism::Account::StoreOptions{.WorkerCount = 1U,
            .RuntimeRegistry = RuntimeRegistry, .RevokeRuntimesOnSeal = false});
    const auto CandidateDefinition = MakeReloadAccount(Id, "reload-new-identity");
    const std::array CandidateDefinitions{CandidateDefinition};
    auto CandidateUpdate = CandidateStore->PrepareReplacement(CandidateDefinitions);
    ASSERT_TRUE(CandidateUpdate);
    const auto RuntimeTransaction =
        CandidateStore->PrepareRuntimeTransaction(*CandidateUpdate);
    ASSERT_TRUE(RuntimeTransaction);
    ASSERT_TRUE(CandidateStore->CommitSnapshot(*CandidateUpdate));
    (*RuntimeTransaction)->Rollback();

    Prism::Application::AccountCatalog CandidateAccounts;
    CandidateAccounts.Store = CandidateStore;
    CandidateAccounts.Identities = Identities;
    CandidateAccounts.IdentityPreparation = *IdentityPreparation;
    CandidateAccounts.RuntimeTransaction = *RuntimeTransaction;
    const auto CurrentSnapshot = std::make_shared<
        Prism::Application::RuntimeGenerationSnapshot>(
        CurrentGeneration, Prism::Application::AccountCatalog{},
        Prism::Application::RuntimeGenerationServices{});
    const auto CandidateSnapshot = std::make_shared<
        Prism::Application::RuntimeGenerationSnapshot>(
        *CandidateGeneration, std::move(CandidateAccounts),
        Prism::Application::RuntimeGenerationServices{});
    Prism::Application::Reload::PreparedGenerationReload Prepared{
        CandidateSnapshot, CurrentSnapshot, std::move(*CandidateToken),
        *IdentityPreparation, {}, std::chrono::steady_clock::now() +
            std::chrono::seconds{5}};

    bool Completed = false;
    std::optional<std::expected<void, Prism::Fault::Failure>> Published;
    std::exception_ptr Exception;
    Net::co_spawn(State->Io,
        Prism::Application::Reload::PublicationTransaction::PublishPreparedReload(
            State, std::move(Prepared)),
        [&](std::exception_ptr Error, std::expected<void, Prism::Fault::Failure> Result)
        {
            Exception = Error;
            Published = std::move(Result);
            Completed = true;
        });
    State->Io.run();

    ASSERT_FALSE(Exception);
    ASSERT_TRUE(Completed);
    ASSERT_TRUE(Published);
    ASSERT_FALSE(*Published);
    EXPECT_EQ(Published->error().Code, Prism::Fault::Code::InvalidArgument);
    EXPECT_EQ(State->GenerationPublisher->Current(), CurrentGeneration);
    EXPECT_TRUE(State->GenerationPublisher->Load()->IsAdmitted(Id));
    EXPECT_EQ(State->Phase.load(), Prism::Application::RuntimePhase::Ready);
    EXPECT_EQ(State->ExitCode, 0);
    EXPECT_FALSE(State->ShutdownFailure);
    EXPECT_EQ(OldRuntime->StableKey(), "reload-stable-account");
    EXPECT_EQ(OldRuntime->Transfer(), OldTransfer);
    const auto Registered = RuntimeRegistry->FindOrCreate(Id, 1U);
    ASSERT_TRUE(Registered);
    EXPECT_EQ(*Registered, OldRuntime);
}
