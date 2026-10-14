/**
 * @file ApplicationAssemblyLifecycleTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ApplicationTestSupport.hpp"
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Application/Shutdown/DrainStages.hpp>
#include <Preview/Application/Shutdown/GenerationRetirement.hpp>
#include <Preview/Composition/Provider/ProviderCatalog.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/deferred.hpp>

namespace
{
/**
 * @brief 验证空闲数据转发超时后双方传输都已关闭。
 */
auto VerifyIdleRelayClosesBothTransports() -> void
{
    Net::io_context Io;
    auto Inbound = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
    auto Outbound = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
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
    auto Runtime = std::make_shared<Preview::Application::Application::RuntimeState>(
        2, Phase->Generation->Id(), Preview::Network::Dns::Config{});
    Preview::Application::Startup::StartupTransaction Transaction(Runtime);
    Runtime->Generation = Phase->Generation;
    Runtime->Accounts = Phase->Accounts;
    ASSERT_TRUE(Preview::Application::Startup::ProcessServices::Build(Runtime, *Phase));
    ASSERT_TRUE(Runtime->Traffic);
    EXPECT_EQ(Runtime->Services->Traffic.get(), Runtime->Traffic.get());
    EXPECT_EQ(Runtime->Services->RecognitionLatency.get(), Runtime->Traffic.get());
    EXPECT_EQ(Runtime->StatisticsFlushInterval, std::chrono::milliseconds{10});
    EXPECT_EQ(Runtime->StatisticsFlushArmedIntervalMilliseconds.load(), 10);
    Runtime = Transaction.Commit();
    Runtime->Services->Traffic->Report({.Generation = Phase->Generation->Id(),
        .Worker = Preview::WorkerId{1}, .Session = Preview::SessionId{22},
        .Account = Preview::AccountId{11}, .Up = 37, .Down = 41});
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
    auto Runtime = std::make_shared<Preview::Application::Application::RuntimeState>(
        2, Phase->Generation->Id(), Preview::Network::Dns::Config{});
    Preview::Application::Startup::StartupTransaction Transaction(Runtime);
    Runtime->Generation = Phase->Generation;
    Runtime->Accounts = Phase->Accounts;
    ASSERT_TRUE(Preview::Application::Startup::ProcessServices::Build(Runtime, *Phase));
    auto Counter = Runtime->Traffic;
    ASSERT_TRUE(Counter);
    Runtime = Transaction.Commit();
    Counter->Report({.Generation = Phase->Generation->Id(), .Worker = Preview::WorkerId{2},
        .Session = Preview::SessionId{22}, .Account = Preview::AccountId{11}, .Up = 13, .Down = 17});
    EXPECT_EQ(Counter->ConsumedObservations(), 0U);
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
    struct Totals final { std::size_t Up{0}, Down{0}, Calls{0}, ByteCalls{0}; };
    class Traffic final : public Preview::Foundation::TrafficSink
    {
    public:
        explicit Traffic(std::shared_ptr<Totals> Result) : Result_(std::move(Result)) {}
        auto Report(Preview::Foundation::TrafficEvent Event) noexcept -> void override
        {
            Result_->Up += Event.Up; Result_->Down += Event.Down;
            if (Event.Kind == Preview::Foundation::TrafficEventKind::Completed) ++Result_->Calls;
            else ++Result_->ByteCalls;
        }
        auto Retire(Preview::Foundation::TrafficRetirement Owner)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Preview::Fault::Failure>{}; }
    private:
        std::shared_ptr<Totals> Result_;
    };
    Net::io_context Io;
    auto Result = std::make_shared<Totals>();
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
        Net::steady_timer Timer(Io, std::chrono::milliseconds(10));
        co_await Timer.async_wait(Net::use_awaitable);
        Relay.reset();
        OwnerObservedDuringRelay = !WeakTraffic.expired() && Outbound->Written.size() == 2 && Inbound->Written.size() == 5;
        (void)Inbound->Close();
        (void)Outbound->Close();
    };
    Net::co_spawn(Io, Driver(), Net::detached);
    std::thread WorkerA([&Io] { Io.run(); });
    std::thread WorkerB([&Io] { Io.run(); });
    WorkerA.join();
    WorkerB.join();
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
    class ThrowOnCloseTransport final : public Preview::Transmission
    {
    public:
        explicit ThrowOnCloseTransport(std::shared_ptr<Preview::PreviewMockTransport> Inner)
            : Preview::Transmission(Inner->Executor()), Inner_(std::move(Inner)) {}

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
            (void)Inner_->Close();
            return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::IoError});
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            (void)Inner_->Cancel();
            return {};
        }

    private:
        std::shared_ptr<Preview::PreviewMockTransport> Inner_;
    };

    VerifyIdleRelayClosesBothTransports();

    Net::io_context Io;
    auto RunWorkers = [&Io]
    {
        std::thread WorkerA([&Io] { Io.run(); });
        std::thread WorkerB([&Io] { Io.run(); });
        WorkerA.join();
        WorkerB.join();
    };

    auto CloseInboundRaw = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
    auto CloseInbound = std::make_shared<ThrowOnCloseTransport>(CloseInboundRaw);
    auto CloseOutbound = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
    Preview::Network::Relay::Result CloseResult;
    bool CloseDone = false;
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
    RunWorkers();
    EXPECT_TRUE(CloseDone);
    EXPECT_EQ(CloseFailure, nullptr);
    EXPECT_EQ(CloseResult.Failure.Code, Preview::Fault::Code::IoError);
    EXPECT_FALSE(CloseInboundRaw->IsOpen());
    EXPECT_FALSE(CloseOutbound->IsOpen());

    Io.restart();
    auto ErrorInbound = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
    auto ErrorOutbound = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
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


namespace
{
    namespace Provider = Preview::Composition::Provider;
    using AdmissionSignal = Net::experimental::channel<void(boost::system::error_code)>;
    using ShutdownRuntime = Preview::Application::Application::RuntimeState;

    struct PendingAdmission final
    {
        explicit PendingAdmission(Net::any_io_executor Executor)
            : Entered(Executor, 1), Released(Executor, 1) {}
        AdmissionSignal Entered;
        AdmissionSignal Released;
    };

    class FailingAdmissionTransport final : public Preview::Transmission
    {
    public:
        FailingAdmissionTransport(
            Net::any_io_executor Executor,
            std::shared_ptr<PendingAdmission> Pending)
            : Preview::Transmission(Executor), Executor_(std::move(Executor)),
              Pending_(std::move(Pending)) {}

        auto Executor() const -> ExecutorType override { return Executor_; }
        auto IsOpen() const -> bool override { return Open_; }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(ReadOperation{}, Executor_),
                Handler,
                ReadInput{
                    std::static_pointer_cast<FailingAdmissionTransport>(
                        Preview::Transmission::shared_from_this()),
                    Buffer});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
                Executor_, std::move(Handler),
                Preview::IoResult{0, {Preview::Fault::Code::IoError}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(Executor_, std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ++CloseCalls_;
            if (CloseCalls_ == 1)
            {
                return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::IoError,
                    std::make_error_code(std::errc::connection_reset)});
            }
            Open_ = false;
            (void)Pending_->Released.try_send(boost::system::error_code{});
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            (void)Pending_->Released.try_send(boost::system::error_code{});
            return {};
        }

    private:
        struct ReadInput final
        {
            std::shared_ptr<FailingAdmissionTransport> Owner;
            std::span<std::byte> Buffer;
        };

        struct ReadOperation final
        {
            template <class OperationState>
            auto operator()(OperationState Operation, ReadInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };

        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            (void)Buffer;
            (void)Pending_->Entered.try_send(boost::system::error_code{});
            co_await Pending_->Released.async_receive(Net::use_awaitable);
            co_return Preview::IoResult{
                0, Preview::Fault::FromNative(Preview::make_error_code(Preview::Error::NotOpen))};
        }

        Net::any_io_executor Executor_;
        std::shared_ptr<PendingAdmission> Pending_;
        std::size_t CloseCalls_{0};
        bool Open_{true};
    };

    struct ProviderOwnerFixture final
    {
        ProviderOwnerFixture()
            : Pin(Preview::Testing::ProviderPin()),
              UseState(std::make_shared<Preview::Foundation::GenerationUseState>()),
              Accounts(Preview::Testing::ProviderAccount(
                  Preview::Account::Credential::Password("provider-password"))) {}

        [[nodiscard]] auto PrepareInput() const -> Provider::Preparation
        {
            const Preview::Contract::ProtocolConfiguration ProtocolValue{
                "socks-instance", "socks5", "socks5", {}, {}};
            return {Pin, UseState, {{ProtocolValue, true, false,
                {Pin, Accounts->Credentials, Accounts->Authenticator}}}, {}};
        }

        [[nodiscard]] auto Bind(Net::any_io_executor Executor)
            -> std::expected<void, Preview::Contract::ProviderFailure>
        {
            auto Prepared = Provider::ProviderCatalog::Prepare(
                PrepareInput(), Provider::BindingServices{std::move(Executor), {}, {}, {}});
            if (!Prepared)
            {
                return std::unexpected(Prepared.error());
            }
            auto Frozen = Prepared->Freeze();
            if (!Frozen)
            {
                return std::unexpected(Frozen.error());
            }
            auto Bound = Frozen->Bind({});
            if (!Bound)
            {
                return std::unexpected(Bound.error());
            }
            Catalog = std::make_shared<Provider::BoundCatalog>(std::move(*Bound));
            return {};
        }

        [[nodiscard]] auto MakeSnapshot(
            Preview::Application::Configuration::SharedConfigurationGeneration Generation,
            Preview::Application::AccountCatalog AccountsValue) const
            -> Preview::Application::SharedRuntimeGenerationSnapshot
        {
            Preview::Application::RuntimeGenerationServices Services;
            Services.Providers = Catalog;
            Services.UseState = UseState;
            return std::make_shared<Preview::Application::RuntimeGenerationSnapshot>(
                std::move(Generation), std::move(AccountsValue), std::move(Services));
        }

        Preview::Foundation::GenerationPin Pin;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;
        std::shared_ptr<Preview::Testing::ProviderAccounts> Accounts;
        std::shared_ptr<Provider::BoundCatalog> Catalog;
    };

    struct HistoricalFailureProbe final
    {
        explicit HistoricalFailureProbe(Net::any_io_executor ExecutorValue)
            : Executor(std::move(ExecutorValue)), Pending(std::make_shared<PendingAdmission>(Executor)),
              AcceptFinished(Executor, 1) {}

        Net::any_io_executor Executor;
        std::shared_ptr<PendingAdmission> Pending;
        AdmissionSignal AcceptFinished;
        std::shared_ptr<Provider::BoundCatalog> Catalog;
        std::shared_ptr<Preview::Contract::StreamFactory> Factory;
        std::shared_ptr<FailingAdmissionTransport> Carrier;
        std::shared_ptr<Preview::Executor::ClosingStorage> Storage;
        std::optional<Preview::Fault::Failure> HistoricalFailure;
        std::optional<Preview::Fault::Failure> FinalDrainFailure;
        bool InitialDrainFailed{false};
        bool PhysicallyRetiredAfterInitialDrain{false};
        bool AcceptReturned{false};
        bool AcceptSucceeded{false};
        std::optional<Preview::Contract::ProtocolDataPlane> Plane;
        bool PhysicallyRetiredAfterRetry{false};
        std::exception_ptr Unexpected;
    };

    auto AcceptPendingSocks(const std::shared_ptr<HistoricalFailureProbe> &Probe)
        -> Net::awaitable<void>
    {
        Preview::Contract::StreamAcceptInput Input{
            Probe->Carrier, {},
            std::make_shared<Preview::Memory::BytePool>(
                Preview::Memory::BytePoolOptions{.BlockCount = 8})};
        auto Accepted = co_await Probe->Factory->Accept(std::move(Input));
        Probe->AcceptReturned = true;
        Probe->AcceptSucceeded = static_cast<bool>(Accepted);
        if (Accepted)
        {
            auto Value = std::move(*Accepted);
            (void)Value;
        }
    }

    auto CompletePendingSocks(
        const std::shared_ptr<HistoricalFailureProbe> &Probe,
        std::exception_ptr Error) -> void
    {
        Probe->Unexpected = std::move(Error);
        (void)Probe->AcceptFinished.try_send(boost::system::error_code{});
    }

    auto CreateHistoricalProviderFailure(
        const std::shared_ptr<HistoricalFailureProbe> &Probe) -> Net::awaitable<void>
    {
        Net::co_spawn(Probe->Executor, AcceptPendingSocks(Probe),
            [Probe](std::exception_ptr Error) { CompletePendingSocks(Probe, std::move(Error)); });
        co_await Probe->Pending->Entered.async_receive(Net::use_awaitable);
        Probe->Catalog->Close();
        const auto Initial = co_await Probe->Catalog->Drain();
        Probe->InitialDrainFailed = !Initial;
        if (!Initial)
        {
            Probe->HistoricalFailure = Initial.error();
        }
        Probe->PhysicallyRetiredAfterInitialDrain =
            Probe->Catalog->PhysicalRetirement().Complete();

        Probe->Factory.reset();
        Probe->Carrier.reset();
        Probe->Storage->Retry();
        (void)Probe->Pending->Released.try_send(boost::system::error_code{});
        co_await Probe->AcceptFinished.async_receive(Net::use_awaitable);
        Probe->Storage->Collect();
        const auto Retry = co_await Probe->Catalog->Drain();
        if (!Retry)
        {
            Probe->FinalDrainFailure = Retry.error();
            if (!Probe->HistoricalFailure)
            {
                Probe->HistoricalFailure = Retry.error();
            }
        }
        Probe->PhysicallyRetiredAfterRetry =
            Probe->Catalog->PhysicalRetirement().Complete();
        Probe->Storage->Collect();
        Probe->Storage->Retry();
        Probe->Storage->Collect();
    }
}

TEST(PreviewApplicationShutdown, ReleasesRetiredGenerationAfterPhysicalReceiptAndKeepsFailure)
{
    TemporaryConfiguration Configuration(FindFreePort());
    const auto Phase = Preview::Application::Startup::GenerationPhase::Build(
        {Configuration.Path(), {}});
    ASSERT_TRUE(Phase);

    auto Runtime = std::make_shared<ShutdownRuntime>(
        1, Phase->Generation->Id(), Preview::Network::Dns::Config{});
    Runtime->Generation = Phase->Generation;
    Runtime->Accounts = Phase->Accounts;

    ProviderOwnerFixture FailedFixture;
    ASSERT_TRUE(FailedFixture.Bind(Runtime->Io.get_executor()));
    auto Probe = std::make_shared<HistoricalFailureProbe>(Runtime->Io.get_executor());
    Probe->Catalog = FailedFixture.Catalog;
    Probe->Factory = FailedFixture.Catalog->Find("socks-instance")->Stream();
    Probe->Carrier = std::make_shared<FailingAdmissionTransport>(Runtime->Io.get_executor(), Probe->Pending);
    Probe->Storage = Runtime->ClosingResources;

    std::exception_ptr ProbeFailure;
    Net::co_spawn(Runtime->Io, CreateHistoricalProviderFailure(Probe),
        [&ProbeFailure](std::exception_ptr Error) { ProbeFailure = std::move(Error); });
    Runtime->Io.run();

    EXPECT_FALSE(ProbeFailure);
    EXPECT_FALSE(Probe->Unexpected);
    EXPECT_TRUE(Probe->AcceptReturned);
    EXPECT_FALSE(Probe->AcceptSucceeded);
    ASSERT_TRUE(Probe->InitialDrainFailed);
    EXPECT_FALSE(Probe->PhysicallyRetiredAfterInitialDrain);
    ASSERT_TRUE(Probe->HistoricalFailure);
    ASSERT_TRUE(Probe->FinalDrainFailure);
    EXPECT_EQ(Probe->FinalDrainFailure->Code, Probe->HistoricalFailure->Code);
    EXPECT_EQ(Probe->FinalDrainFailure->Native, Probe->HistoricalFailure->Native);
    ASSERT_TRUE(Probe->PhysicallyRetiredAfterRetry);

    auto FailedOwner = FailedFixture.MakeSnapshot(Phase->Generation, Phase->Accounts);
    ASSERT_TRUE(FailedOwner->CanRetire());
    auto Token = Runtime->GenerationPublisher->Prepare({}, FailedOwner, {});
    ASSERT_TRUE(Token);
    ASSERT_TRUE(Runtime->GenerationPublisher->Publish(*Token));

    ProviderOwnerFixture FirstRetiredFixture;
    ProviderOwnerFixture SecondRetiredFixture;
    ASSERT_TRUE(FirstRetiredFixture.Bind(Runtime->Io.get_executor()));
    ASSERT_TRUE(SecondRetiredFixture.Bind(Runtime->Io.get_executor()));
    auto FirstRetired = FirstRetiredFixture.MakeSnapshot(Phase->Generation, Phase->Accounts);
    auto SecondRetired = SecondRetiredFixture.MakeSnapshot(Phase->Generation, Phase->Accounts);
    Runtime->RetiredGenerationSnapshots.push_back(FirstRetired);
    Runtime->RetiredGenerationSnapshots.push_back(SecondRetired);

    Runtime->Io.restart();
    std::optional<Preview::Application::Shutdown::ShutdownOutcome> Outcome;
    std::exception_ptr DrainFailure;
    const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    Net::co_spawn(Runtime->Io,
        Preview::Application::Shutdown::GenerationRetirement::DrainGenerationSnapshots(Runtime, Deadline),
        [&Outcome, &DrainFailure](std::exception_ptr Error,
            Preview::Application::Shutdown::ShutdownOutcome Result)
        {
            DrainFailure = std::move(Error);
            if (!DrainFailure)
            {
                Outcome.emplace(std::move(Result));
            }
        });
    Runtime->Io.run();

    EXPECT_FALSE(DrainFailure);
    ASSERT_TRUE(Outcome);
    ASSERT_FALSE(*Outcome);
    EXPECT_EQ(Outcome->error().Code, Probe->HistoricalFailure->Code);
    EXPECT_EQ(Outcome->error().Native, Probe->HistoricalFailure->Native);
    EXPECT_FALSE(Runtime->ActiveGenerationSnapshot());
    EXPECT_TRUE(Runtime->RetiredGenerationSnapshots.empty());
    EXPECT_TRUE(FailedOwner->PhysicalRetirementComplete());
    EXPECT_TRUE(FirstRetired->PhysicalRetirementComplete());
    EXPECT_TRUE(SecondRetired->PhysicalRetirementComplete());
    EXPECT_EQ(Runtime->GenerationPublisher->RetainedCount(), 0U);

    const std::weak_ptr<Provider::BoundCatalog> WeakFailedCatalog = FailedFixture.Catalog;
    const std::weak_ptr<Provider::BoundCatalog> WeakFirstRetiredCatalog = FirstRetiredFixture.Catalog;
    const std::weak_ptr<Provider::BoundCatalog> WeakSecondRetiredCatalog = SecondRetiredFixture.Catalog;
    FailedOwner.reset();
    FirstRetired.reset();
    SecondRetired.reset();
    Probe->Catalog.reset();
    FailedFixture.Catalog.reset();
    FirstRetiredFixture.Catalog.reset();
    SecondRetiredFixture.Catalog.reset();
    Probe.reset();
    EXPECT_TRUE(WeakFailedCatalog.expired());
    EXPECT_TRUE(WeakFirstRetiredCatalog.expired());
    EXPECT_TRUE(WeakSecondRetiredCatalog.expired());
}
