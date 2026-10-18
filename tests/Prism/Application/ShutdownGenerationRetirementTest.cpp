#include "ApplicationTestSupport.hpp"
#include <Prism/Application/Shutdown/DrainStages.hpp>
#include <Prism/Application/Shutdown/GenerationRetirement.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Contract/Ingress/CarrierCatalogOwner.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Application/RuntimeGenerationSnapshot.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <atomic>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <utility>

namespace
{
    namespace Provider = Prism::Composition::Provider;
    using AdmissionSignal = Net::experimental::channel<void(boost::system::error_code)>;
    using ShutdownRuntime = Prism::Application::Application::RuntimeState;

    class LeaseReleasingProviderOwner final : public Prism::Contract::CarrierCatalogOwner
    {
    public:
        using Result = std::expected<void, Prism::Fault::Failure>;

        explicit LeaseReleasingProviderOwner(Prism::Foundation::GenerationUseLease Lease)
            : Lease_(std::move(Lease)) {}

        auto Close() noexcept -> void override { Closed_ = true; }

        [[nodiscard]] auto Drain() -> boost::asio::awaitable<Result> override
        {
            DrainCalled_ = true;
            if (!Closed_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            Lease_.reset();
            Retired_ = true;
            co_return Result{};
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return Retired_; }
        [[nodiscard]] auto CloseCalled() const noexcept -> bool { return Closed_; }
        [[nodiscard]] auto DrainCalled() const noexcept -> bool { return DrainCalled_; }

    private:
        std::optional<Prism::Foundation::GenerationUseLease> Lease_;
        bool Closed_{false};
        bool DrainCalled_{false};
        bool Retired_{false};
    };

    class RetryableCancellationProviderOwner final : public Prism::Contract::CarrierCatalogOwner
    {
    public:
        using Result = std::expected<void, Prism::Fault::Failure>;

        auto Close() noexcept -> void override { Closed_ = true; }

        [[nodiscard]] auto Drain() -> boost::asio::awaitable<Result> override
        {
            ++DrainCalls_;
            if (!Closed_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            if (DrainCalls_ == 1U)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            Retired_ = true;
            co_return Result{};
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return Retired_; }
        [[nodiscard]] auto DrainCalls() const noexcept -> std::size_t { return DrainCalls_; }

    private:
        std::size_t DrainCalls_{0U};
        bool Closed_{false};
        bool Retired_{false};
    };

    struct PendingAdmission final
    {
        explicit PendingAdmission(Net::any_io_executor Executor)
            : Entered(Executor, 1), Released(Executor, 1), CloseRetryCompleted(Executor, 1) {}
        AdmissionSignal Entered;
        AdmissionSignal Released;
        AdmissionSignal CloseRetryCompleted;
        std::atomic<unsigned> CloseAttempts{0};
    };

    class FailingAdmissionTransport final : public Prism::Transmission
    {
    public:
        FailingAdmissionTransport(
            Net::any_io_executor Executor,
            std::shared_ptr<PendingAdmission> Pending)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)),
              Pending_(std::move(Pending)) {}

        auto Executor() const -> ExecutorType override { return Executor_; }
        auto IsOpen() const -> bool override { return Open_; }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(ReadOperation{}, Executor_),
                Handler,
                ReadInput{
                    std::static_pointer_cast<FailingAdmissionTransport>(
                        Prism::Transmission::shared_from_this()),
                    Buffer});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Prism::Transport::Detail::PostResult(
                Executor_, std::move(Handler),
                Prism::IoResult{0, {Prism::Fault::Code::IoError}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transport::Detail::PostResult(Executor_, std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            const auto Attempt = Pending_->CloseAttempts.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (Attempt == 1)
            {
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::IoError,
                    std::make_error_code(std::errc::connection_reset)});
            }
            Open_ = false;
            (void)Pending_->CloseRetryCompleted.try_send(boost::system::error_code{});
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
                Prism::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };

        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            (void)Buffer;
            (void)Pending_->Entered.try_send(boost::system::error_code{});
            co_await Pending_->Released.async_receive(Net::use_awaitable);
            co_return Prism::IoResult{
                0, Prism::Fault::FromNative(Prism::make_error_code(Prism::Error::NotOpen))};
        }

        Net::any_io_executor Executor_;
        std::shared_ptr<PendingAdmission> Pending_;
        bool Open_{true};
    };

    struct ProviderOwnerFixture final
    {
        ProviderOwnerFixture()
            : Pin(Prism::Testing::ProviderPin()),
              UseState(std::make_shared<Prism::Foundation::GenerationUseState>()),
              Accounts(Prism::Testing::ProviderAccount(
                  Prism::Account::Credential::Password("provider-password"))) {}

        [[nodiscard]] auto PrepareInput() const -> Provider::Preparation
        {
            const Prism::Contract::ProtocolConfiguration ProtocolValue{
                "socks-instance", "socks5", "socks5", {}, {}};
            return {Pin, UseState, {{ProtocolValue, true, false,
                {Pin, Accounts->Credentials, Accounts->Authenticator}}}, {}};
        }

        [[nodiscard]] auto Bind(Net::any_io_executor Executor)
            -> std::expected<void, Prism::Contract::ProviderFailure>
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
            Prism::Application::Configuration::SharedConfigurationGeneration Generation,
            Prism::Application::AccountCatalog AccountsValue) const
            -> Prism::Application::SharedRuntimeGenerationSnapshot
        {
            Prism::Application::RuntimeGenerationServices Services;
            Services.Providers = Catalog;
            Services.UseState = UseState;
            return std::make_shared<Prism::Application::RuntimeGenerationSnapshot>(
                std::move(Generation), std::move(AccountsValue), std::move(Services));
        }

        Prism::Foundation::GenerationPin Pin;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        std::shared_ptr<Prism::Testing::ProviderAccounts> Accounts;
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
        Provider::PhysicalRetirementReceipt FinalPhysicalReceipt;
        std::shared_ptr<Prism::Contract::StreamFactory> Factory;
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> BoundGeneration;
        std::shared_ptr<FailingAdmissionTransport> Carrier;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage;
        std::optional<Prism::Fault::Failure> HistoricalFailure;
        std::optional<Prism::Fault::Failure> FinalDrainFailure;
        std::optional<Prism::Fault::Failure> DrainFailureAfterMove;
        std::size_t CloseAttemptsAfterInitialDrain{0};
        bool CarrierOpenAfterInitialDrain{false};
        bool CarrierActivityRetiredAfterInitialDrain{false};
        bool BoundGenerationAliveAfterInitialDrain{false};
        bool InitialDrainFailed{false};
        bool PhysicallyRetiredAfterInitialDrain{false};
        bool AcceptReturned{false};
        bool AcceptSucceeded{false};
        std::optional<Prism::Contract::ProtocolDataPlane> Plane;
        bool PhysicallyRetiredAfterRetry{false};
        std::exception_ptr Unexpected;
    };

    auto AcceptPendingSocks(const std::shared_ptr<HistoricalFailureProbe> &Probe)
        -> Net::awaitable<void>
    {
        Prism::Contract::StreamAcceptInput Input{
            Probe->Carrier, {},
            std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount = 8})};
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
        Probe->CloseAttemptsAfterInitialDrain =
            Probe->Pending->CloseAttempts.load(std::memory_order_acquire);
        Probe->CarrierOpenAfterInitialDrain = Probe->Carrier->IsOpen();
        Probe->CarrierActivityRetiredAfterInitialDrain =
            Probe->Carrier->Activity()->IsRetired();
        Probe->PhysicallyRetiredAfterInitialDrain =
            Probe->Catalog->PhysicalRetirement().Complete();
        Probe->BoundGenerationAliveAfterInitialDrain = !Probe->BoundGeneration.expired();

        Probe->Carrier.reset();
        co_await Probe->AcceptFinished.async_receive(Net::use_awaitable);
        Probe->Storage->Retry();
        co_await Probe->Pending->CloseRetryCompleted.async_receive(Net::use_awaitable);
        Net::steady_timer RetryDelay(Probe->Executor);
        for (std::size_t Attempt = 0; Attempt < 5000; ++Attempt)
        {
            const auto Retry = co_await Probe->Catalog->Drain();
            if (Probe->Catalog->PhysicalRetirement().Complete())
            {
                if (!Retry)
                {
                    Probe->FinalDrainFailure = Retry.error();
                }
                break;
            }
            Probe->Storage->Retry();
            RetryDelay.expires_after(std::chrono::milliseconds(1));
            co_await RetryDelay.async_wait(Net::use_awaitable);
        }
        Probe->FinalPhysicalReceipt = Probe->Catalog->PhysicalRetirement();
        Probe->PhysicallyRetiredAfterRetry = Probe->FinalPhysicalReceipt.Complete();
        Probe->Storage->Collect();
        Probe->Storage->Retry();
        Probe->Storage->Collect();

        auto MoveConstructed = std::make_shared<Provider::BoundCatalog>(std::move(*Probe->Catalog));
        auto MoveAssigned = std::make_shared<Provider::BoundCatalog>();
        *MoveAssigned = std::move(*MoveConstructed);
        Probe->Catalog = std::move(MoveAssigned);
        const auto AfterMove = co_await Probe->Catalog->Drain();
        if (!AfterMove) Probe->DrainFailureAfterMove = AfterMove.error();
    }
}

/** @brief 代次 admission 关闭前先排空 provider 并释放活动 lease。 */
TEST(PrismApplicationShutdown, DrainsProviderLeaseBeforeClosingGenerationAdmission)
{
    auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
    auto Lease = UseState->Acquire();
    ASSERT_TRUE(Lease);
    auto Owner = std::make_shared<LeaseReleasingProviderOwner>(std::move(*Lease));
    auto Providers = std::make_shared<Provider::BoundCatalog>();
    ASSERT_TRUE(Providers->AdoptCarrierOwner("lease-owner", Owner));

    Prism::Application::RuntimeGenerationServices Services;
    Services.Providers = Providers;
    Services.UseState = UseState;
    boost::asio::io_context Io;
    std::optional<std::expected<void, Prism::Fault::Failure>> Outcome;
    std::exception_ptr Exception;
    boost::asio::co_spawn(Io, Services.DrainOwnedServices(),
        [&Outcome, &Exception](std::exception_ptr Error,
            std::expected<void, Prism::Fault::Failure> Value)
        {
            Exception = std::move(Error);
            Outcome.emplace(std::move(Value));
        });
    Io.run();

    EXPECT_FALSE(Exception);
    ASSERT_TRUE(Outcome.has_value());
    ASSERT_TRUE(*Outcome);
    EXPECT_TRUE(Owner->CloseCalled());
    EXPECT_TRUE(Owner->DrainCalled());
    EXPECT_TRUE(Owner->IsRetired());
    EXPECT_EQ(UseState->Outstanding(), 0U);
    EXPECT_FALSE(UseState->AdmissionOpen());
    EXPECT_TRUE(Services.PhysicalRetirementComplete());
}

TEST(PrismApplicationShutdown, RetriesProviderCancellationUntilPhysicalRetirement)
{
    TemporaryConfiguration Configuration(FindFreePort());
    const auto Phase = Prism::Application::Startup::GenerationPhase::Build(
        {Configuration.Path(), {}});
    ASSERT_TRUE(Phase);

    auto Runtime = std::make_shared<ShutdownRuntime>(
        1, Phase->Generation->Id(), Prism::Network::Dns::Config{});
    Runtime->Generation = Phase->Generation;
    Runtime->Accounts = Phase->Accounts;

    auto Providers = std::make_shared<Provider::BoundCatalog>();
    auto Owner = std::make_shared<RetryableCancellationProviderOwner>();
    ASSERT_TRUE(Providers->AdoptCarrierOwner("retryable-owner", Owner));
    Prism::Application::RuntimeGenerationServices Services;
    Services.Providers = Providers;
    Services.UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
    auto Snapshot = std::make_shared<Prism::Application::RuntimeGenerationSnapshot>(
        Phase->Generation, Phase->Accounts, std::move(Services));
    auto Token = Runtime->GenerationPublisher->Prepare({}, Snapshot, {});
    ASSERT_TRUE(Token);
    ASSERT_TRUE(Runtime->GenerationPublisher->Publish(*Token));

    std::optional<Prism::Application::Shutdown::ShutdownOutcome> Outcome;
    std::exception_ptr DrainException;
    const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    Net::co_spawn(Runtime->Io,
        Prism::Application::Shutdown::GenerationRetirement::DrainGenerationSnapshots(
            Runtime, Deadline),
        [&Outcome, &DrainException](std::exception_ptr Error,
            Prism::Application::Shutdown::ShutdownOutcome Result)
        {
            DrainException = std::move(Error);
            if (!DrainException) Outcome.emplace(std::move(Result));
        });
    Runtime->Io.run();

    EXPECT_FALSE(DrainException);
    ASSERT_TRUE(Outcome);
    EXPECT_TRUE(*Outcome);
    EXPECT_GE(Owner->DrainCalls(), 2U);
    EXPECT_TRUE(Owner->IsRetired());
    EXPECT_FALSE(Snapshot->FirstDrainFailure());
    EXPECT_TRUE(Snapshot->PhysicalRetirementComplete());
    EXPECT_FALSE(Runtime->ActiveGenerationSnapshot());
    EXPECT_EQ(Runtime->GenerationPublisher->RetainedCount(), 0U);
}

TEST(PrismApplicationShutdown, ReleasesRetiredGenerationAfterPhysicalReceiptAndKeepsFailure)
{
    TemporaryConfiguration Configuration(FindFreePort());
    const auto Phase = Prism::Application::Startup::GenerationPhase::Build(
        {Configuration.Path(), {}});
    ASSERT_TRUE(Phase);

    auto Runtime = std::make_shared<ShutdownRuntime>(
        1, Phase->Generation->Id(), Prism::Network::Dns::Config{});
    Runtime->Generation = Phase->Generation;
    Runtime->Accounts = Phase->Accounts;

    ProviderOwnerFixture FailedFixture;
    ASSERT_TRUE(FailedFixture.Bind(Runtime->Io.get_executor()));
    auto Probe = std::make_shared<HistoricalFailureProbe>(Runtime->Io.get_executor());
    Probe->Catalog = FailedFixture.Catalog;
    Probe->Factory = FailedFixture.Catalog->Find("socks-instance")->Stream();
    Probe->BoundGeneration = FailedFixture.Pin;
    FailedFixture.Pin.reset();
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
    EXPECT_EQ(Probe->HistoricalFailure->Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(Probe->HistoricalFailure->Native,
        std::make_error_code(std::errc::connection_reset));
    EXPECT_EQ(Probe->CloseAttemptsAfterInitialDrain, 1U);
    EXPECT_TRUE(Probe->CarrierOpenAfterInitialDrain);
    EXPECT_FALSE(Probe->CarrierActivityRetiredAfterInitialDrain);
    EXPECT_TRUE(Probe->BoundGenerationAliveAfterInitialDrain);
    for (const auto& Owner : Probe->FinalPhysicalReceipt.Owners)
    {
        EXPECT_EQ(Owner.State, Provider::PhysicalRetirementState::Retired) << Owner.Owner;
    }
    ASSERT_TRUE(Probe->PhysicallyRetiredAfterRetry);
    ASSERT_TRUE(Probe->Factory);
    EXPECT_TRUE(Probe->BoundGeneration.expired());
    ASSERT_TRUE(Probe->FinalDrainFailure);
    EXPECT_EQ(Probe->FinalDrainFailure->Code, Probe->HistoricalFailure->Code);
    EXPECT_EQ(Probe->FinalDrainFailure->Native, Probe->HistoricalFailure->Native);
    ASSERT_TRUE(Probe->DrainFailureAfterMove);
    EXPECT_EQ(Probe->DrainFailureAfterMove->Code, Probe->HistoricalFailure->Code);
    EXPECT_EQ(Probe->DrainFailureAfterMove->Native, Probe->HistoricalFailure->Native);
    EXPECT_EQ(Probe->Pending->CloseAttempts.load(std::memory_order_acquire), 2U);

    FailedFixture.Catalog = Probe->Catalog;
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
    std::optional<Prism::Application::Shutdown::ShutdownOutcome> Outcome;
    std::exception_ptr DrainFailure;
    const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    Net::co_spawn(Runtime->Io,
        Prism::Application::Shutdown::GenerationRetirement::DrainGenerationSnapshots(Runtime, Deadline),
        [&Outcome, &DrainFailure](std::exception_ptr Error,
            Prism::Application::Shutdown::ShutdownOutcome Result)
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
