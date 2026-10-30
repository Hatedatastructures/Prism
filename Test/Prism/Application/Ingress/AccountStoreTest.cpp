/** @file AccountStoreTest.cpp @brief 真实 Application 存储装配与有限额度认证。 */

#include "../Startup/StartupSupport.hpp"

#include <Prism/Account/Account.hpp>
#include <Prism/Account/UsagePersistence.hpp>
#include <Prism/Application/Account/IdentityRegistry.hpp>
#include <Prism/Application/Assembly/Dns.hpp>
#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Application/Startup/Detail/Generation.hpp>
#include <Prism/Application/Storage/Sqlite/Detail/Usage.hpp>
#include <Prism/Application/Storage/StorageRuntime.hpp>
#include <Prism/Application/Storage/Detail/Lifecycle.hpp>
#include <Prism/Contract/Account/PayloadBudget.hpp>

#include <boost/asio/use_future.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
    class TemporaryStorageDirectory final
    {
    public:
        TemporaryStorageDirectory()
            : Path_(std::filesystem::temp_directory_path() /
                ("PrismAccountStorage-" + std::to_string(
                    std::chrono::steady_clock::now().time_since_epoch().count())))
        {
        }

        ~TemporaryStorageDirectory()
        {
            std::error_code Error;
            std::filesystem::remove_all(Path_, Error);
        }

        [[nodiscard]] auto Get() const -> const std::filesystem::path &
        {
            return Path_;
        }

    private:
        std::filesystem::path Path_;
    };

    template <typename Result>
    auto RunStorage(Net::awaitable<Result> Work) -> Result
    {
        Net::io_context Context;
        auto Value = Net::co_spawn(Context, std::move(Work), Net::use_future);
        Context.run();
        return Value.get();
    }

    class FixedPolicySource final : public Prism::Account::PolicySource
    {
    public:
        explicit FixedPolicySource(std::shared_ptr<const Prism::Account::PolicySnapshot> Policy)
            : Policy_(std::move(Policy))
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

    class UnusedUsagePersistence final : public Prism::Account::UsagePersistence
    {
    public:
        auto ResolveCycle(Prism::Account::UsageCycleRequest)
            -> Net::awaitable<std::expected<Prism::Account::UsageCycle, Prism::Fault::Failure>> override
        {
            co_return Prism::Account::UsageCycle{};
        }

        auto Read(Prism::Account::UsageReadRequest)
            -> Net::awaitable<std::expected<Prism::Account::UsageSnapshot, Prism::Fault::Failure>> override
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }

        auto Reserve(Prism::Account::UsageReservationRequest)
            -> Net::awaitable<std::expected<Prism::Account::UsageReservation, Prism::Fault::Failure>> override
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }

        auto Settle(Prism::Account::UsageSettlementRequest)
            -> Net::awaitable<std::expected<Prism::Account::UsageSnapshot, Prism::Fault::Failure>> override
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }

        auto Adjust(Prism::Account::UsageAdjustmentRequest)
            -> Net::awaitable<std::expected<Prism::Account::UsageSnapshot, Prism::Fault::Failure>> override
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
    };

    class FinalSettlementFailurePersistence final : public Prism::Account::UsagePersistence
    {
    public:
        explicit FinalSettlementFailurePersistence(
            std::shared_ptr<Prism::Account::UsagePersistence> Delegate)
            : Delegate_(std::move(Delegate))
        {
        }

        auto ResolveCycle(Prism::Account::UsageCycleRequest Request)
            -> Net::awaitable<std::expected<Prism::Account::UsageCycle, Prism::Fault::Failure>> override
        {
            co_return co_await Delegate_->ResolveCycle(std::move(Request));
        }

        auto Read(Prism::Account::UsageReadRequest Request)
            -> Net::awaitable<std::expected<Prism::Account::UsageSnapshot, Prism::Fault::Failure>> override
        {
            co_return co_await Delegate_->Read(std::move(Request));
        }

        auto Reserve(Prism::Account::UsageReservationRequest Request)
            -> Net::awaitable<std::expected<Prism::Account::UsageReservation, Prism::Fault::Failure>> override
        {
            ++ReserveCalls;
            ReservedCycle = Request.Usage.Cycle;
            co_return co_await Delegate_->Reserve(std::move(Request));
        }

        auto Settle(Prism::Account::UsageSettlementRequest Request)
            -> Net::awaitable<std::expected<Prism::Account::UsageSnapshot, Prism::Fault::Failure>> override
        {
            ++SettleCalls;
            if (Request.Final)
            {
                FinalSettlementConsumedBytes = Request.ConsumedBytes;
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
            co_return co_await Delegate_->Settle(std::move(Request));
        }

        auto Adjust(Prism::Account::UsageAdjustmentRequest Request)
            -> Net::awaitable<std::expected<Prism::Account::UsageSnapshot, Prism::Fault::Failure>> override
        {
            co_return co_await Delegate_->Adjust(std::move(Request));
        }

        std::uint32_t ReserveCalls{0U};
        std::uint32_t SettleCalls{0U};
        std::optional<Prism::Account::UsageCycle> ReservedCycle;
        std::optional<std::uint64_t> FinalSettlementConsumedBytes;

    private:
        std::shared_ptr<Prism::Account::UsagePersistence> Delegate_;
    };

    [[nodiscard]] auto MakePolicySource(const std::optional<std::uint64_t> TrafficBytes)
        -> std::shared_ptr<FixedPolicySource>
    {
        Prism::Account::PolicySettings Settings;
        Settings.Transfer.TrafficBytes = TrafficBytes;
        auto Policy = std::make_shared<const Prism::Account::PolicySnapshot>(
            Prism::Account::PolicySnapshot::CreateRequest{
                Prism::Account::PolicyVersion{1U}, std::move(Settings), {}});
        return std::make_shared<FixedPolicySource>(std::move(Policy));
    }

    [[nodiscard]] auto PublishAccount(Prism::Account::AccountStore &Store,
        const Prism::AccountId Id,
        std::string StableKey) -> std::shared_ptr<const Prism::Account::AccountBinding>
    {
        auto CredentialText = StableKey;
        std::vector<Prism::Account::CredentialMaterial> Credentials;
        Credentials.push_back({Prism::Account::CredentialScope{1U}, {},
            Prism::Account::Credential::Password(CredentialText)});
        auto Materials = std::make_shared<const Prism::Account::AccountMaterials>(
            Prism::Account::AccountMaterials::CreateRequest{
                Id, std::move(StableKey), std::move(Credentials)});
        auto Prepared = Store.PrepareUpsert(
            Prism::Account::AccountDefinition{std::move(Materials), {}});
        if (!Prepared || !Store.Commit(*Prepared))
        {
            return {};
        }
        return Store.FindById(Id);
    }
}

TEST(PrismApplicationStorage, AuthenticatesLimitedAccountAcrossProductionRestart)
{
    TemporaryStorageDirectory Storage;
    const auto StorageDirectory = Storage.Get().generic_string();
    const auto TcpPort = FindFreePort();
    TemporaryConfiguration Configuration(TcpPort,
        ConfigurationShape{
            .AccountPolicy = R"({"TrafficBytes":{"Mode":"Finite","Value":1048576}})",
            .StorageDirectory = StorageDirectory,
            .OperationsPort = FindFreePort()});
    const auto Ledger = Storage.Get() / "ledger.sqlite3";
    std::string InstanceKey;

    {
        RunningApplication Application(Configuration.Path());
        ASSERT_TRUE(Application.Start());
        ASSERT_TRUE(std::filesystem::exists(Ledger));

        Net::io_context Io;
        Tcp::socket Socket(Io);
        boost::system::error_code Error;
        Socket.connect(Tcp::endpoint(Net::ip::address_v4::loopback(),
            Application.Port()), Error);
        ASSERT_FALSE(Error) << Error.message();
        std::uint8_t Status = 0xff;
        ASSERT_TRUE(Authenticate(Socket, "local-token", Status));
        EXPECT_EQ(Status, 0x00U);
        Socket.close(Error);
        Application.Stop();
        EXPECT_EQ(Application.ExitCode(), 0);
    }

    {
        auto Opened = RunStorage(Prism::Application::Storage::StorageRuntime::Open(
            {Storage.Get(), "verify"}));
        ASSERT_TRUE(Opened);
        InstanceKey = (*Opened)->InstanceKey();
        ASSERT_TRUE(RunStorage((*Opened)->Shutdown()));
        (*Opened)->Join();
    }

    {
        RunningApplication Application(Configuration.Path());
        ASSERT_TRUE(Application.Start());

        Net::io_context Io;
        Tcp::socket Socket(Io);
        boost::system::error_code Error;
        Socket.connect(Tcp::endpoint(Net::ip::address_v4::loopback(),
            Application.Port()), Error);
        ASSERT_FALSE(Error) << Error.message();
        std::uint8_t Status = 0xff;
        ASSERT_TRUE(Authenticate(Socket, "local-token", Status));
        EXPECT_EQ(Status, 0x00U);
        Socket.close(Error);
        Application.Stop();
        ASSERT_EQ(Application.ExitCode(), 0);
    }

    auto Reopened = RunStorage(Prism::Application::Storage::StorageRuntime::Open(
        {Storage.Get(), "verify-again"}));
    ASSERT_TRUE(Reopened);
    EXPECT_EQ((*Reopened)->InstanceKey(), InstanceKey);
    ASSERT_TRUE(RunStorage((*Reopened)->Shutdown()));
    (*Reopened)->Join();
}

TEST(PrismApplicationStorage, FailedPersistenceAttachmentClosesStorageAndLeavesRegistryUnbound)
{
    TemporaryStorageDirectory Storage;
    TemporaryConfiguration Configuration(FindFreePort(),
        ConfigurationShape{.StorageDirectory = Storage.Get().generic_string(),
                           .OperationsPort = FindFreePort()});
    const auto Phase = Prism::Application::Startup::GenerationPhase::Build(
        {Configuration.Path(), {}});
    ASSERT_TRUE(Phase);

    auto Identities = std::make_shared<Prism::Application::AccountIdentityRegistry>();
    auto Preparation = Identities->BeginPreparation();
    ASSERT_TRUE(Preparation);
    const auto StableId = (*Preparation)->Account("stable-account");
    const auto MissingKeyId = (*Preparation)->Account("missing-key-account");
    ASSERT_TRUE(StableId);
    ASSERT_TRUE(MissingKeyId);

    auto Store = std::make_shared<Prism::Account::AccountStore>(
        Prism::Account::StoreOptions{
            .WorkerCount = static_cast<std::uint32_t>(
                Phase->Generation->Configuration().Runtime.WorkerCount),
            .RuntimeRegistry = Identities->RuntimeRegistry(),
            .RevokeRuntimesOnSeal = false});
    const auto StableBinding = PublishAccount(*Store, *StableId, "stable-account");
    ASSERT_TRUE(StableBinding);
    auto MissingKeyRuntime = Identities->RuntimeRegistry()->FindOrCreate(*MissingKeyId, 1U);
    ASSERT_TRUE(MissingKeyRuntime);
    ASSERT_TRUE((*MissingKeyRuntime)->StableKey().empty());
    ASSERT_TRUE(Identities->RuntimeRegistry()->AttachPolicySource(MakePolicySource(std::nullopt)));

    auto Runtime = std::make_shared<Prism::Application::Application::RuntimeState>(
        Prism::Application::Application::RuntimeState::Options{
            .WorkerCount = Phase->Generation->Configuration().Runtime.WorkerCount,
            .Generation = Phase->Generation->Id(),
            .Dns = Prism::Application::Assembly::MakeDnsConfig(
                Phase->Generation->Configuration().Dns)});
    Runtime->Generation = Phase->Generation;
    Runtime->Accounts.Identities = Identities;
    Runtime->Accounts.Store = Store;

    const auto Opened = Prism::Application::StorageLifecycle::Open(Runtime, Configuration.Path());
    ASSERT_FALSE(Opened);
    EXPECT_EQ(Opened.error().Path, "Accounts");
    EXPECT_FALSE(Runtime->StorageOwner);
    EXPECT_FALSE(Runtime->StorageShutdownSucceeded.load(std::memory_order_acquire));
    EXPECT_FALSE(StableBinding->Runtime()->Transfer());
    EXPECT_FALSE((*MissingKeyRuntime)->Transfer());

    const auto Reopened = RunStorage(Prism::Application::Storage::StorageRuntime::Open(
        {Storage.Get(), "after-attachment-failure"}));
    ASSERT_TRUE(Reopened);
    ASSERT_TRUE(RunStorage((*Reopened)->Shutdown()));
    (*Reopened)->Join();

    const auto RepairedBinding = PublishAccount(
        *Store, *MissingKeyId, "missing-key-account");
    ASSERT_TRUE(RepairedBinding);
    EXPECT_TRUE(Identities->RuntimeRegistry()->AttachUsagePersistence(
        std::make_shared<UnusedUsagePersistence>(), "retry-attachment"));
    EXPECT_TRUE(StableBinding->Runtime()->Transfer());
    EXPECT_TRUE(RepairedBinding->Runtime()->Transfer());
    EXPECT_EQ(RepairedBinding->Runtime(), *MissingKeyRuntime);
    EXPECT_TRUE((*MissingKeyRuntime)->Transfer());
}

TEST(PrismApplicationStorage, FinalSettlementFailureRejectsShutdownReceiptAndJoin)
{
    TemporaryStorageDirectory Storage;
    TemporaryConfiguration Configuration(FindFreePort(),
        ConfigurationShape{.StorageDirectory = Storage.Get().generic_string(),
                           .OperationsPort = FindFreePort()});
    const auto Phase = Prism::Application::Startup::GenerationPhase::Build(
        {Configuration.Path(), {}});
    ASSERT_TRUE(Phase);

    auto Identities = std::make_shared<Prism::Application::AccountIdentityRegistry>();
    auto Preparation = Identities->BeginPreparation();
    ASSERT_TRUE(Preparation);
    const auto Id = (*Preparation)->Account("final-settlement-account");
    ASSERT_TRUE(Id);
    ASSERT_TRUE(Identities->RuntimeRegistry()->AttachPolicySource(
        MakePolicySource(4U * 1024U * 1024U)));

    auto Opened = RunStorage(
        Prism::Application::Storage::StorageRuntime::Open(
            {Storage.Get(), "final-settlement-failure"}));
    ASSERT_TRUE(Opened);
    const auto StorageOwner = *Opened;
    auto Persistence = std::make_shared<FinalSettlementFailurePersistence>(
        std::make_shared<Prism::Application::Storage::SqliteUsagePersistence>(StorageOwner));
    ASSERT_TRUE(Identities->RuntimeRegistry()->AttachUsagePersistence(
        Persistence, "final-settlement-failure"));

    auto Store = std::make_shared<Prism::Account::AccountStore>(
        Prism::Account::StoreOptions{
            .WorkerCount = static_cast<std::uint32_t>(
                Phase->Generation->Configuration().Runtime.WorkerCount),
            .RuntimeRegistry = Identities->RuntimeRegistry(),
            .RevokeRuntimesOnSeal = false});
    const auto Binding = PublishAccount(*Store, *Id, "final-settlement-account");
    ASSERT_TRUE(Binding);
    auto Transfer = Binding->Runtime()->Transfer();
    ASSERT_TRUE(Transfer);

    auto Runtime = std::make_shared<Prism::Application::Application::RuntimeState>(
        Prism::Application::Application::RuntimeState::Options{
            .WorkerCount = Phase->Generation->Configuration().Runtime.WorkerCount,
            .Generation = Phase->Generation->Id(),
            .Dns = Prism::Application::Assembly::MakeDnsConfig(
                Phase->Generation->Configuration().Dns)});
    Runtime->Generation = Phase->Generation;
    Runtime->Accounts.Identities = Identities;
    Runtime->Accounts.Store = Store;
    Runtime->StorageOwner = StorageOwner;

    {
        auto Acquired = RunStorage(Transfer->Acquire(
            Prism::Contract::PayloadRequest{1U,
                Prism::Contract::PayloadDirection::Upload, false}));
        ASSERT_TRUE(Acquired);
        Acquired->Finish(1U);
    }

    const auto Finalized = RunStorage(
        Prism::Application::StorageLifecycle::Finalize(Runtime));
    ASSERT_FALSE(Finalized);
    EXPECT_EQ(Finalized.error().Code, Prism::Fault::Code::IoError);
    ASSERT_TRUE(Persistence->FinalSettlementConsumedBytes);
    EXPECT_EQ(*Persistence->FinalSettlementConsumedBytes, 1U);
    EXPECT_EQ(Persistence->ReserveCalls, 1U);
    EXPECT_EQ(Persistence->SettleCalls, 1U);
    EXPECT_FALSE(Runtime->StorageShutdownSucceeded.load(std::memory_order_acquire));
    EXPECT_THROW(Prism::Application::StorageLifecycle::Join(Runtime), std::runtime_error);

    ASSERT_TRUE(RunStorage(Runtime->StorageOwner->Shutdown()));
    Runtime->StorageOwner->Join();
    Runtime->StorageOwner.reset();
    EXPECT_FALSE(Runtime->StorageShutdownSucceeded.load(std::memory_order_acquire));

    const auto Reopened = RunStorage(
        Prism::Application::Storage::StorageRuntime::Open(
            {Storage.Get(), "final-settlement-after-cleanup"}));
    ASSERT_TRUE(Reopened);
    ASSERT_TRUE(Persistence->ReservedCycle);
    {
        Prism::Application::Storage::SqliteUsagePersistence Usage(*Reopened);
        const auto Snapshot = RunStorage(Usage.Read(
            {"final-settlement-account", *Persistence->ReservedCycle,
             4U * 1024U * 1024U}));
        ASSERT_TRUE(Snapshot);
        EXPECT_EQ(Snapshot->SettledBytes, 0U);
        EXPECT_EQ(Snapshot->ReservedBytes, 0U);
        EXPECT_EQ(Snapshot->UncertainBytes, 1024U * 1024U);
        EXPECT_EQ(Snapshot->RemainingBytes, 3U * 1024U * 1024U);
    }
    ASSERT_TRUE(RunStorage((*Reopened)->Shutdown()));
    (*Reopened)->Join();
}

TEST(PrismApplicationStorage, DurableReservationSurvivesNormalRuntimeReopen)
{
    TemporaryStorageDirectory Storage;
    const Prism::Account::UsageReadRequest Read{
        "durable-reservation-account", {0, 1000}, 4U * 1024U * 1024U};
    const Prism::Account::UsageReservationRequest ReservationRequest{
        Read, "durable-reservation-request", 1024U * 1024U, 2U * 1024U * 1024U};
    std::string InstanceKey;
    std::string ReservationId;

    {
        const auto Opened = RunStorage(
            Prism::Application::Storage::StorageRuntime::Open(
                {Storage.Get(), "durable-first"}));
        ASSERT_TRUE(Opened);
        InstanceKey = (*Opened)->InstanceKey();
        {
            Prism::Application::Storage::SqliteUsagePersistence Usage(*Opened);
            const auto Reserved = RunStorage(Usage.Reserve(ReservationRequest));
            ASSERT_TRUE(Reserved);
            EXPECT_EQ(Reserved->Bytes, 1024U * 1024U);
            ReservationId = Reserved->ReservationId;
        }
        ASSERT_TRUE(RunStorage((*Opened)->Shutdown()));
        (*Opened)->Join();
    }

    const auto Reopened = RunStorage(
        Prism::Application::Storage::StorageRuntime::Open(
            {Storage.Get(), "durable-second"}));
    ASSERT_TRUE(Reopened);
    EXPECT_EQ((*Reopened)->InstanceKey(), InstanceKey);
    {
        Prism::Application::Storage::SqliteUsagePersistence Usage(*Reopened);
        const auto Snapshot = RunStorage(Usage.Read(Read));
        ASSERT_TRUE(Snapshot);
        EXPECT_EQ(Snapshot->SettledBytes, 0U);
        EXPECT_EQ(Snapshot->ReservedBytes, 0U);
        EXPECT_EQ(Snapshot->UncertainBytes, 1024U * 1024U);
        EXPECT_EQ(Snapshot->RemainingBytes, 3U * 1024U * 1024U);

        const auto OldSettlement = RunStorage(Usage.Settle(
            {ReservationId, 1024U * 1024U, true}));
        ASSERT_FALSE(OldSettlement);
        EXPECT_EQ(OldSettlement.error().Code, Prism::Fault::Code::ReplayDetected);

        const auto Stable = RunStorage(Usage.Read(Read));
        ASSERT_TRUE(Stable);
        EXPECT_EQ(Stable->SettledBytes, 0U);
        EXPECT_EQ(Stable->ReservedBytes, 0U);
        EXPECT_EQ(Stable->UncertainBytes, 1024U * 1024U);
        EXPECT_EQ(Stable->RemainingBytes, 3U * 1024U * 1024U);

        const auto Fresh = RunStorage(Usage.Reserve(
            {Read, "durable-reservation-after-reopen", 1024U * 1024U,
             2U * 1024U * 1024U}));
        ASSERT_TRUE(Fresh);
        EXPECT_EQ(Fresh->Bytes, 1024U * 1024U);
        const auto AfterReservation = RunStorage(Usage.Read(Read));
        ASSERT_TRUE(AfterReservation);
        EXPECT_EQ(AfterReservation->ReservedBytes, 1024U * 1024U);
        EXPECT_EQ(AfterReservation->UncertainBytes, 1024U * 1024U);
        EXPECT_EQ(AfterReservation->RemainingBytes, 2U * 1024U * 1024U);
    }
    ASSERT_TRUE(RunStorage((*Reopened)->Shutdown()));
    (*Reopened)->Join();
}
