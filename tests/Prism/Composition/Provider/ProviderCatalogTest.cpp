/** @file ProviderCatalogTest.cpp @brief 实际实例、冻结、单次绑定、移动和关闭后拒绝。 */
#include <gtest/gtest.h>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Composition/Provider/BoundCatalog.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <TestSupport/Fixtures/RecognitionWire.hpp>
#include <atomic>
#include <cstddef>
#include <expected>
#include <optional>
#include <stdexcept>
#include <thread>
#include "CatalogFixture.hpp"
#include <Prism/Transport/MemoryStream.hpp>
#include <boost/asio/co_spawn.hpp>
namespace
{
    namespace P=Prism::Composition::Provider;
    using E=Prism::Contract::ProviderError;
    TEST(BoundCatalogDrainPolicy, RequiresOwnerReceiptForRetiredCancellationAndBlockedAttempts)
    {
        using Failure = Prism::Fault::Failure;
        using Retirement = P::PhysicalRetirementState;
        using Receipt = P::Detail::DrainOwnerFailureReceipt;
        const auto Canceled = std::expected<void, Failure>{std::unexpected(
            Failure{Prism::Fault::Code::Canceled})};
        const auto Blocked = std::expected<void, Failure>{std::unexpected(
            Failure{Prism::Fault::Code::Blocked})};
        const auto IoError = Failure{Prism::Fault::Code::IoError};
        const auto IoFailure = std::expected<void, Failure>{std::unexpected(IoError)};

        EXPECT_TRUE(P::Detail::IsRetryableDrainAttempt(
            Canceled, Receipt{{}, Retirement::Active, false}));
        EXPECT_FALSE(P::Detail::IsRetryableDrainAttempt(
            Canceled, Receipt{{}, Retirement::Retired, false}));
        EXPECT_TRUE(P::Detail::IsRetryableDrainAttempt(
            Canceled, Receipt{{}, Retirement::Retired, true}));
        EXPECT_FALSE(P::Detail::IsRetryableDrainAttempt(Canceled,
            Receipt{Failure{Prism::Fault::Code::Canceled}, Retirement::Retired, true}));
        EXPECT_FALSE(P::Detail::IsRetryableDrainAttempt(Canceled,
            Receipt{IoError, Retirement::Retired, true}));
        EXPECT_TRUE(P::Detail::IsRetryableDrainAttempt(
            Blocked, Receipt{{}, Retirement::Active, true}));
        EXPECT_FALSE(P::Detail::IsRetryableDrainAttempt(
            Blocked, Receipt{{}, Retirement::Active, false}));
        EXPECT_FALSE(P::Detail::IsRetryableDrainAttempt(
            IoFailure, Receipt{{}, Retirement::Active, true}));
    }

    /** @brief 构造携带有界字节池的真实流接入输入。 */
    [[nodiscard]] auto MakeStreamAcceptInput(Prism::SharedTransmission Inbound,
        Prism::Contract::RequestMetadata Metadata={}) -> Prism::Contract::StreamAcceptInput
    {
        return {std::move(Inbound),std::move(Metadata),
            std::make_shared<Prism::Memory::BytePool>(Prism::Memory::BytePoolOptions{.BlockCount=8})};
    }
    TEST(ProviderCatalogContract, RejectsMissingAndDuplicateKeys)
    {
        ProviderTesting::Fixture Fixture;auto Input=Fixture.Input();
        Input.Instances.push_back(Input.Instances[0]);
        auto Prepared=P::ProviderCatalog::Prepare(std::move(Input),Fixture.Services());
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Code,E::DuplicateInstance);
        Input=Fixture.Input("");auto Missing=P::ProviderCatalog::Prepare(std::move(Input),Fixture.Services());
        EXPECT_FALSE(Missing);
    }
    TEST(ProviderCatalogContract, ValidatesRequiredCapabilitiesBeforePrepare)
    {
        ProviderTesting::Fixture Fixture;auto Input=Fixture.Input();Input.Instances[0].Udp=true;
        auto Prepared=P::ProviderCatalog::Prepare(std::move(Input),Fixture.Services());
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Code,E::MissingResolver);
    }
    TEST(ProviderCatalogContract, PrepareRequiresValidationAndPropagatesTypedFailure)
    {
        ProviderTesting::Fixture Fixture;auto Input=Fixture.Input();Input.Instances[0].Authentication.Credentials={};
        auto Prepared=P::ProviderCatalog::Prepare(std::move(Input),Fixture.Services());
        ASSERT_FALSE(Prepared);EXPECT_EQ(Prepared.error().Instance,"socks-instance");
        EXPECT_EQ(Prepared.error().Path,"Authentication");
    }
    TEST(ProviderCatalogContract, LocksRegistrationAfterPrepareAndFreezesOnlyOnce)
    {
        ProviderTesting::Fixture Fixture;auto Prepared=P::ProviderCatalog::Prepare(Fixture.Input(),Fixture.Services());
        ASSERT_TRUE(Prepared);auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);
        auto Twice=Prepared->Freeze();ASSERT_FALSE(Twice);EXPECT_EQ(Twice.error().Code,E::AlreadyFrozen);
        auto Bound=Frozen->Bind({});ASSERT_TRUE(Bound);Bound->Close();Fixture.Io.run();
    }
    TEST(ProviderCatalogContract, BindsFrozenCatalogWithTypedServicesAndClosesOwnerOnce)
    {
        ProviderTesting::Fixture Fixture;
        auto Input = Fixture.Input();
        const auto UseState = Input.UseState;
        auto Prepared=P::ProviderCatalog::Prepare(std::move(Input),Fixture.Services());
        ASSERT_TRUE(Prepared);auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);
        auto Bound=Frozen->Bind({});ASSERT_TRUE(Bound);
        EXPECT_EQ(Bound->UseState(), UseState);
        auto Factory=Bound->Find("socks-instance")->Stream();
        Bound->Close();Bound->Close();bool Rejected=false,Drained=false;
        auto [Client,Server]=Prism::MakeMemoryPair(Fixture.Io.get_executor());
        auto Run=[&]()->boost::asio::awaitable<void>
        {
            auto Inbound=std::make_shared<Prism::MemoryStream>(std::move(Server));
            auto Result=co_await Factory->Accept(MakeStreamAcceptInput(std::move(Inbound)));
            Rejected=!Result;Drained=static_cast<bool>(co_await Bound->Drain());
        };
        boost::asio::co_spawn(Fixture.Io,Run(),[](std::exception_ptr Error){EXPECT_FALSE(Error);});
        Fixture.Io.run();EXPECT_TRUE(Rejected);EXPECT_TRUE(Drained);
    }
    TEST(ProviderCatalogContract, PreparedCatalogSharesOneBindGateWithFrozenCatalog)
    {
        ProviderTesting::Fixture Fixture;auto Prepared=P::ProviderCatalog::Prepare(Fixture.Input(),Fixture.Services());
        ASSERT_TRUE(Prepared);auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);
        P::FrozenCatalog Moved(std::move(*Frozen));auto Invalid=Frozen->Bind({});
        ASSERT_FALSE(Invalid);EXPECT_EQ(Invalid.error().Code,E::AlreadyBound);
        auto Bound=Moved.Bind({});ASSERT_TRUE(Bound);auto Twice=Moved.Bind({});
        ASSERT_FALSE(Twice);EXPECT_EQ(Twice.error().Code,E::AlreadyBound);Bound->Close();Fixture.Io.run();
    }
    TEST(ProviderCatalogContract, ConvertsBindFailureToTypedErrorAndConsumesBindOnce)
    {
        ProviderTesting::Fixture Fixture;auto Prepared=P::ProviderCatalog::Prepare(Fixture.Input(),Fixture.Services());
        ASSERT_TRUE(Prepared);auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);std::stop_source Stop;Stop.request_stop();
        auto Failed=Frozen->Bind(Stop.get_token());ASSERT_FALSE(Failed);EXPECT_EQ(Failed.error().Code,E::Cancelled);
        auto Twice=Frozen->Bind({});ASSERT_FALSE(Twice);EXPECT_EQ(Twice.error().Code,E::AlreadyBound);
    }
    TEST(ProviderCatalogContract, PreservesMultipleConfiguredInstancesOfSameProtocol)
    {
        ProviderTesting::Fixture Fixture;auto Input=Fixture.Input();auto Second=Input.Instances[0];Second.Protocol.Id="second";
        Input.Instances.push_back(std::move(Second));auto Prepared=P::ProviderCatalog::Prepare(std::move(Input),Fixture.Services());
        ASSERT_TRUE(Prepared);auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);auto Bound=Frozen->Bind({});ASSERT_TRUE(Bound);
        EXPECT_EQ(Bound->Entries().size(),2);EXPECT_NE(Bound->Find("socks-instance")->Stream(),Bound->Find("second")->Stream());
        Bound->Close();Fixture.Io.run();
    }
}


namespace
{
    namespace Net = boost::asio;
    using DrainSignal = Net::experimental::channel<void(boost::system::error_code)>;
    enum class RetirementReceipt
    {
        OnCloseSucceeded, CarrierActivityFailed, CarrierActivitySucceeded,
        AdmissionHandlerReturned, CarrierDestroyed
    };
    using RetirementSignal = Net::experimental::concurrent_channel<
        void(boost::system::error_code, RetirementReceipt)>;

    struct CloseStats final
    {
        int Calls{0};
        bool Open{true}, Destroyed{false}, WrongThread{false};
        std::thread::id Thread{std::this_thread::get_id()};
    };

    struct PendingIo final
    {
        explicit PendingIo(Net::any_io_executor Executor)
            : Entered(Executor, 1), Released(Executor, 1), Retirements(Executor, 16) {}
        DrainSignal Entered, Released;
        RetirementSignal Retirements;
        std::atomic<bool> ReceiptDropped{false};
        std::atomic<bool> ReadReleaseRequested{false};
        std::shared_ptr<CloseStats> Stats{std::make_shared<CloseStats>()};
        /** @brief 幂等唤醒 fixture 的挂起读取；不代替控制关闭或 activity 回执。 */
        auto ReleaseRead() noexcept -> bool
        {
            bool NotRequested = false;
            if (!ReadReleaseRequested.compare_exchange_strong(
                    NotRequested, true, std::memory_order_acq_rel))
            {
                return true;
            }
            if (Released.try_send(boost::system::error_code{})) return true;
            ReadReleaseRequested.store(false, std::memory_order_release);
            return false;
        }
        auto Publish(RetirementReceipt Receipt) noexcept -> void
        {
            if (!Retirements.try_send(boost::system::error_code{}, Receipt))
                ReceiptDropped.store(true, std::memory_order_release);
        }
    };

    /** @brief 为真实底层传输 Drain 回执加测试观察点，不改变其错误或所有权。 */
    class ObservedCarrierActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        ObservedCarrierActivity(
            std::shared_ptr<Prism::Contract::CarrierActivity> Inner,
            std::shared_ptr<PendingIo> Pending)
            : Inner_(std::move(Inner)), Pending_(std::move(Pending)) {}
        auto Seal() noexcept -> void override { Inner_->Seal(); }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return Inner_->IsRetired(); }
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        { return Inner_->Executor(); }
        auto Drain() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            auto Result = co_await Inner_->Drain();
            auto Receipt = RetirementReceipt::CarrierActivityFailed;
            if (Result)
            {
                Receipt = RetirementReceipt::CarrierActivitySucceeded;
            }
            Pending_->Publish(Receipt);
            co_return Result;
        }
    private:
        std::shared_ptr<Prism::Contract::CarrierActivity> Inner_;
        std::shared_ptr<PendingIo> Pending_;
    };

    class FailingAdmissionTransport final : public Prism::Transmission
    {
    public:
        FailingAdmissionTransport(Net::any_io_executor Executor, std::shared_ptr<PendingIo> Pending)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)), Pending_(std::move(Pending)),
              Activity_(std::make_shared<ObservedCarrierActivity>(Prism::Transmission::Activity(), Pending_)) {}
        ~FailingAdmissionTransport() override
        {
            CheckThread(); Pending_->Stats->Destroyed = true;
            Pending_->Publish(RetirementReceipt::CarrierDestroyed);
        }
        auto Executor() const -> ExecutorType override { return Executor_; }
        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override { return Activity_; }
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(ReadWork{}, Executor_), Handler,
                ReadInput{std::static_pointer_cast<FailingAdmissionTransport>(
                              Prism::Transmission::shared_from_this()),
                          Buffer});
        }
        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        { Prism::Transport::Detail::PostResult(Executor_, std::move(Handler), NotOpen()); }
        auto StartWriteShutdown(Completion Handler) -> void override
        { Prism::Transport::Detail::PostResult(Executor_, std::move(Handler), {}); }
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            CheckThread();
            (void)Pending_->ReleaseRead();
            return {};
        }
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            CheckThread();
            if (++Pending_->Stats->Calls == 1) throw std::runtime_error("owned carrier close failed once");
            Pending_->Stats->Open = false;
            (void)Pending_->ReleaseRead();
            Pending_->Publish(RetirementReceipt::OnCloseSucceeded);
            return {};
        }
        auto IsOpen() const -> bool override { CheckThread(); return Pending_->Stats->Open; }
    private:
        struct ReadInput final
        {
            std::shared_ptr<FailingAdmissionTransport> Owner;
            std::span<std::byte> Buffer;
        };
        /** @brief 原协程体原位保留，新前门一次性映射正式结果。 */
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(Input.Owner->Executor(),
                    Input.Owner->ReadPartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
        {
            (void)Buffer;
            (void)Pending_->Entered.try_send(boost::system::error_code{});
            co_await Pending_->Released.async_receive(Net::use_awaitable);
            co_return Prism::IoResult{0,
                Prism::Fault::FromNative(Prism::make_error_code(Prism::Error::NotOpen))};
        }
        /** @brief 载体已失效的确定失败；保留协议私有 NotOpen 的原生 category/value。 */
        static auto NotOpen() -> Prism::IoResult
        { return Prism::IoResult{0, Prism::Fault::FromNative(Prism::make_error_code(Prism::Error::NotOpen))}; }
        auto CheckThread() const -> void
        { Pending_->Stats->WrongThread |= Pending_->Stats->Thread != std::this_thread::get_id(); }
        Net::any_io_executor Executor_;
        std::shared_ptr<PendingIo> Pending_;
        std::shared_ptr<ObservedCarrierActivity> Activity_;
    };

    struct CatalogDrainResult final
    {
        bool Prepared{false}, ReadEntered{false}, SocksAccepted{false}, SocksReturned{false};
        bool SsAccepted{false}, SsLease{false}, ClientConnected{false};
        bool ConnectionAtAccept{false}, ConnectionZero{false}, MaterialReleased{false};
        bool Failed{false}, TimedOut{false}, FailedCarrierRetained{false}, CarrierRetiredAfterRetry{false};
        bool RetryOnCloseSucceeded{false}, RetryCarrierActivityDrained{false};
        bool RetryAdmissionHandlerReturned{false}, RetryCarrierDestroyed{false};
        bool RetryCatalogDrainReturned{false}, CatalogReleasedAfterRetry{false};
        bool CatalogPhysicalRetiredAfterCleanup{false}, CatalogPhysicalRetiredAfterRetry{false};
        bool RetirementReceiptDropped{false};
        std::size_t PendingAfterCleanup{0}, PendingAfterRetry{0};
        Prism::Fault::Failure Failure{Prism::Fault::Code::Success};
        Prism::Fault::Failure RetryCatalogDrainFailure{Prism::Fault::Code::Success};
        std::string SetupError;
        std::exception_ptr Unexpected;
        std::shared_ptr<CloseStats> Stats;
        std::weak_ptr<Prism::Transmission> WeakFailedCarrier;
        std::weak_ptr<Prism::Contract::CarrierActivity> WeakFailedCarrierActivity;
        std::weak_ptr<P::BoundCatalog> WeakCatalog;
        std::weak_ptr<Prism::Contract::StreamFactory> WeakSocksFactory, WeakSsFactory;
        const Prism::Transmission* FailedCarrierIdentity{nullptr};
        std::weak_ptr<const Prism::Account::AccountBinding> WeakRecord;
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> WeakGeneration;
        std::weak_ptr<Prism::Executor::ContextOwner> WeakContext;
    };

    struct CatalogDrainScenario final
    {
        CatalogDrainScenario()
            : Context(Prism::Executor::ContextOwner::Create(Storage)), Executor(Context->Io.get_executor()),
              Deadline(Executor), SsReady(Executor, 1), ClientReady(Executor, 1), SocksDone(Executor, 1),
              Pending(std::make_shared<PendingIo>(Executor))
        { Result.Stats = Pending->Stats; Result.WeakContext = Context; }
        auto Stop() noexcept -> void
        {
            if (StopRequested) return;
            StopRequested = true;
            if (Catalog) Catalog->Close();
            else if (Carrier) (void)Carrier->Close();
            if (SsClient) (void)SsClient->Close();
            (void)Pending->ReleaseRead();
            (void)SsReady.try_send(boost::system::error_code{});
            (void)ClientReady.try_send(boost::system::error_code{});
            (void)SocksDone.try_send(boost::system::error_code{});
            Deadline.cancel();
        }
        // context先创建最后释放；返回的结果只保存普通计数，不携带Asio资源。
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage{std::make_shared<Prism::Executor::ClosingStorage>()};
        std::shared_ptr<Prism::Executor::ContextOwner> Context;
        Net::any_io_executor Executor;
        Net::steady_timer Deadline;
        DrainSignal SsReady, ClientReady, SocksDone;
        std::shared_ptr<PendingIo> Pending;
        CatalogDrainResult Result;
        Prism::Foundation::GenerationPin Pin;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState{
            std::make_shared<Prism::Foundation::GenerationUseState>()};
        std::shared_ptr<Prism::Testing::ProviderAccounts> SocksAccounts, SsAccounts;
        Prism::SharedAuthenticator SocksAuth, SsAuth;
        std::shared_ptr<P::BoundCatalog> Catalog;
        std::shared_ptr<Prism::Contract::StreamFactory> SocksFactory, SsFactory;
        Prism::SharedTransmission Carrier, SsClient, SsServer, SsConnection;
        std::optional<Prism::Contract::ProtocolDataPlane> Plane;
        std::array<std::uint8_t, 16> Key{Prism::Testing::RecognitionWire::MakePsk(0x77)};
        std::size_t TasksStarted{0}, TasksCompleted{0};
        bool StopRequested{false};
    };

    /** @brief 记录一个独立协程的真实完成并传播其异常。 */
    auto CompleteCatalogTask(
        const std::shared_ptr<CatalogDrainScenario>& State,
        std::exception_ptr Error) -> void
    {
        if (Error)
        {
            State->Result.Unexpected = std::move(Error);
            State->Stop();
        }
        ++State->TasksCompleted;
        if (State->TasksCompleted == State->TasksStarted)
            State->Context->Io.stop();
        // 五个真实完成回调已返回后停止本阶段；后续显式重启等待清理与退休回执。
    }

    auto PrepareCatalogDrain(const std::shared_ptr<CatalogDrainScenario>& State) -> bool
    {
        State->Pin = Prism::Testing::ProviderPin();
        State->Result.WeakGeneration = State->Pin;
        State->SocksAccounts = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Password("provider-password"));
        const std::string Bytes(reinterpret_cast<const char*>(State->Key.data()), State->Key.size());
        State->SsAccounts = Prism::Testing::ProviderAccount(Prism::Account::Credential::Psk(Bytes));
        State->SocksAuth = State->SocksAccounts->Authenticator;
        State->SsAuth = State->SsAccounts->Authenticator;
        P::Preparation Input{State->Pin, State->UseState, {
            {{"socks-instance", "socks5", "socks5", {}, {}}, true, false,
             {State->Pin, State->SocksAccounts->Credentials, State->SocksAuth}},
            {{"ss-instance", "ss2022", "ss2022", {}, {}}, true, false,
             {State->Pin, State->SsAccounts->Credentials, State->SsAuth}}}};
        auto Prepared = P::ProviderCatalog::Prepare(std::move(Input), {State->Executor, {}, {}, {}});
        if (!Prepared) { State->Result.SetupError = "catalog prepare rejected the real account services"; return false; }
        auto Frozen = Prepared->Freeze();
        if (!Frozen) { State->Result.SetupError = "catalog freeze failed"; return false; }
        auto Bound = Frozen->Bind({});
        if (!Bound) { State->Result.SetupError = "catalog bind failed"; return false; }
        State->Catalog = std::make_shared<P::BoundCatalog>(std::move(*Bound));
        State->Result.WeakCatalog = State->Catalog;
        State->SocksFactory = State->Catalog->Find("socks-instance")->Stream();
        State->SsFactory = State->Catalog->Find("ss-instance")->Stream();
        State->Result.WeakSocksFactory = State->SocksFactory;
        State->Result.WeakSsFactory = State->SsFactory;
        State->Carrier = std::make_shared<FailingAdmissionTransport>(State->Executor, State->Pending);
        State->Result.WeakFailedCarrierActivity = State->Carrier->Activity();
        State->Result.WeakFailedCarrier = State->Carrier;
        State->Result.FailedCarrierIdentity = State->Carrier.get();
        auto [Client, Server] = Prism::MakeMemoryPair(State->Executor);
        State->SsClient = std::make_shared<Prism::MemoryStream>(std::move(Client));
        State->SsServer = std::make_shared<Prism::MemoryStream>(std::move(Server));
        State->Result.Prepared = true;
        return true;
    }

    auto AcceptFailingSocks(const std::shared_ptr<CatalogDrainScenario>& State) -> Net::awaitable<void>
    {
        try { auto Value = co_await State->SocksFactory->Accept(MakeStreamAcceptInput(State->Carrier)); State->Result.SocksAccepted = bool(Value); }
        catch (...) { State->Result.Unexpected = std::current_exception(); }
        State->Result.SocksReturned = true;
        State->Pending->Publish(RetirementReceipt::AdmissionHandlerReturned);
        (void)State->SocksDone.try_send(boost::system::error_code{});
    }

    auto AcceptHealthySs(const std::shared_ptr<CatalogDrainScenario>& State) -> Net::awaitable<void>
    {
        try
        {
            auto Value = co_await State->SsFactory->Accept(MakeStreamAcceptInput(State->SsServer));
            State->Result.SsAccepted = bool(Value);
            if (Value) { State->Result.SsLease = bool(Value->AccountLease); State->Plane.emplace(std::move(*Value)); }
        }
        catch (...) { State->Result.Unexpected = std::current_exception(); }
        (void)State->SsReady.try_send(boost::system::error_code{});
    }

    auto ConnectHealthySs(const std::shared_ptr<CatalogDrainScenario>& State) -> Net::awaitable<void>
    {
        try
        {
            Prism::Shadowsocks2022::ClientConfig Config;
            Config.Psk = State->Key;
            auto Connection = co_await Prism::Shadowsocks2022::Connect(State->SsClient, Config,
                {Prism::Shadowsocks2022::AddressType::Domain, "echo", 7});
            State->Result.ClientConnected = bool(Connection);
            if (Connection) State->SsConnection = std::move(*Connection);
        }
        catch (...) { State->Result.Unexpected = std::current_exception(); }
        (void)State->ClientReady.try_send(boost::system::error_code{});
    }

    /** @brief 等待健康 Shadowsocks 客户端真实 Activity drain 完成。 */
    auto DrainCleanupClient(Prism::SharedTransmission Client) -> Net::awaitable<void>
    {
        const auto DrainResult = co_await Client->Activity()->Drain();
        if (!DrainResult) throw std::runtime_error("healthy provider client failed cleanup drain");
    }

    /** @brief 等待重试 control、底层 Activity、接入 handler 与 provider drain 的真实回执。 */
    auto AwaitProviderRetirement(std::shared_ptr<CatalogDrainScenario> State) -> Net::awaitable<void>
    {
        bool OnCloseSucceeded = false, ActivityDrained = false;
        bool AdmissionReturned = false, CarrierDestroyed = false;
        const auto Catalog = State->Catalog;
        if (!Catalog) throw std::runtime_error("provider catalog owner vanished before retry drain receipt");
        while (!OnCloseSucceeded || !ActivityDrained || !AdmissionReturned || !CarrierDestroyed)
        {
            const auto Receipt = co_await State->Pending->Retirements.async_receive(Net::use_awaitable);
            if (Receipt == RetirementReceipt::OnCloseSucceeded && !OnCloseSucceeded)
            {
                OnCloseSucceeded = true;
                // 底层 Close 已实际重试成功；此时再驱动 catalog ticket 的 typed drain，
                // 由真正 provider owner 释放其 tracked transport，再等待最终销毁回执。
                const auto WrapperResult = co_await Catalog->Drain();
                State->Result.RetryCatalogDrainReturned = true;
                if (!WrapperResult) State->Result.RetryCatalogDrainFailure = WrapperResult.error();
            }
            if (Receipt == RetirementReceipt::CarrierActivitySucceeded) ActivityDrained = true;
            if (Receipt == RetirementReceipt::AdmissionHandlerReturned) AdmissionReturned = true;
            if (Receipt == RetirementReceipt::CarrierDestroyed) CarrierDestroyed = true;
            State->Storage->Collect();
            // 低层物理回执可能使父 admission ticket 可退休；再请求一次原 executor 清理。
            State->Storage->Retry();
        }
        State->Result.RetryOnCloseSucceeded = OnCloseSucceeded;
        State->Result.RetryCarrierActivityDrained = ActivityDrained;
        State->Result.RetryAdmissionHandlerReturned = AdmissionReturned;
        State->Result.RetryCarrierDestroyed = CarrierDestroyed;
        State->Result.CatalogPhysicalRetiredAfterRetry = Catalog->PhysicalRetirement().Complete();
    }

    auto CleanupCatalogDrain(const std::shared_ptr<CatalogDrainScenario>& State) -> void
    {
        State->Context->Io.restart();
        auto CleanupClient = State->SsClient;
        State->Plane.reset(); State->SsConnection.reset(); (void)State->SsClient->Close();
        State->Carrier.reset(); State->SocksFactory.reset(); State->SsFactory.reset();
        State->SocksAccounts.reset(); State->SsAccounts.reset(); State->SocksAuth.reset(); State->SsAuth.reset();
        State->SsClient.reset(); State->SsServer.reset(); State->Pin.reset();
        Net::co_spawn(State->Context->Io, DrainCleanupClient(std::move(CleanupClient)),
            [State](std::exception_ptr Error)
        {
            if (Error) State->Result.Unexpected = std::move(Error);
            State->Context->Io.stop();
        });
        State->Context->Io.run();
        State->Storage->Collect();
        State->Result.PendingAfterCleanup = State->Storage->Pending();
        State->Storage->Collect();
        if (State->Catalog)
        {
            State->Result.CatalogPhysicalRetiredAfterCleanup =
                State->Catalog->PhysicalRetirement().Complete();
        }
        {
            const auto FailedCarrier = State->Result.WeakFailedCarrier.lock();
            State->Result.FailedCarrierRetained = FailedCarrier &&
                FailedCarrier.get() == State->Result.FailedCarrierIdentity &&
                !State->Result.WeakFailedCarrierActivity.expired() && !State->Result.Stats->Destroyed;
        }
        State->Context->Io.restart();
        State->Storage->Retry();
        Net::co_spawn(State->Context->Io, AwaitProviderRetirement(State),
            [State](std::exception_ptr Error)
        {
            if (Error) State->Result.Unexpected = std::move(Error);
            State->Context->Io.stop();
        });
        State->Context->Io.run();
        State->Storage->Collect();
        State->Result.PendingAfterRetry = State->Storage->Pending();
        State->Result.RetirementReceiptDropped = State->Pending->ReceiptDropped.load(std::memory_order_acquire);
        State->Result.CarrierRetiredAfterRetry =
            State->Result.RetryOnCloseSucceeded && State->Result.RetryCarrierActivityDrained &&
            State->Result.RetryAdmissionHandlerReturned && State->Result.RetryCarrierDestroyed &&
            State->Result.RetryCatalogDrainReturned &&
            State->Result.WeakFailedCarrier.expired() &&
            State->Result.PendingAfterRetry == 0;
        State->Catalog.reset();
        State->Storage->Collect();
        State->Result.CatalogReleasedAfterRetry = State->Result.WeakCatalog.expired() &&
            State->Result.WeakSocksFactory.expired() && State->Result.WeakSsFactory.expired();
        State->Deadline.cancel();
    }

    auto DriveCatalogDrain(const std::shared_ptr<CatalogDrainScenario>& State) -> Net::awaitable<void>
    {
        Net::co_spawn(State->Context->Io, AcceptFailingSocks(State),
            [State](std::exception_ptr Error) { CompleteCatalogTask(State, std::move(Error)); });
        ++State->TasksStarted;
        Net::co_spawn(State->Context->Io, AcceptHealthySs(State),
            [State](std::exception_ptr Error) { CompleteCatalogTask(State, std::move(Error)); });
        ++State->TasksStarted;
        Net::co_spawn(State->Context->Io, ConnectHealthySs(State),
            [State](std::exception_ptr Error) { CompleteCatalogTask(State, std::move(Error)); });
        ++State->TasksStarted;
        co_await State->Pending->Entered.async_receive(Net::use_awaitable);
        State->Result.ReadEntered = true;
        State->Carrier.reset();
        co_await State->SsReady.async_receive(Net::use_awaitable);
        co_await State->ClientReady.async_receive(Net::use_awaitable);
        auto Record = State->SsAccounts->Store->FindById(Prism::AccountId{1});
        if (!Record || !State->Plane || !State->Result.ClientConnected)
        { State->Result.SetupError = "healthy SS2022 did not publish a real authenticated plane"; }
        if (Record)
        {
            const auto Runtime = Record->Runtime();
            State->Result.ConnectionAtAccept = Runtime->ActiveConnections() == 1;
            State->Result.WeakRecord = Record;
            auto Removed = State->SsAccounts->Store->PrepareRemove(Record->AccountId());
            if (!Removed || !State->SsAccounts->Store->Commit(*Removed)) State->Result.SetupError = "account removal failed";
            Record.reset();
            State->SsAccounts.reset(); State->SsAuth.reset();
            State->Catalog->Close(); State->Plane.reset(); State->SsConnection.reset(); (void)State->SsClient->Close();
            State->Result.ConnectionZero = Runtime->ActiveConnections() == 0;
        }
        else State->Catalog->Close();
        const auto DrainResult=co_await State->Catalog->Drain();
        if(!DrainResult)
        {
            State->Result.Failed=true;
            State->Result.Failure=DrainResult.error();
        }
        State->Result.MaterialReleased = State->Result.WeakRecord.expired();
        co_await State->SocksDone.async_receive(Net::use_awaitable);
        State->Deadline.cancel();
    }

    auto WatchCatalogDrain(const std::shared_ptr<CatalogDrainScenario>& State) -> Net::awaitable<void>
    {
        State->Deadline.expires_after(std::chrono::seconds(5));
        boost::system::error_code Error;
        co_await State->Deadline.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (Error) co_return;
        State->Result.TimedOut = true;
        State->Stop();
    }

    auto RunCatalogDrainScenario() -> CatalogDrainResult
    {
        auto State = std::make_shared<CatalogDrainScenario>();
        if (!PrepareCatalogDrain(State)) return State->Result;
        Net::co_spawn(State->Context->Io, WatchCatalogDrain(State),
            [State](std::exception_ptr Error) { CompleteCatalogTask(State, std::move(Error)); });
        ++State->TasksStarted;
        Net::co_spawn(State->Context->Io, DriveCatalogDrain(State),
            [State](std::exception_ptr Error) { CompleteCatalogTask(State, std::move(Error)); });
        ++State->TasksStarted;
        auto& Io = State->Context->Io;
        bool AdmissionReleased = false;
        while (State->TasksCompleted < State->TasksStarted)
        {
            const auto CompletedBeforeRun = State->TasksCompleted;
            Io.run();
            if (State->TasksCompleted == State->TasksStarted) break;
            if (!Io.stopped())
            {
                if (State->TasksCompleted == CompletedBeforeRun)
                {
                    State->Result.Unexpected = std::make_exception_ptr(
                        std::runtime_error("executor returned before owned catalog tasks completed"));
                    State->Stop();
                }
                continue;
            }
            Io.restart();
            if (State->Context->Fatal->HasFailure() && !AdmissionReleased)
            {
                AdmissionReleased = State->Pending->ReleaseRead();
                if (!AdmissionReleased)
                {
                    State->Result.Unexpected = std::make_exception_ptr(
                        std::runtime_error("pending admission read did not accept its cleanup release"));
                    State->Stop();
                }
                continue;
            }
            if (State->TasksCompleted == CompletedBeforeRun)
            {
                State->Result.Unexpected = std::make_exception_ptr(
                    std::runtime_error("executor returned before owned catalog tasks completed"));
                State->Stop();
            }
        }
        CleanupCatalogDrain(State);
        return State->Result;
    }

    TEST(ProviderCatalogContract, DrainContinuesAfterTypedOwnerFailure)
    {
        const auto Result = RunCatalogDrainScenario();
        EXPECT_TRUE(Result.Prepared) << Result.SetupError;
        EXPECT_TRUE(Result.SetupError.empty()) << Result.SetupError;
        EXPECT_FALSE(Result.Unexpected);
        EXPECT_FALSE(Result.TimedOut);
        EXPECT_TRUE(Result.ReadEntered); EXPECT_TRUE(Result.SocksReturned); EXPECT_FALSE(Result.SocksAccepted);
        EXPECT_TRUE(Result.SsAccepted); EXPECT_TRUE(Result.SsLease); EXPECT_TRUE(Result.ClientConnected);
        EXPECT_TRUE(Result.ConnectionAtAccept); EXPECT_TRUE(Result.ConnectionZero);
        EXPECT_TRUE(Result.Failed); EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::Blocked);
        EXPECT_FALSE(Result.Failure.Native);
        EXPECT_TRUE(Result.MaterialReleased);
        EXPECT_TRUE(Result.FailedCarrierRetained);
        EXPECT_FALSE(Result.CatalogPhysicalRetiredAfterCleanup);
        // 首次失败的 I/O、控制、binding 与 admission ticket 四槽，加健康 wrapper 的 I/O、控制两槽。
        EXPECT_EQ(Result.PendingAfterCleanup, 6U);
        EXPECT_EQ(Result.PendingAfterRetry, 0);
        EXPECT_TRUE(Result.RetryOnCloseSucceeded);
        EXPECT_TRUE(Result.RetryCarrierActivityDrained);
        EXPECT_TRUE(Result.RetryAdmissionHandlerReturned);
        EXPECT_TRUE(Result.RetryCarrierDestroyed);
        EXPECT_TRUE(Result.RetryCatalogDrainReturned);
        EXPECT_EQ(Result.RetryCatalogDrainFailure.Code, Prism::Fault::Code::Blocked);
        EXPECT_FALSE(Result.RetryCatalogDrainFailure.Native);
        EXPECT_TRUE(Result.CatalogPhysicalRetiredAfterRetry);
        EXPECT_FALSE(Result.RetirementReceiptDropped);
        EXPECT_TRUE(Result.CarrierRetiredAfterRetry);
        EXPECT_TRUE(Result.CatalogReleasedAfterRetry);
        ASSERT_TRUE(Result.Stats); EXPECT_EQ(Result.Stats->Calls, 2);
        EXPECT_TRUE(Result.Stats->Destroyed); EXPECT_FALSE(Result.Stats->Open);
        EXPECT_FALSE(Result.Stats->WrongThread);
        EXPECT_TRUE(Result.WeakFailedCarrier.expired());
        EXPECT_TRUE(Result.WeakFailedCarrierActivity.expired());
        EXPECT_TRUE(Result.WeakGeneration.expired()); EXPECT_TRUE(Result.WeakContext.expired());
    }
}


