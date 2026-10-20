/** @file MuxServiceTest.cpp @brief 正式协议 owner 的真实 wire、子流与冷 binding 生命周期。 */
#include <TestSupport/Fixtures/MuxRoot.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <Prism/Protocols/Mux/SingMux/SingMux.hpp>
#include <Prism/Protocols/Mux/Detail/Root/RootChild.hpp>
#include <Prism/Protocols/Mux/Detail/Root/RootSession.hpp>
#include <Prism/Protocols/Mux/Detail/Root/RootState.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <exception>
#include <atomic>
#include <barrier>
#include <optional>
#include <system_error>
#include <thread>
namespace
{
    namespace F=Prism::Testing::MuxRoot;
    namespace Net=boost::asio;
    using Mode=Prism::Mux::Mode;
    using Smux=Prism::Mux::Smux::Client<>;
    using Yamux=Prism::Mux::Yamux::Client<>;
    using ControlCallSignal = Net::experimental::channel<void(boost::system::error_code)>;

    class PartialEnvelopeFailure : public Prism::Transmission
    {
    public:
        PartialEnvelopeFailure(Net::any_io_executor Executor, Prism::Fault::Failure Failure)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)), Failure_(Failure) {}
        auto Executor() const -> ExecutorType override { return Executor_; }
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (Reads_++ == 0)
            {
                Buffer.front() = std::byte{0};
                Prism::Transmission::PostResult(
                    Executor_, std::move(Handler), Prism::IoResult{1U, {}});
                return;
            }
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{0U, Failure_});
        }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{Buffer.size(), {}});
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{});
        }
        auto OnClose() -> ControlResult override { return {}; }
        auto OnCancel() -> ControlResult override { return {}; }
        std::size_t Reads_{0};
    private:
        Net::any_io_executor Executor_;
        Prism::Fault::Failure Failure_;
    };

    struct FakePhysicalResource final
    {
        auto Close() noexcept -> bool
        {
            bool Open = true;
            return Closed.compare_exchange_strong(Open, true, std::memory_order_acq_rel);
        }
        std::atomic_bool Closed{false};
    };

    class ChildControlFailure final : public PartialEnvelopeFailure
    {
    public:
        ChildControlFailure(Net::any_io_executor Executor, Prism::Fault::Failure Failure)
            : PartialEnvelopeFailure(Executor, Failure), ControlFailure_(Failure),
              ControlCalls_(std::make_shared<ControlCallSignal>(Executor, 2U)),
              Physical_(std::make_shared<FakePhysicalResource>()) {}
        auto OnClose() -> Prism::Transmission::ControlResult override
        {
            ++CloseCalls_;
            (void)ControlCalls_->try_send(boost::system::error_code{});
            return std::unexpected(ControlFailure_);
        }
        auto OnCancel() -> Prism::Transmission::ControlResult override
        {
            ++CancelCalls_;
            (void)ControlCalls_->try_send(boost::system::error_code{});
            return std::unexpected(ControlFailure_);
        }
        [[nodiscard]] auto RequiresExternalCloseReceipt() const noexcept -> bool override
        { return true; }
        [[nodiscard]] auto ControlCalls() const noexcept
            -> std::shared_ptr<ControlCallSignal> { return ControlCalls_; }
        [[nodiscard]] auto CloseReceiptOwner() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierCloseReceipt> { return CloseReceipt(); }
        auto CloseExternalResource() noexcept -> bool
        {
            if (!Physical_->Close()) return false;
            CloseReceipt()->ConfirmExternalClose();
            return true;
        }
        Prism::Fault::Failure ControlFailure_;
        std::size_t CloseCalls_{0}, CancelCalls_{0};
    private:
        std::shared_ptr<ControlCallSignal> ControlCalls_;
        std::shared_ptr<FakePhysicalResource> Physical_;
    };

    struct ChildControlScenario final
    {
        std::shared_ptr<ChildControlFailure> Transport;
        std::shared_ptr<Prism::Mux::Detail::ChildState> Child;
        Prism::Fault::Failure DrainFailure;
        bool RetiredBeforePhysicalClose{false};
        bool ControlDispatchBarrierPassed{false};
        bool PhysicalCloseConfirmed{false};
        bool RetiredAfterPhysicalClose{false};
    };

    auto RunChildControlFailure(std::shared_ptr<ChildControlScenario> State)
        -> Net::awaitable<void>
    {
        const auto Calls = State->Transport->ControlCalls();
        State->Child->Cancel();
        co_await Calls->async_receive(Net::use_awaitable);
        co_await Calls->async_receive(Net::use_awaitable);
        // 让当前 executor callback 退栈后再投递物理关闭回执。
        co_await Net::post(Net::use_awaitable);
        State->ControlDispatchBarrierPassed = true;
        State->RetiredBeforePhysicalClose = State->Transport->Activity()->IsRetired();
        State->PhysicalCloseConfirmed = State->Transport->CloseExternalResource();
        const auto Drained = co_await State->Transport->CloseReceiptOwner()->Drain();
        if (!Drained) State->DrainFailure = Drained.error();
        State->RetiredAfterPhysicalClose = State->Transport->Activity()->IsRetired();
    }

    class RetryableCarrierActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        explicit RetryableCarrierActivity(std::shared_ptr<Prism::Contract::CarrierActivity> Inner)
            : Inner_(std::move(Inner)) {}
        auto Seal() noexcept -> void override { Inner_->Seal(); }
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        { return Inner_->Executor(); }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return Retired_.load(std::memory_order_acquire) && Inner_->IsRetired(); }
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            const auto Inner = co_await Inner_->Drain();
            if (!Inner) co_return std::unexpected(Inner.error());
            if (Attempts_.fetch_add(1U) == 0U)
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            Retired_.store(true, std::memory_order_release);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        std::atomic_size_t Attempts_{0};
    private:
        std::shared_ptr<Prism::Contract::CarrierActivity> Inner_;
        std::atomic_bool Retired_{false};
    };

    class RetryablePartialEnvelopeFailure final : public PartialEnvelopeFailure
    {
    public:
        RetryablePartialEnvelopeFailure(Net::any_io_executor Executor,
            Prism::Fault::Failure Failure)
            : PartialEnvelopeFailure(Executor, Failure),
              Activity_(std::make_shared<RetryableCarrierActivity>(
                  Prism::Transmission::Activity())) {}
        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        { return Activity_; }
        std::shared_ptr<RetryableCarrierActivity> Activity_;
    };

    template<class Client>
    auto One(std::shared_ptr<F::State> S,Mode Wire) -> Net::awaitable<void>
    {
        const auto P=co_await F::Start(S);const auto C=co_await F::Connect<Client>(P,Wire);
        auto Stream=co_await F::RoundTrip(S,C);EXPECT_TRUE(Stream); if(!Stream) co_return;
        EXPECT_EQ(S->Record->Runtime()->ActiveStreams(),1U);Stream->Close();
        EXPECT_TRUE(co_await F::Wait(S->Reported));co_await F::Close(C);EXPECT_TRUE(co_await F::Wait(P->Done));
        EXPECT_EQ(S->Dials,1U);EXPECT_EQ(S->Reports.size(),1U); if(S->Reports.empty()) co_return;
        EXPECT_EQ(S->Reports[0].Relay.Total[0],F::Literal.size());EXPECT_EQ(S->Reports[0].Relay.Total[1],F::Literal.size());
        co_await F::Finish(S);
    }
    auto RunOccupiedParentTaskIdentity(std::shared_ptr<F::State> S) -> Net::awaitable<void>;
    auto RunCancelOneRoot(std::shared_ptr<F::State> S) -> Net::awaitable<void>;
    auto RunRetirementBudgetCase(Net::any_io_executor Executor) -> Net::awaitable<void>
    {
        auto [RootClientRaw, RootInboundRaw] = Prism::MakeMemoryPair(Executor);
        auto RootClient = std::make_shared<Prism::MemoryStream>(std::move(RootClientRaw));
        auto RootInbound = std::make_shared<Prism::MemoryStream>(std::move(RootInboundRaw));
        Prism::Mux::RootOptions Options{.Wire = Mode::Smux, .MaxStreams = 1U};
        auto Root = std::make_shared<Prism::Mux::Detail::RootState>(RootInbound, std::move(Options));
        auto Retained = std::make_shared<Prism::Mux::Detail::ChildState>();
        Retained->Root = Root;
        Retained->RetirementSlot = Root->ReserveChildRetirementSlot();
        EXPECT_TRUE(Retained->RetirementSlot);
        if (!Retained->RetirementSlot) co_return;
        const auto RetainedSlot = *Retained->RetirementSlot;
        const std::weak_ptr<Prism::Mux::Detail::ChildState> WeakRetained = Retained;
        Root->RetainChildUntilRootRetired(std::move(Retained));

        auto [ChildClientRaw, ChildInboundRaw] = Prism::MakeMemoryPair(Executor);
        auto ChildClient = std::make_shared<Prism::MemoryStream>(std::move(ChildClientRaw));
        auto Child = std::make_shared<Prism::Mux::Detail::ChildState>();
        Child->Inbound = std::make_shared<Prism::MemoryStream>(std::move(ChildInboundRaw));
        bool Rejected = false;
        Child->Reject = [&Rejected] { Rejected = true; };
        const auto Started = Prism::Mux::Detail::StartChild(Root, Child);
        EXPECT_TRUE(Started);
        if (!Started) co_return;
        EXPECT_FALSE(Child->Admitted);
        EXPECT_FALSE(Child->RetirementSlot);
        EXPECT_FALSE(Root->ReserveChildRetirementSlot());

        const auto Children = co_await Root->Children->Drain();
        EXPECT_TRUE(Children);
        EXPECT_TRUE(Rejected);
        EXPECT_EQ(Root->Children->Stats().Active, 0U);
        Root->RequestCancel();
        Root->Loops->Seal();
        EXPECT_TRUE(co_await Root->Loops->Drain());
        EXPECT_TRUE(co_await Root->Lifetime.Drain());
        const auto Engine = co_await Prism::Mux::Detail::DrainRootEngine(Root);
        const auto Carrier = co_await Prism::Mux::Detail::DrainRootCarrier(Root, Engine.H2Retired);
        EXPECT_TRUE(Carrier.Retired);
        Root->ReleaseChildRetirementSlot(RetainedSlot);
        EXPECT_TRUE(Root->ReleaseResources());
        EXPECT_TRUE(Root->ResourcesRetired.load());
        EXPECT_TRUE(WeakRetained.expired());
        (void)RootClient->Close();
        (void)ChildClient->Close();
    }
    auto RunCreatedRoot(
        std::shared_ptr<Prism::Mux::RootBinding> Binding,
        Prism::SharedTransmission Inbound,
        std::shared_ptr<Prism::Foundation::GenerationUseState> RequestUseState)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        auto Created = co_await F::CreateRoot(std::move(Binding), std::move(Inbound));
        if (!Created) co_return std::unexpected(Created.error());
        auto Session = std::move(Created->Session);
        auto Plane = std::move(Created->Plane);
        if (auto *Mux = Plane.Mux()) Mux->Session.reset();
        Prism::Contract::MuxRootRequest Request{
            .GenerationUseState = std::move(RequestUseState)};
        co_return co_await Session->Run(std::move(Request));
    }
    TEST(MuxService, SmuxAcceptsAndOwnsOneChildStream)
    { F::Scenario(Mode::Smux,[](auto S)->Net::awaitable<void>{co_await One<Smux>(S,Mode::Smux);}); }
    TEST(MuxService, YamuxAcceptsAndOwnsOneChildStream)
    { F::Scenario(Mode::Yamux,[](auto S)->Net::awaitable<void>{co_await One<Yamux>(S,Mode::Yamux);}); }
    TEST(MuxService, AcceptsSingMuxProtocolEnvelope)
    { F::Scenario(Mode::Auto,[](auto S)->Net::awaitable<void>{co_await One<Yamux>(S,Mode::Yamux);}); }
    TEST(MuxService, RootSessionRetainsNativeEnvelopeFailureAfterPartialPrefix)
    {
        Net::io_context Io;
        const auto Native = std::make_error_code(std::errc::connection_reset);
        auto Raw = std::make_shared<PartialEnvelopeFailure>(
            Io.get_executor(), Prism::Fault::FromNative(Native));
        using ResultType = std::expected<void, Prism::Fault::Failure>;
        std::optional<ResultType> Result;
        std::exception_ptr Exception;
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        auto Fixture = std::make_shared<F::State>(Io.get_executor());
        auto Binding = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{
            .Services = {.Egress = std::make_shared<F::Egress>(Fixture)},
            .GenerationUseState = UseState});
        Net::co_spawn(Io, RunCreatedRoot(Binding, Raw, UseState),
            [&](std::exception_ptr Error, ResultType Value)
            {
                Exception = Error;
                Result = std::move(Value);
            });
        Io.run();
        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Result.has_value());
        ASSERT_FALSE(*Result);
        EXPECT_EQ(Result->error().Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result->error().Native, Native);
        EXPECT_EQ(Raw->Reads_, 2U);
        EXPECT_EQ(UseState->Outstanding(), 0U);
    }
    TEST(MuxService, ChildControlRetainsNativeFailureAndStillAttemptsClose)
    {
        Net::io_context Io;
        const auto Native = std::make_error_code(std::errc::connection_reset);
        auto Transport = std::make_shared<ChildControlFailure>(
            Io.get_executor(), Prism::Fault::FromNative(Native));
        auto Child = std::make_shared<Prism::Mux::Detail::ChildState>();
        Child->Inbound = Transport;
        Child->ControlFailure = std::make_shared<Prism::Fault::FailureState>();
        Child->Reset = [Native]() -> std::expected<void, Prism::Fault::Failure>
        { return std::unexpected(Prism::Fault::FromNative(Native)); };
        auto State = std::make_shared<ChildControlScenario>();
        State->Transport = Transport;
        State->Child = Child;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunChildControlFailure(State),
            [&](std::exception_ptr Failure) { Exception = std::move(Failure); });
        Io.run();
        ASSERT_FALSE(Exception);
        const auto Failure = Child->ControlFailure->Load();
        EXPECT_EQ(Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Failure.Native, Native);
        EXPECT_EQ(Transport->CancelCalls_, 1U);
        EXPECT_EQ(Transport->CloseCalls_, 1U);
        EXPECT_TRUE(State->ControlDispatchBarrierPassed);
        EXPECT_FALSE(State->RetiredBeforePhysicalClose);
        EXPECT_TRUE(State->PhysicalCloseConfirmed);
        EXPECT_EQ(State->DrainFailure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(State->DrainFailure.Native, Native);
        EXPECT_TRUE(State->RetiredAfterPhysicalClose);
    }
    TEST(MuxService, ChildRetirementCapacityRejectsBeforeAdmission)
    {
        Net::io_context Io;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunRetirementBudgetCase(Io.get_executor()),
            [&](std::exception_ptr Failure) { Exception = std::move(Failure); });
        Io.run();
        EXPECT_FALSE(Exception);
    }
    TEST(MuxService, RootRejectsDifferentGenerationStateBeforeReadingWire)
    {
        Net::io_context Io;
        auto OptionState = std::make_shared<Prism::Foundation::GenerationUseState>();
        auto RequestState = std::make_shared<Prism::Foundation::GenerationUseState>();
        auto Raw = std::make_shared<PartialEnvelopeFailure>(
            Io.get_executor(), Prism::Fault::Failure{Prism::Fault::Code::IoError});
        auto Fixture = std::make_shared<F::State>(Io.get_executor());
        auto Binding = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{
            .Services = {.Egress = std::make_shared<F::Egress>(Fixture)},
            .GenerationUseState = OptionState});
        using ResultType = std::expected<void, Prism::Fault::Failure>;
        std::optional<ResultType> Result;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunCreatedRoot(Binding, Raw, RequestState),
            [&](std::exception_ptr Failure, ResultType Value)
            { Exception = std::move(Failure); Result = std::move(Value); });
        Io.run();
        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Result);
        ASSERT_FALSE(*Result);
        EXPECT_EQ(Result->error().Code, Prism::Fault::Code::InvalidArgument);
        EXPECT_EQ(Raw->Reads_, 0U);
        EXPECT_EQ(OptionState->Outstanding(), 0U);
        EXPECT_EQ(RequestState->Outstanding(), 0U);
    }
    TEST(MuxService, RootRejectsClosedGenerationWithoutStartingProtocol)
    {
        Net::io_context Io;
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        ASSERT_TRUE(UseState->CloseAdmissionIfUnused());
        auto Raw = std::make_shared<PartialEnvelopeFailure>(
            Io.get_executor(), Prism::Fault::Failure{Prism::Fault::Code::IoError});
        auto Fixture = std::make_shared<F::State>(Io.get_executor());
        auto Binding = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{
            .Services = {.Egress = std::make_shared<F::Egress>(Fixture)},
            .GenerationUseState = UseState});
        using ResultType = std::expected<void, Prism::Fault::Failure>;
        std::optional<ResultType> Result;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunCreatedRoot(Binding, Raw, UseState),
            [&](std::exception_ptr Failure, ResultType Value)
            { Exception = std::move(Failure); Result = std::move(Value); });
        Io.run();
        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Result);
        ASSERT_FALSE(*Result);
        EXPECT_EQ(Result->error().Code, Prism::Fault::Code::ResourceUnavailable);
        EXPECT_EQ(Raw->Reads_, 0U);
        EXPECT_EQ(UseState->Outstanding(), 0U);
    }
    struct PhysicalDrainRetryResult final
    {
        Prism::Fault::Failure CreateFailure;
        Prism::Fault::Failure RunFailure;
        Prism::Fault::Failure DrainFailure;
        std::size_t FirstAttempt{0};
        std::size_t FinalAttempts{0};
        std::size_t UsesAfterRun{0};
        std::size_t UsesAfterDrain{0};
        bool HeldAfterRun{false};
        bool RetiredAfterDrain{false};
        bool WeakRootAliveAfterRun{false};
        bool WeakRootExpiredAfterDrain{false};
        bool ClosedAdmissionAfterDrain{false};
    };

    auto RunPhysicalDrainRetry(Net::any_io_executor Executor)
        -> Net::awaitable<PhysicalDrainRetryResult>
    {
        PhysicalDrainRetryResult Result;
        auto Fixture = std::make_shared<F::State>(Executor);
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        auto Binding = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{
            .Services = {.Egress = std::make_shared<F::Egress>(Fixture)},
            .GenerationUseState = UseState});
        const auto Native = std::make_error_code(std::errc::connection_reset);
        auto Raw = std::make_shared<RetryablePartialEnvelopeFailure>(
            Executor, Prism::Fault::FromNative(Native));
        auto Created = co_await F::CreateRoot(Binding, Raw);
        if (!Created)
        {
            Result.CreateFailure = Created.error();
            co_return Result;
        }
        auto Root = std::move(Created->Session);
        const std::weak_ptr<Prism::Mux::Detail::RootSession> WeakRoot =
            std::static_pointer_cast<Prism::Mux::Detail::RootSession>(Root);
        auto Plane = std::move(Created->Plane);
        if (auto *Mux = Plane.Mux()) Mux->Session.reset();
        Prism::Contract::MuxRootRequest Request{.GenerationUseState = UseState};
        const auto RunResult = co_await Root->Run(std::move(Request));
        if (RunResult) co_return Result;
        Result.RunFailure = RunResult.error();
        Result.UsesAfterRun = UseState->Outstanding();
        Result.FirstAttempt = Raw->Activity_->Attempts_.load();
        Result.HeldAfterRun = !Binding->IsRetired();
        Root.reset();
        Result.WeakRootAliveAfterRun = !WeakRoot.expired();

        Binding->Close();
        const auto DrainResult = co_await Binding->Drain();
        if (!DrainResult) Result.DrainFailure = DrainResult.error();
        Result.FinalAttempts = Raw->Activity_->Attempts_.load();
        Result.UsesAfterDrain = UseState->Outstanding();
        Result.RetiredAfterDrain = Binding->IsRetired();
        Result.WeakRootExpiredAfterDrain = WeakRoot.expired();
        Result.ClosedAdmissionAfterDrain = UseState->CloseAdmissionIfUnused();
        co_return Result;
    }

    TEST(MuxService, FailedPhysicalDrainRetainsRootGenerationForSameOwnerRetry)
    {
        Net::io_context Io;
        std::optional<PhysicalDrainRetryResult> Result;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunPhysicalDrainRetry(Io.get_executor()),
            [&](std::exception_ptr Failure, PhysicalDrainRetryResult Value)
            {
                Exception = std::move(Failure);
                Result = std::move(Value);
            });
        Io.run();
        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Result);
        EXPECT_FALSE(Result->CreateFailure.Failed());
        EXPECT_EQ(Result->RunFailure.Native,
            std::make_error_code(std::errc::connection_reset));
        EXPECT_EQ(Result->DrainFailure.Native,
            std::make_error_code(std::errc::connection_reset));
        EXPECT_EQ(Result->UsesAfterRun, 1U);
        EXPECT_EQ(Result->FirstAttempt, 1U);
        EXPECT_TRUE(Result->HeldAfterRun);
        EXPECT_TRUE(Result->WeakRootAliveAfterRun);
        EXPECT_EQ(Result->UsesAfterDrain, 0U);
        EXPECT_EQ(Result->FinalAttempts, 2U);
        EXPECT_TRUE(Result->RetiredAfterDrain);
        EXPECT_TRUE(Result->WeakRootExpiredAfterDrain);
        EXPECT_TRUE(Result->ClosedAdmissionAfterDrain);
    }
    TEST(MuxService, FactoryRejectsWireDifferentFromColdBinding)
    {
        F::Scenario(Mode::Yamux,[](auto S)->Net::awaitable<void>
        {
            const auto P=co_await F::Start(S);const auto C=co_await F::Connect<Smux>(P,Mode::Smux);
            EXPECT_TRUE(co_await F::Wait(P->Done));
            EXPECT_FALSE(P->Status);
            if (!P->Status) EXPECT_EQ(P->Status.error().Code,F::Code::NotSupported);
            EXPECT_EQ(S->Dials,0U);EXPECT_TRUE(S->Reports.empty());co_await F::Close(C);co_await F::Finish(S);
        });
    }
    TEST(MuxService, RejectsMissingStreamHandler)
    {
        Net::io_context Io;
        auto [ClientRaw, ServerRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto Raw = std::make_shared<Prism::MemoryStream>(std::move(ServerRaw));
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        auto Binding = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{
            .Wire = Mode::Smux, .GenerationUseState = UseState});
        using CreateResult = std::expected<Prism::Mux::RootCreateResult,
            Prism::Fault::Failure>;
        std::optional<CreateResult> Created;
        std::exception_ptr Exception;
        Net::co_spawn(Io, F::CreateRoot(Binding, Raw),
            [&](std::exception_ptr Failure, CreateResult Value)
            {
                Exception = std::move(Failure);
                Created = std::move(Value);
            });
        Io.run();
        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Created);
        ASSERT_FALSE(*Created);
        EXPECT_EQ(Created->error().Code, Prism::Fault::Code::Canceled);
        EXPECT_TRUE(Raw->Activity()->IsRetired());
        EXPECT_EQ(UseState->Outstanding(), 0U);

        Binding->Close();
        std::optional<std::expected<void, Prism::Fault::Failure>> Drained;
        Net::co_spawn(Io, Binding->Drain(),
            [&](std::exception_ptr Failure,
                std::expected<void, Prism::Fault::Failure> Value)
            {
                Exception = std::move(Failure);
                Drained = std::move(Value);
            });
        Io.restart();
        Io.run();
        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Drained);
        EXPECT_TRUE(*Drained);
        EXPECT_TRUE(Binding->IsRetired());
        EXPECT_TRUE(UseState->CloseAdmissionIfUnused());
        (void)ClientRaw.Close();
    }
    struct UnstartedRootResult final
    {
        Prism::Fault::Failure CreateFailure;
        Prism::Fault::Failure DrainFailure;
        std::size_t UsesAfterDrain{0};
        bool HeldBeforeDrain{false};
        bool RetiredAfterDrain{false};
        bool RootExpiredAfterDrain{false};
        bool ClosedAdmissionAfterDrain{false};
    };

    struct SingleCreateResult final
    {
        bool Prepared{false}, Created{false}, DuplicateRejected{false};
        bool DrainSucceeded{false}, RetiredAfterDrain{false}, RootExpiredAfterDrain{false};
        std::size_t UsesAfterCreate{0}, UsesAfterDuplicate{0}, UsesAfterDrain{0};
    };

    auto RunSingleCreate(Net::any_io_executor Executor) -> Net::awaitable<SingleCreateResult>
    {
        SingleCreateResult Result;
        auto Fixture = std::make_shared<F::State>(Executor);
        auto UseState = Fixture->UseState;
        auto [ClientRaw, ServerRaw] = Prism::MakeMemoryPair(Executor);
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(ServerRaw));
        auto Prepared = co_await F::PrepareCreate(Inbound, UseState);
        if (!Prepared) co_return Result;
        if (!Prepared->Request) co_return Result;
        Result.Prepared = true;
        Prism::Mux::RootOptions Options{.Wire = Mode::Smux,
            .Services = {.Egress = std::make_shared<F::Egress>(Fixture)}, .GenerationUseState = UseState};
        auto Created = Prism::Mux::Detail::RootSession::Create(*Prepared->Request, Options);
        if (!Created) co_return Result;
        Result.Created = true;
        auto Root = std::move(*Created);
        const std::weak_ptr<Prism::Mux::Detail::RootSession> WeakRoot = Root;
        Result.UsesAfterCreate = UseState->Outstanding();
        auto Duplicate = Prism::Mux::Detail::RootSession::Create(*Prepared->Request, Options);
        Result.DuplicateRejected = !Duplicate && Duplicate.error().Code == Prism::Fault::Code::InvalidArgument;
        Result.UsesAfterDuplicate = UseState->Outstanding();
        auto Plane = Prepared->Request->TakePlane();
        Prepared->Request->Transfer();
        Root->Close();
        const auto Drain = co_await Root->Drain();
        Result.DrainSucceeded = static_cast<bool>(Drain);
        Result.RetiredAfterDrain = Root->IsRetired();
        Result.UsesAfterDrain = UseState->Outstanding();
        Root.reset(); if (auto *Mux = Plane.Mux()) Mux->Session.reset();
        Plane = {}; Inbound.reset();
        Result.RootExpiredAfterDrain = WeakRoot.expired();
        (void)ClientRaw.Close();
        co_return Result;
    }

    auto RunUnstartedRootLifecycle(Net::any_io_executor Executor)
        -> Net::awaitable<UnstartedRootResult>
    {
        UnstartedRootResult Result;
        auto Fixture = std::make_shared<F::State>(Executor);
        auto Binding = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{
            .Wire = Mode::Smux,
            .Services = {.Egress = std::make_shared<F::Egress>(Fixture)},
            .GenerationUseState = Fixture->UseState});
        auto [ClientRaw, ServerRaw] = Prism::MakeMemoryPair(Executor);
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(ServerRaw));
        auto Created = co_await F::CreateRoot(Binding, Inbound);
        if (!Created)
        {
            Result.CreateFailure = Created.error();
            co_return Result;
        }
        auto Root = std::move(Created->Session);
        const std::weak_ptr<Prism::Mux::Detail::RootSession> WeakRoot =
            std::static_pointer_cast<Prism::Mux::Detail::RootSession>(Root);
        auto Plane = std::move(Created->Plane);
        if (auto *Mux = Plane.Mux()) Mux->Session.reset();
        Root.reset();
        Result.HeldBeforeDrain = !WeakRoot.expired() && !Binding->IsRetired();
        Binding->Close();
        const auto Drained = co_await Binding->Drain();
        if (!Drained) Result.DrainFailure = Drained.error();
        Result.RetiredAfterDrain = Binding->IsRetired();
        Result.RootExpiredAfterDrain = WeakRoot.expired();
        Result.UsesAfterDrain = Fixture->UseState->Outstanding();
        Result.ClosedAdmissionAfterDrain = Fixture->UseState->CloseAdmissionIfUnused();
        (void)ClientRaw.Close();
        co_return Result;
    }

    TEST(MuxService, UnstartedRootStaysOwnedUntilCarrierActivityDrains)
    {
        Net::io_context Io;
        std::optional<UnstartedRootResult> Result;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunUnstartedRootLifecycle(Io.get_executor()),
            [&](std::exception_ptr Failure, UnstartedRootResult Value)
            {
                Exception = std::move(Failure);
                Result = std::move(Value);
            });
        Io.run();
        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Result);
        EXPECT_FALSE(Result->CreateFailure.Failed());
        EXPECT_FALSE(Result->DrainFailure.Failed());
        EXPECT_TRUE(Result->HeldBeforeDrain);
        EXPECT_TRUE(Result->RetiredAfterDrain);
        EXPECT_TRUE(Result->RootExpiredAfterDrain);
        EXPECT_EQ(Result->UsesAfterDrain, 0U);
        EXPECT_TRUE(Result->ClosedAdmissionAfterDrain);
    }
    TEST(MuxService, RootCreateRequestCannotReplaceItsSessionOrLease)
    {
        Net::io_context Io;
        std::optional<SingleCreateResult> Result; std::exception_ptr Exception;
        Net::co_spawn(Io, RunSingleCreate(Io.get_executor()), [&](std::exception_ptr Failure,
            SingleCreateResult Value) { Exception = std::move(Failure); Result = std::move(Value); });
        Io.run();
        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Result);
        EXPECT_TRUE(Result->Prepared); EXPECT_TRUE(Result->Created);
        EXPECT_TRUE(Result->DuplicateRejected); EXPECT_TRUE(Result->DrainSucceeded);
        EXPECT_EQ(Result->UsesAfterCreate, 1U); EXPECT_EQ(Result->UsesAfterDuplicate, 1U);
        EXPECT_TRUE(Result->RetiredAfterDrain); EXPECT_EQ(Result->UsesAfterDrain, 0U);
        EXPECT_TRUE(Result->RootExpiredAfterDrain);
    }
    TEST(MuxService, ConcurrentRegisterAndCloseRetainEveryAdmissionUntilRetired)
    {
        F::ConcurrentRegistryScenario Scenario;
        F::PrepareConcurrentRegistryRoots(Scenario);
        ASSERT_FALSE(Scenario.PrepareFailureA);
        ASSERT_FALSE(Scenario.PrepareFailureB);
        ASSERT_TRUE(Scenario.PreparedA);
        ASSERT_TRUE(*Scenario.PreparedA);
        ASSERT_TRUE(Scenario.PreparedB);
        ASSERT_TRUE(*Scenario.PreparedB);
        ASSERT_FALSE(Scenario.PrepareFailureAnchor);
        ASSERT_TRUE(Scenario.PreparedAnchor);
        ASSERT_TRUE(*Scenario.PreparedAnchor);
        ASSERT_TRUE(Scenario.AnchorCreated && *Scenario.AnchorCreated);

        F::RegisterConcurrentRootsAndClose(Scenario);
        ASSERT_FALSE(Scenario.CreateFailureA);
        ASSERT_FALSE(Scenario.CreateFailureB);
        ASSERT_TRUE(Scenario.CreatedA);
        ASSERT_TRUE(Scenario.CreatedB);
        EXPECT_TRUE(Scenario.NotRetiredAtSeal);
        if (!*Scenario.CreatedA)
            EXPECT_EQ(Scenario.CreatedA->error().Code, Prism::Fault::Code::Canceled);
        if (!*Scenario.CreatedB)
            EXPECT_EQ(Scenario.CreatedB->error().Code, Prism::Fault::Code::Canceled);

        F::DrainConcurrentRoots(Scenario);
        ASSERT_FALSE(Scenario.DrainException);
        ASSERT_TRUE(Scenario.Drained);
        EXPECT_TRUE(Scenario.Binding->IsRetired());
        EXPECT_TRUE(Scenario.InboundA->Activity()->IsRetired());
        EXPECT_TRUE(Scenario.InboundB->Activity()->IsRetired());
        EXPECT_EQ(Scenario.UseState->Outstanding(), 0U);
        EXPECT_TRUE(Scenario.UseState->CloseAdmissionIfUnused());
        if (Scenario.RegisteredA) EXPECT_TRUE(Scenario.WeakA.expired());
        if (Scenario.RegisteredB) EXPECT_TRUE(Scenario.WeakB.expired());
        EXPECT_TRUE(Scenario.WeakAnchor.expired());
        (void)Scenario.ClientA->Close();
        (void)Scenario.ClientB->Close();
        (void)Scenario.AnchorClient->Close();
    }
    TEST(MuxService, SmuxStartsWithOccupiedParentTaskIdentity)
    {
        F::Scenario(Mode::Smux,RunOccupiedParentTaskIdentity);
    }
    TEST(MuxService, CancelingOneRootDoesNotStopSiblingStreams)
    {
        F::Scenario(Mode::Smux,RunCancelOneRoot);
    }
    TEST(MuxService, RejectedStreamStartClosesRootSession)
    {
        F::Scenario(Mode::Smux,[](auto S)->Net::awaitable<void>
        {
            const auto P=co_await F::Start(S);const auto C=co_await F::Connect<Smux>(P,Mode::Smux);
            S->Binding->Close();EXPECT_TRUE(co_await F::Wait(P->Done));
            EXPECT_FALSE(P->Status);
            if (!P->Status) EXPECT_EQ(P->Status.error().Code,F::Code::Canceled);
            EXPECT_FALSE(P->Server->IsOpen());EXPECT_EQ(S->Dials,0U);EXPECT_TRUE(S->Reports.empty());
            const auto Rejected = co_await F::CreateRoot(S->Binding, P->Server);
            EXPECT_FALSE(Rejected);co_await F::Close(C);co_await F::Finish(S);
        });
    }
    auto Stop(std::shared_ptr<F::State> S,bool IdleSibling) -> Net::awaitable<void>
    {
        const auto A=co_await F::Start(S);const auto CA=co_await F::Connect<Smux>(A,Mode::Smux);
        auto Stream=co_await F::RoundTrip(S,CA);std::shared_ptr<F::Peer> B;std::shared_ptr<Smux> CB;
        if(IdleSibling){B=co_await F::Start(S);CB=co_await F::Connect<Smux>(B,Mode::Smux);EXPECT_FALSE(B->Returned);}
        EXPECT_FALSE(A->Returned);EXPECT_EQ(S->Dials,1U);S->Binding->Close();S->Binding->Close();
        const auto Drain = co_await S->Binding->Drain();
        EXPECT_FALSE(Drain);
        if (!Drain) EXPECT_EQ(Drain.error().Code, F::Code::Canceled);
        EXPECT_TRUE(S->Binding->IsRetired());
        EXPECT_TRUE(A->Returned);EXPECT_FALSE(A->Status);
        if (!A->Status) EXPECT_EQ(A->Status.error().Code,F::Code::Canceled);
        if(B)
        {
            EXPECT_TRUE(B->Returned);EXPECT_FALSE(B->Status);
            if (!B->Status) EXPECT_EQ(B->Status.error().Code,F::Code::Canceled);
        }
        EXPECT_EQ(S->Reports.size(),1U);EXPECT_TRUE(A->WeakRoot.expired());if(B)EXPECT_TRUE(B->WeakRoot.expired());
        co_await F::Close(CA);if(CB)co_await F::Close(CB);co_await F::Finish(S);
    }

    auto RunOccupiedParentTaskIdentity(std::shared_ptr<F::State> S) -> Net::awaitable<void>
    {
        auto Scope=std::make_shared<Prism::Lifecycle::TaskRegistry>(S->Executor);
        auto Released=std::make_shared<F::Signal>(S->Executor,1);
        Prism::Lifecycle::TaskRequest Request{.Context={.SessionId=Prism::SessionId{941},
            .WorkerId=Prism::WorkerId{23},.Generation=Prism::GenerationId{7}},.StartOnSubmit=true};
        Request.Cancel=[Released]{(void)Released->try_send(boost::system::error_code{});};
        const auto Blocker=[Released]()->Net::awaitable<void>{co_await Released->async_receive(Net::use_awaitable);};
        const auto Task=Scope->SpawnTracked(std::move(Request),Blocker());EXPECT_TRUE(Task);
        Prism::Contract::RequestMetadata Metadata;Metadata.TaskIdentity=Task->Identity();
        const auto P=co_await F::Start(S,Metadata);const auto C=co_await F::Connect<Smux>(P,Mode::Smux);
        auto Stream=co_await F::RoundTrip(S,C);Stream->Close();EXPECT_TRUE(co_await F::Wait(S->Reported));
        EXPECT_EQ(S->Reports.size(),1U); if(S->Reports.empty()) co_return;const auto Actual=S->Reports[0].Identity;
        EXPECT_EQ(Actual.SessionId,Metadata.TaskIdentity.SessionId);EXPECT_EQ(Actual.WorkerId,Metadata.TaskIdentity.WorkerId);
        EXPECT_EQ(Actual.Generation,Metadata.TaskIdentity.Generation);EXPECT_NE(Actual.TaskId,Metadata.TaskIdentity.TaskId);
        EXPECT_TRUE(Actual.TaskId);EXPECT_TRUE(Actual.StreamId);
        co_await F::Close(C);EXPECT_TRUE(co_await F::Wait(P->Done));(void)Scope->Cancel();EXPECT_TRUE(co_await Scope->Drain());
        EXPECT_EQ(Scope->Stats().Active,0U);EXPECT_FALSE(Scope->IsDrainBlocked());co_await F::Finish(S);
    }

    auto RunCancelOneRoot(std::shared_ptr<F::State> S) -> Net::awaitable<void>
    {
        const auto A=co_await F::Start(S),B=co_await F::Start(S);
        const auto CA=co_await F::Connect<Smux>(A,Mode::Smux),CB=co_await F::Connect<Smux>(B,Mode::Smux);
        auto First=co_await F::RoundTrip(S,CA);auto Other=co_await F::RoundTrip(S,CB);
        A->Root->Cancel();EXPECT_TRUE(co_await F::Wait(A->Done));EXPECT_TRUE(A->WeakRoot.expired());
        EXPECT_FALSE(A->Status);
        if (!A->Status) EXPECT_EQ(A->Status.error().Code,F::Code::Canceled);
        auto Extra=co_await F::RoundTrip(S,CB);auto Last=co_await F::RoundTrip(S,CB);
        EXPECT_TRUE(Extra);EXPECT_TRUE(Last);EXPECT_FALSE(B->Returned);
        co_await F::Close(CA);co_await F::Close(CB);EXPECT_TRUE(co_await F::Wait(B->Done));
        EXPECT_TRUE(B->Status);EXPECT_EQ(S->Dials,4U);EXPECT_EQ(S->Reports.size(),4U);co_await F::Finish(S);
    }
    auto RunConcurrentDrainWaiters(std::shared_ptr<F::State> S) -> Net::awaitable<void>
    {
        const auto Peer=co_await F::Start(S);
        const auto Client=co_await F::Connect<Smux>(Peer,Mode::Smux);
        auto Stream=co_await F::RoundTrip(S,Client);
        EXPECT_TRUE(Stream);EXPECT_FALSE(Peer->Returned);
        S->Binding->Close();
        using Net::experimental::awaitable_operators::operator&&;
        const auto [First,Second]=co_await (S->Binding->Drain()&&S->Binding->Drain());
        EXPECT_FALSE(First);EXPECT_FALSE(Second);EXPECT_TRUE(S->Binding->IsRetired());
        if (!First) EXPECT_EQ(First.error().Code, F::Code::Canceled);
        if (!Second) EXPECT_EQ(Second.error().Code, F::Code::Canceled);
        EXPECT_TRUE(co_await F::Wait(Peer->Done));
        EXPECT_FALSE(Peer->Status);
        if (!Peer->Status) EXPECT_EQ(Peer->Status.error().Code,F::Code::Canceled);
        EXPECT_TRUE(Peer->WeakRoot.expired());
        co_await F::Close(Client);co_await F::Finish(S);
    }
    TEST(MuxService, StopWakesIdleRootsAndDrainsChildren)
    { F::Scenario(Mode::Smux,[](auto S)->Net::awaitable<void>{co_await Stop(S,true);}); }
    TEST(MuxService, StopOwnsControlForNoControlRun)
    { F::Scenario(Mode::Smux,[](auto S)->Net::awaitable<void>{co_await Stop(S,false);}); }
    TEST(MuxService, ConcurrentDrainWaitersPinOneRootUntilRunReturns)
    { F::Scenario(Mode::Smux,RunConcurrentDrainWaiters); }
}
