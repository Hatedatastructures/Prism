/** @file RootFinishTest.cpp @brief Mux child Finish 首因与真实 root 退休回归。 */
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <Prism/Account/Account.hpp>
#include <Prism/Lifecycle/Task/Registry.hpp>
#include <Prism/Protocols/Mux/Root/Child.hpp>
#include <Prism/Protocols/Mux/Root/Session.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include "../../../Protocols/Mux/Mux/RootCloseTestSupport.hpp"
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Fixtures/MuxRoot.hpp>
#include "../../../Protocols/Mux/Mux/AcceptSupport.hpp"
#include <array>
#include <atomic>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>

namespace
{
    namespace Net = boost::asio;
    namespace ParentTask = Prism::Testing::MuxAcceptSupport;
    class UnusedEgress final : public Prism::Contract::StreamEgress
    {
    public:
        auto Connect(Prism::Network::Target)
            -> Net::awaitable<std::expected<Prism::SharedTransmission,
                Prism::Fault::Failure>> override
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        }
    };

    struct TrafficRecorder final : Prism::Foundation::TrafficSink
    {
        std::size_t Completed{0};
        std::size_t Up{0};
        std::size_t Down{0};

        auto Report(Prism::Foundation::TrafficEvent Event) noexcept -> void override
        {
            Up += Event.Up;
            Down += Event.Down;
            if (Event.Kind == Prism::Foundation::TrafficEventKind::Completed)
            {
                ++Completed;
            }
        }
        auto Retire(Prism::Foundation::TrafficRetirement Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Prism::Fault::Failure>{}; }
    };

    struct FinishProbe final
    {
        std::size_t Calls{0};
        std::exception_ptr Failure;
        std::optional<Prism::Fault::Failure> TypedFailure;
    };

    /** @brief 观测 root 关闭 owner 及其对底层传输执行的操作。 */
    struct PhysicalRootCloseObservation final
    {
        std::size_t RequestCloseCalls{0U};
        std::size_t CancelCalls{0U};
        std::size_t CloseCalls{0U};
        bool CancelSucceeded{false};
        bool CloseSucceeded{false};
        bool InboundOpenAfterDrain{true};
    };

    class PhysicalRootEngine final : public Prism::Mux::Detail::RootEngineControl
    {
    public:
        explicit PhysicalRootEngine(Prism::SharedTransmission Inbound)
            : Inbound_(std::move(Inbound)) {}

        auto RequestClose() noexcept -> std::expected<void, Prism::Fault::Failure> override
        {
            ++CloseObservation_.RequestCloseCalls;
            if (!Inbound_)
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            try
            {
                ++CloseObservation_.CancelCalls;
                const auto Canceled = Inbound_->Cancel();
                ++CloseObservation_.CloseCalls;
                const auto Closed = Inbound_->Close();
                CloseObservation_.CancelSucceeded = static_cast<bool>(Canceled);
                CloseObservation_.CloseSucceeded = static_cast<bool>(Closed);
                if (!Canceled) return std::unexpected(Canceled.error());
                if (!Closed) return std::unexpected(Closed.error());
                return {};
            }
            catch (const boost::system::system_error &Error)
            {
                return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
            }
            catch (const std::system_error &Error)
            {
                return std::unexpected(Prism::Fault::FromNative(Error.code()));
            }
            catch (...)
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
        }

        auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            if (!Inbound_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            const auto Activity = Inbound_->Activity();
            if (!Activity)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            Activity->Seal();
            const auto Result = co_await Activity->Drain();
            Retired_.store(Activity->IsRetired(), std::memory_order_release);
            co_return Result;
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return Retired_.load(std::memory_order_acquire); }

        [[nodiscard]] auto CloseObservation() const noexcept
            -> const PhysicalRootCloseObservation &
        {
            return CloseObservation_;
        }

        [[nodiscard]] auto InboundIsOpen() const noexcept -> bool
        {
            return Inbound_ && Inbound_->IsOpen();
        }

    private:
        Prism::SharedTransmission Inbound_;
        PhysicalRootCloseObservation CloseObservation_;
        std::atomic_bool Retired_{false};
    };

    struct FinishFailureScenario final
    {
        std::shared_ptr<const Prism::Account::AccountBinding> Record;
        std::shared_ptr<Prism::Testing::ProviderAccounts> Directory;
        std::shared_ptr<Prism::Mux::RootBinding> Binding;
        std::shared_ptr<Prism::Mux::Detail::RootSession> RootSessionOwner;
        std::shared_ptr<Prism::Mux::Detail::RootState> Root;
        std::shared_ptr<PhysicalRootEngine> Engine;
        std::shared_ptr<Prism::Mux::Detail::ChildState> Child;
        std::shared_ptr<Prism::Contract::Ingress::StreamCatalog> StreamCatalogOwner;
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> ParentTasks;
        std::shared_ptr<Prism::MemoryStream> ChildPeer;
        Prism::Contract::Ingress::StreamIdentity StreamIdentity;
        std::weak_ptr<Prism::Mux::Detail::ChildState> RetainedChild;
        std::weak_ptr<Prism::Transmission> RetainedInbound, RootInbound;
        std::shared_ptr<TrafficRecorder> Traffic;
        std::shared_ptr<FinishProbe> Finish;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState{
            std::make_shared<Prism::Foundation::GenerationUseState>()};
        std::exception_ptr TaskFailure;
        std::exception_ptr ScenarioFailure;
        Prism::Fault::Failure TaskFault{};
        Prism::Fault::Failure RootDrainFailure{};
        Prism::Lifecycle::TaskStats StatsAtDrain{};
        std::size_t ConnectionsAtDrain{0};
        std::size_t StreamsAfterStart{0};
        std::size_t StreamsAtDrain{0};
        std::size_t StreamsAfterRootRetirement{0};
        std::size_t StreamsAfterRepeatedDrain{0};
        bool ParentTaskAliveAtChildDrain{false};
        Prism::Contract::Ingress::StreamCatalogStatus CatalogStatusAfterStart{
            Prism::Contract::Ingress::StreamCatalogStatus::CapabilityUnavailable};
        Prism::Contract::Ingress::StreamCatalogStatus CatalogStatusAfterDrain{
            Prism::Contract::Ingress::StreamCatalogStatus::CapabilityUnavailable};
        Prism::Contract::Ingress::StreamState CatalogStateAfterDrain{
            Prism::Contract::Ingress::StreamState::Active};
        Prism::Contract::Ingress::StreamCatalogStatus CatalogStatusAfterRootRetirement{
            Prism::Contract::Ingress::StreamCatalogStatus::CapabilityUnavailable};
        std::size_t ConnectionsAfterRelease{0};
        bool RootLeaseHeldAtDrain{false};
        bool RootLeaseReleasedAfterDrain{false};
        bool ReacquiredBeforeRootRetirement{false};
        std::size_t UsesAfterChildDrain{0};
        std::size_t UsesAfterRootRetirement{0};
        bool RootRetiredAfterDrain{false};
        bool EngineRetiredAfterDrain{false};
        PhysicalRootCloseObservation RootCloseObservation;
        bool ChildOwnerReleasedAfterDrain{false};
        bool ChildInboundReleasedAfterDrain{false};
        bool RootInboundReleasedAfterDrain{false};
        bool EngineOwnerReleasedAfterDrain{false};
        bool RootSessionOwnerReleasedAfterDrain{false};
        bool InvalidWireSent{false};
        std::size_t ObserverCalls{0};
        bool SetupFailed{false};
        bool Reacquired{false};
        std::optional<Prism::Fault::Failure> TypedFinishFailure;
        Prism::Fault::Failure ChildReportFailure;
    };

    auto ThrowMuxFinish(std::shared_ptr<FinishProbe> Probe)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        ++Probe->Calls;
        if (Probe->TypedFailure)
        {
            co_return std::unexpected(*Probe->TypedFailure);
        }
        Probe->Failure = std::make_exception_ptr(std::runtime_error("mux-finish"));
        std::rethrow_exception(Probe->Failure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    struct FinishOwner final
    {
        std::shared_ptr<FinishProbe> Probe;

        auto operator()() const
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            return ThrowMuxFinish(Probe);
        }
    };

    struct ThrowingObserver final
    {
        std::shared_ptr<FinishFailureScenario> State;

        auto operator()(Prism::Mux::ChildReport Report) const -> void
        {
            ++State->ObserverCalls;
            State->ChildReportFailure = Report.Relay.Failure;
            throw std::runtime_error("observer-failure");
        }
    };

    struct FailureCapture final
    {
        std::weak_ptr<FinishFailureScenario> State;

        auto operator()(
            const Prism::Lifecycle::TaskIdentity &,
            Prism::Fault::Failure Failure) const
            -> void
        {
            if (const auto Owner = State.lock())
                Owner->TaskFault = Failure;
        }
    };

    auto SendInvalidChildWire(const std::shared_ptr<FinishFailureScenario> &State)
        -> Net::awaitable<void>
    {
        const std::array<std::byte, 3> InvalidWire{
            std::byte{0}, std::byte{0}, std::byte{0xFF}};
        const auto Result = co_await State->ChildPeer->WriteExact(InvalidWire);
        State->InvalidWireSent = Result.Failure.Succeeded() && Result.Bytes == InvalidWire.size();
    }

    auto PrepareFinishFailureScenario(
        const std::shared_ptr<FinishFailureScenario> &State,
        Net::any_io_executor Executor)
        -> Net::awaitable<std::shared_ptr<Prism::MemoryStream>>
    {
        State->Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Token("mux-finish"), Prism::AccountId{5001},
            {.MaxConnections = 1, .MaxStreams = 1});
        State->Record = State->Directory->Store->FindById(Prism::AccountId{5001});
        if (!State->Record)
        {
            State->SetupFailed = true;
            co_return std::shared_ptr<Prism::MemoryStream>{};
        }
        auto Acquired = State->Directory->Credentials.TryAcquire(
            {.Credential = Prism::Account::CredentialView::Token("mux-finish")});
        if (!Acquired)
        {
            State->SetupFailed = true;
            co_return std::shared_ptr<Prism::MemoryStream>{};
        }

        auto [RootRaw, RootPeerRaw] = Prism::MakeMemoryPair(Executor);
        auto RootInbound = std::make_shared<Prism::MemoryStream>(std::move(RootRaw));
        auto RootPeer = std::make_shared<Prism::MemoryStream>(std::move(RootPeerRaw));
        auto [ChildRaw, ChildPeer] = Prism::MakeMemoryPair(Executor);
        State->ChildPeer = std::make_shared<Prism::MemoryStream>(std::move(ChildPeer));
        State->Traffic = std::make_shared<TrafficRecorder>();
        State->Finish = std::make_shared<FinishProbe>();
        State->Finish->TypedFailure = State->TypedFinishFailure;
        Prism::Mux::RootOptions Options;
        Options.Wire = Prism::Mux::Mode::Smux;
        Options.Services.Egress = std::make_shared<UnusedEgress>();
        Options.Services.Traffic = State->Traffic;
        Options.Observe = ThrowingObserver{State};
        Options.GenerationUseState = State->UseState;
        State->Binding = std::make_shared<Prism::Mux::RootBinding>(std::move(Options));
        auto Reserved = co_await Prism::Contract::InboundAdmission::Prepare(RootInbound);
        if (!Reserved)
        {
            State->SetupFailed = true;
            co_return std::shared_ptr<Prism::MemoryStream>{};
        }
        auto Admission = std::move(*Reserved);
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Protocol = Prism::Contract::ProtocolType::Trojan;
        Plane.ProtocolAuthenticated = true;
        Plane.AccountLease = std::move(*Acquired);
        Plane.Root = Prism::Contract::MuxRootDataPlane{RootInbound, {}};
        auto CreateRequest = Prism::Contract::MuxRootCreateRequest::Prepare(
            Admission.RootCreateOwner(), State->UseState, std::move(Plane));
        if (!CreateRequest)
        {
            State->SetupFailed = true;
            if (Plane.HasTransport())
                (void)co_await Admission.Reject(std::move(Plane), CreateRequest.error());
            co_return std::shared_ptr<Prism::MemoryStream>{};
        }
        auto Created = State->Binding->Create(std::move(*CreateRequest));
        if (!Created)
        {
            State->SetupFailed = true;
            co_return std::shared_ptr<Prism::MemoryStream>{};
        }
        State->RootSessionOwner = std::static_pointer_cast<Prism::Mux::Detail::RootSession>(
            Created->Session);
        State->Root = Prism::Mux::Testing::RootSessionStateFixture::State(
            State->RootSessionOwner);
        State->RootInbound = State->Root->Inbound;
        State->StreamCatalogOwner = std::make_shared<Prism::Contract::Ingress::StreamCatalog>();
        EXPECT_TRUE(State->StreamCatalogOwner->Enable(State->Root->Options.MaxStreams));
        State->Root->StreamCatalogOwner = State->StreamCatalogOwner;
        State->Root->SelectedWire = Prism::Mux::Mode::Smux;
        State->Engine = std::make_shared<PhysicalRootEngine>(State->Root->Inbound);
        State->Root->EngineControl = State->Engine;
        const Prism::Lifecycle::TaskContext ParentContext{
            .SessionId = Prism::SessionId{501},
            .WorkerId = Prism::WorkerId{31},
            .Generation = Prism::GenerationId{9}};
        auto Parent = co_await ParentTask::CreateRootParentTask(
            State->Root->Executor, ParentContext,
            Prism::Lifecycle::TaskRegistry::FailureHandler{FailureCapture{State}});
        if (!Parent)
        {
            State->SetupFailed = true;
            co_return std::shared_ptr<Prism::MemoryStream>{};
        }
        State->ParentTasks = std::move(Parent->Registry);
        State->Root->Children = std::move(Parent->Children);
        State->Root->Lease = std::move(Created->Plane.AccountLease);
        State->Root->Admission = State->Root->Lease.Streams();
        State->Root->Metadata.TaskIdentity = Parent->Identity;
        State->Child = std::make_shared<Prism::Mux::Detail::ChildState>();
        State->Child->Inbound = std::make_shared<Prism::MemoryStream>(std::move(ChildRaw));
        State->Child->Identity.StreamId = Prism::StreamId{71};
        State->Child->Finish = FinishOwner{State->Finish};
        if (!Prism::Mux::Detail::StartChild(State->Root, State->Child))
        {
            State->SetupFailed = true;
            co_return std::shared_ptr<Prism::MemoryStream>{};
        }
        State->StreamsAfterStart = State->Record->Runtime()->ActiveStreams();
        State->StreamIdentity = {
            Prism::SessionId{501}, Prism::WorkerId{31}, Prism::GenerationId{9},
            Prism::StreamId{71}};
        State->CatalogStatusAfterStart =
            State->StreamCatalogOwner->Find(State->StreamIdentity).Status;
        co_return RootPeer;
    }

    auto DrainFailedChild(const std::shared_ptr<FinishFailureScenario> &State)
        -> Net::awaitable<bool>
    {
        State->Root->Children->Seal();
        co_await SendInvalidChildWire(State);
        EXPECT_TRUE(co_await State->Root->Children->Drain());
        State->TaskFailure = State->Finish->Failure;
        State->StatsAtDrain = State->Root->Children->Stats();
        State->ParentTaskAliveAtChildDrain =
            State->ParentTasks->Stats().Active == 1U;
        const auto Catalog = State->StreamCatalogOwner->Find(State->StreamIdentity);
        State->CatalogStatusAfterDrain = Catalog.Status;
        State->CatalogStateAfterDrain = Catalog.Value.State;
        State->ConnectionsAtDrain = State->Record->Runtime()->ActiveConnections();
        State->StreamsAtDrain = State->Record->Runtime()->ActiveStreams();
        State->RootLeaseHeldAtDrain = static_cast<bool>(State->Root->Lease);
        State->UsesAfterChildDrain = State->UseState->Outstanding();
        auto Reacquired = State->Directory->Credentials.TryAcquire(
            {.Credential = Prism::Account::CredentialView::Token("mux-finish")});
        State->ReacquiredBeforeRootRetirement = static_cast<bool>(Reacquired);
        if (Reacquired) Reacquired->Release();

        const auto Retained = State->Root->ChildRetirementSlots[0].Retained;
        if (!Retained || !Retained->Inbound)
        {
            ADD_FAILURE() << "failed child lost its reserved retirement owner";
            co_return false;
        }
        State->RetainedChild = Retained;
        State->RetainedInbound = Retained->Inbound;
        State->Child.reset();
        co_return true;
    }

    auto RetireFailedRoot(const std::shared_ptr<FinishFailureScenario> &State,
        const std::shared_ptr<Prism::MemoryStream> &RootPeer) -> Net::awaitable<void>
    {
        auto RootOwner = State->RootSessionOwner;
        const std::weak_ptr<Prism::Mux::Detail::RootSession> WeakRootOwner = RootOwner;
        const std::weak_ptr<PhysicalRootEngine> WeakEngine = State->Engine;
        auto RootDrain = co_await RootOwner->Drain();
        State->EngineRetiredAfterDrain = State->Engine->IsRetired();
        State->RootRetiredAfterDrain = RootOwner->IsRetired();
        if (!RootDrain) State->RootDrainFailure = RootDrain.error();
        RootDrain = co_await RootOwner->Drain();
        State->StreamsAfterRepeatedDrain = State->Record->Runtime()->ActiveStreams();
        State->RootCloseObservation = State->Engine->CloseObservation();
        State->RootCloseObservation.InboundOpenAfterDrain = State->Engine->InboundIsOpen();
        State->RootLeaseReleasedAfterDrain = !static_cast<bool>(State->Root->Lease);
        State->UsesAfterRootRetirement = State->UseState->Outstanding();
        State->ConnectionsAfterRelease = State->Record->Runtime()->ActiveConnections();
        State->RootSessionOwner.reset();
        RootOwner.reset();
        State->Engine.reset();
        State->Binding->Close();
        const auto BindingDrain = co_await State->Binding->Drain();
        if (!BindingDrain && !State->RootDrainFailure.Failed())
            State->RootDrainFailure = BindingDrain.error();
        State->RootSessionOwnerReleasedAfterDrain = WeakRootOwner.expired();
        State->EngineOwnerReleasedAfterDrain = WeakEngine.expired();
        State->ChildOwnerReleasedAfterDrain = State->RetainedChild.expired();
        State->ChildInboundReleasedAfterDrain = State->RetainedInbound.expired();
        State->RootInboundReleasedAfterDrain = State->RootInbound.expired();
        State->StreamsAfterRootRetirement = State->Record->Runtime()->ActiveStreams();
        State->CatalogStatusAfterRootRetirement =
            State->StreamCatalogOwner->Find(State->StreamIdentity).Status;
        auto Reacquired = State->Directory->Credentials.TryAcquire(
            {.Credential = Prism::Account::CredentialView::Token("mux-finish")});
        State->Reacquired = static_cast<bool>(Reacquired);
        if (Reacquired) Reacquired->Release();
        (void)State->ChildPeer->Close();
        (void)RootPeer->Close();
    }

    auto RunFinishFailureScenario(const std::shared_ptr<FinishFailureScenario> &State)
        -> Net::awaitable<void>
    {
        auto RootPeer = co_await PrepareFinishFailureScenario(
            State, co_await Net::this_coro::executor);
        if (State->SetupFailed && State->ParentTasks)
            EXPECT_TRUE(co_await ParentTask::DrainRootParentTask(State->ParentTasks));
        if (State->SetupFailed) co_return;
        if (!co_await DrainFailedChild(State)) co_return;
        co_await RetireFailedRoot(State, RootPeer);
        EXPECT_TRUE(co_await ParentTask::DrainRootParentTask(State->ParentTasks));
        EXPECT_EQ(State->ParentTasks->Stats().Active, 0U);
        State->Root.reset();
        State->ParentTasks.reset();
        State->Binding.reset();
        State->StreamCatalogOwner.reset();
        State->ChildPeer.reset();
    }

    auto ExceptionMessage(const std::exception_ptr &Failure) -> std::string
    {
        if (!Failure)
        {
            return {};
        }
        try
        {
            std::rethrow_exception(Failure);
        }
        catch (const std::exception &Error)
        {
            return Error.what();
        }
        catch (...)
        {
            return {};
        }
    }
}

auto RunFinishFailureCase(
    std::optional<Prism::Fault::Failure> TypedFailure)
    -> std::shared_ptr<FinishFailureScenario>
{
    auto State = std::make_shared<FinishFailureScenario>();
    State->TypedFinishFailure = std::move(TypedFailure);
    Net::io_context Io;
    Net::co_spawn(Io, RunFinishFailureScenario(State),
        [State](std::exception_ptr Failure)
        { State->ScenarioFailure = std::move(Failure); });
    Io.run();
    return State;
}

auto VerifyFinishFailureScenario(
    const std::shared_ptr<FinishFailureScenario> &State,
    Prism::Fault::Failure ExpectedFailure,
    const bool ExceptionFinish) -> void
{
    ASSERT_FALSE(State->ScenarioFailure); ASSERT_FALSE(State->SetupFailed);
    ASSERT_TRUE(State->InvalidWireSent); ASSERT_EQ(State->Finish->Calls, 1U);
    ASSERT_EQ(State->ObserverCalls, 1U);
    EXPECT_EQ(State->ChildReportFailure.Code, Prism::Fault::Code::NotSupported);
    if (ExceptionFinish)
    {
        EXPECT_EQ(ExceptionMessage(State->TaskFailure), "mux-finish");
        EXPECT_EQ(State->TaskFault.Code, Prism::Fault::Code::IoError);
    }
    else EXPECT_FALSE(State->TaskFailure);
    EXPECT_EQ(State->Traffic->Completed, 1U); EXPECT_EQ(State->Traffic->Up, 0U);
    EXPECT_EQ(State->Traffic->Down, 0U); EXPECT_EQ(State->StatsAtDrain.Active, 0U);
    EXPECT_EQ(State->StatsAtDrain.Failed, ExceptionFinish ? 1U : 0U);
    EXPECT_EQ(State->StatsAtDrain.Completed, 1U);
    EXPECT_TRUE(State->ParentTaskAliveAtChildDrain);
    EXPECT_TRUE(State->RootLeaseHeldAtDrain); EXPECT_EQ(State->UsesAfterChildDrain, 1U);
    EXPECT_FALSE(State->ReacquiredBeforeRootRetirement);
    EXPECT_EQ(State->ConnectionsAtDrain, 1U); EXPECT_EQ(State->StreamsAfterStart, 1U);
    EXPECT_EQ(State->StreamsAtDrain, 1U);
    EXPECT_EQ(State->CatalogStatusAfterDrain,
        Prism::Contract::Ingress::StreamCatalogStatus::Found);
    EXPECT_EQ(State->CatalogStateAfterDrain,
        Prism::Contract::Ingress::StreamState::Draining);
    EXPECT_EQ(State->CatalogStatusAfterStart,
        Prism::Contract::Ingress::StreamCatalogStatus::Found);
    EXPECT_EQ(State->StreamsAfterRootRetirement, 0U);
    EXPECT_EQ(State->CatalogStatusAfterRootRetirement,
        Prism::Contract::Ingress::StreamCatalogStatus::NotFound);
    EXPECT_EQ(State->StreamsAfterRepeatedDrain, 0U);
    EXPECT_TRUE(State->EngineRetiredAfterDrain); EXPECT_TRUE(State->RootRetiredAfterDrain);
    EXPECT_EQ(State->RootCloseObservation.RequestCloseCalls, 1U);
    EXPECT_EQ(State->RootCloseObservation.CancelCalls, 1U);
    EXPECT_EQ(State->RootCloseObservation.CloseCalls, 1U);
    EXPECT_TRUE(State->RootCloseObservation.CancelSucceeded);
    EXPECT_TRUE(State->RootCloseObservation.CloseSucceeded);
    EXPECT_FALSE(State->RootCloseObservation.InboundOpenAfterDrain);
    EXPECT_TRUE(State->ChildOwnerReleasedAfterDrain);
    EXPECT_TRUE(State->ChildInboundReleasedAfterDrain);
    EXPECT_TRUE(State->RootInboundReleasedAfterDrain);
    EXPECT_TRUE(State->EngineOwnerReleasedAfterDrain);
    EXPECT_TRUE(State->RootSessionOwnerReleasedAfterDrain);
    EXPECT_TRUE(State->RootLeaseReleasedAfterDrain);
    EXPECT_EQ(State->UsesAfterRootRetirement, 0U);
    EXPECT_EQ(State->ConnectionsAfterRelease, 0U); EXPECT_TRUE(State->Reacquired);
    EXPECT_TRUE(State->UseState->CloseAdmissionIfUnused());
    EXPECT_EQ(State->RootDrainFailure.Code, ExpectedFailure.Code);
    EXPECT_EQ(State->RootDrainFailure.Native, ExpectedFailure.Native);
    EXPECT_EQ(State->Record->Runtime()->ActiveConnections(), 0U);
}
TEST(MuxRootOwner, RunChildFinishFailureCompletesTrafficAndReleasesChildLease)
{
    VerifyFinishFailureScenario(
        RunFinishFailureCase(std::nullopt),
        Prism::Fault::Failure{Prism::Fault::Code::IoError}, true);
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const Prism::Fault::Failure FinishFailure{
        Prism::Fault::Code::ConnectionReset, Native};
    VerifyFinishFailureScenario(
        RunFinishFailureCase(FinishFailure), FinishFailure, false);
}
