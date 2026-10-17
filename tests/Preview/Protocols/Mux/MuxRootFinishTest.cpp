/** @file MuxRootFinishTest.cpp @brief Mux child Finish 首因与真实 root 退休回归。 */
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <Preview/Account/Account.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>
#include <Preview/Protocols/Mux/Detail/Root/RootChild.hpp>
#include <Preview/Protocols/Mux/Detail/Root/RootSession.hpp>
#include <Preview/Protocols/Mux/RootBinding.hpp>
#include "MuxRootCloseTestSupport.hpp"
#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Contract/Ingress/StreamCatalog.hpp>
#include <Preview/Contract/Services/Authentication.hpp>
#include <Preview/Protocols/Mux/Smux/Smux.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>
#include <TestSupport/Fixtures/MuxRoot.hpp>
#include "MuxStreamAcceptInputTestSupport.hpp"
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
    namespace ParentTask = Preview::Testing::MuxStreamAcceptInputTestSupport;
    class UnusedEgress final : public Preview::Contract::StreamEgress
    {
    public:
        auto Connect(Preview::Network::Target)
            -> Net::awaitable<std::expected<Preview::SharedTransmission,
                Preview::Fault::Failure>> override
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::NotSupported});
        }
    };

    struct TrafficRecorder final : Preview::Foundation::TrafficSink
    {
        std::size_t Completed{0};
        std::size_t Up{0};
        std::size_t Down{0};

        auto Report(Preview::Foundation::TrafficEvent Event) noexcept -> void override
        {
            Up += Event.Up;
            Down += Event.Down;
            if (Event.Kind == Preview::Foundation::TrafficEventKind::Completed)
            {
                ++Completed;
            }
        }
        auto Retire(Preview::Foundation::TrafficRetirement Owner)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Preview::Fault::Failure>{}; }
    };

    struct FinishProbe final
    {
        std::size_t Calls{0};
        std::exception_ptr Failure;
        std::optional<Preview::Fault::Failure> TypedFailure;
    };

    class PhysicalRootEngine final : public Preview::Mux::Detail::RootEngineControl
    {
    public:
        explicit PhysicalRootEngine(Preview::SharedTransmission Inbound)
            : Inbound_(std::move(Inbound)) {}

        auto RequestClose() noexcept -> std::expected<void, Preview::Fault::Failure> override
        {
            if (!Inbound_)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            try
            {
                const auto Canceled = Inbound_->Cancel();
                const auto Closed = Inbound_->Close();
                if (!Canceled) return std::unexpected(Canceled.error());
                if (!Closed) return std::unexpected(Closed.error());
                return {};
            }
            catch (const boost::system::system_error &Error)
            {
                return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
            }
            catch (const std::system_error &Error)
            {
                return std::unexpected(Preview::Fault::FromNative(Error.code()));
            }
            catch (...)
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::IoError});
            }
        }

        auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            if (!Inbound_)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            const auto Activity = Inbound_->Activity();
            if (!Activity)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            Activity->Seal();
            const auto Result = co_await Activity->Drain();
            Retired_.store(Activity->IsRetired(), std::memory_order_release);
            co_return Result;
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return Retired_.load(std::memory_order_acquire); }

    private:
        Preview::SharedTransmission Inbound_;
        std::atomic_bool Retired_{false};
    };

    struct FinishFailureScenario final
    {
        std::shared_ptr<const Preview::Account::AccountBinding> Record;
        std::shared_ptr<Preview::Testing::ProviderAccounts> Directory;
        std::shared_ptr<Preview::Mux::RootBinding> Binding;
        std::shared_ptr<Preview::Mux::Detail::RootSession> RootSessionOwner;
        std::shared_ptr<Preview::Mux::Detail::RootState> Root;
        std::shared_ptr<PhysicalRootEngine> Engine;
        std::shared_ptr<Preview::Mux::Detail::ChildState> Child;
        std::shared_ptr<Preview::Contract::Ingress::StreamCatalog> StreamCatalogOwner;
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> ParentTasks;
        std::shared_ptr<Preview::MemoryStream> ChildPeer;
        Preview::Contract::Ingress::StreamIdentity StreamIdentity;
        std::weak_ptr<Preview::Mux::Detail::ChildState> RetainedChild;
        std::weak_ptr<Preview::Transmission> RetainedInbound, RootInbound;
        std::shared_ptr<TrafficRecorder> Traffic;
        std::shared_ptr<FinishProbe> Finish;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState{
            std::make_shared<Preview::Foundation::GenerationUseState>()};
        std::exception_ptr TaskFailure;
        std::exception_ptr ScenarioFailure;
        Preview::Fault::Failure TaskFault{};
        Preview::Fault::Failure RootDrainFailure{};
        Preview::Lifecycle::TaskStats StatsAtDrain{};
        std::size_t ConnectionsAtDrain{0};
        std::size_t StreamsAfterStart{0};
        std::size_t StreamsAtDrain{0};
        std::size_t StreamsAfterRootRetirement{0};
        std::size_t StreamsAfterRepeatedDrain{0};
        bool ParentTaskAliveAtChildDrain{false};
        Preview::Contract::Ingress::StreamCatalogStatus CatalogStatusAfterStart{
            Preview::Contract::Ingress::StreamCatalogStatus::CapabilityUnavailable};
        Preview::Contract::Ingress::StreamCatalogStatus CatalogStatusAfterDrain{
            Preview::Contract::Ingress::StreamCatalogStatus::CapabilityUnavailable};
        Preview::Contract::Ingress::StreamState CatalogStateAfterDrain{
            Preview::Contract::Ingress::StreamState::Active};
        Preview::Contract::Ingress::StreamCatalogStatus CatalogStatusAfterRootRetirement{
            Preview::Contract::Ingress::StreamCatalogStatus::CapabilityUnavailable};
        std::size_t ConnectionsAfterRelease{0};
        bool RootLeaseHeldAtDrain{false};
        bool RootLeaseReleasedAfterDrain{false};
        bool ReacquiredBeforeRootRetirement{false};
        std::size_t UsesAfterChildDrain{0};
        std::size_t UsesAfterRootRetirement{0};
        bool RootRetiredAfterDrain{false};
        bool EngineRetiredAfterDrain{false};
        bool ChildOwnerReleasedAfterDrain{false};
        bool ChildInboundReleasedAfterDrain{false};
        bool RootInboundReleasedAfterDrain{false};
        bool EngineOwnerReleasedAfterDrain{false};
        bool RootSessionOwnerReleasedAfterDrain{false};
        bool InvalidWireSent{false};
        std::size_t ObserverCalls{0};
        bool SetupFailed{false};
        bool Reacquired{false};
        std::optional<Preview::Fault::Failure> TypedFinishFailure;
        Preview::Fault::Failure ChildReportFailure;
    };

    auto ThrowMuxFinish(std::shared_ptr<FinishProbe> Probe)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        ++Probe->Calls;
        if (Probe->TypedFailure)
        {
            co_return std::unexpected(*Probe->TypedFailure);
        }
        Probe->Failure = std::make_exception_ptr(std::runtime_error("mux-finish"));
        std::rethrow_exception(Probe->Failure);
        co_return std::expected<void, Preview::Fault::Failure>{};
    }

    struct FinishOwner final
    {
        std::shared_ptr<FinishProbe> Probe;

        auto operator()() const
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            return ThrowMuxFinish(Probe);
        }
    };

    struct ThrowingObserver final
    {
        std::shared_ptr<FinishFailureScenario> State;

        auto operator()(Preview::Mux::ChildReport Report) const -> void
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
            const Preview::Lifecycle::TaskIdentity &,
            Preview::Fault::Failure Failure) const
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
        -> Net::awaitable<std::shared_ptr<Preview::MemoryStream>>
    {
        State->Directory = Preview::Testing::ProviderAccount(
            Preview::Account::Credential::Token("mux-finish"), Preview::AccountId{5001},
            {.MaxConnections = 1, .MaxStreams = 1});
        State->Record = State->Directory->Store->FindById(Preview::AccountId{5001});
        if (!State->Record)
        {
            State->SetupFailed = true;
            co_return std::shared_ptr<Preview::MemoryStream>{};
        }
        auto Acquired = State->Directory->Credentials.TryAcquire(
            {.Credential = Preview::Account::CredentialView::Token("mux-finish")});
        if (!Acquired)
        {
            State->SetupFailed = true;
            co_return std::shared_ptr<Preview::MemoryStream>{};
        }

        auto [RootRaw, RootPeerRaw] = Preview::MakeMemoryPair(Executor);
        auto RootInbound = std::make_shared<Preview::MemoryStream>(std::move(RootRaw));
        auto RootPeer = std::make_shared<Preview::MemoryStream>(std::move(RootPeerRaw));
        auto [ChildRaw, ChildPeer] = Preview::MakeMemoryPair(Executor);
        State->ChildPeer = std::make_shared<Preview::MemoryStream>(std::move(ChildPeer));
        State->Traffic = std::make_shared<TrafficRecorder>();
        State->Finish = std::make_shared<FinishProbe>();
        State->Finish->TypedFailure = State->TypedFinishFailure;
        Preview::Mux::RootOptions Options;
        Options.Wire = Preview::Mux::Mode::Smux;
        Options.Services.Egress = std::make_shared<UnusedEgress>();
        Options.Services.Traffic = State->Traffic;
        Options.Observe = ThrowingObserver{State};
        Options.GenerationUseState = State->UseState;
        State->Binding = std::make_shared<Preview::Mux::RootBinding>(std::move(Options));
        auto Reserved = co_await Preview::Contract::InboundAdmission::Prepare(RootInbound);
        if (!Reserved)
        {
            State->SetupFailed = true;
            co_return std::shared_ptr<Preview::MemoryStream>{};
        }
        auto Admission = std::move(*Reserved);
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Protocol = Preview::Contract::ProtocolType::Trojan;
        Plane.ProtocolAuthenticated = true;
        Plane.AccountLease = std::move(*Acquired);
        Plane.Root = Preview::Contract::MuxRootDataPlane{RootInbound, {}};
        auto CreateRequest = Preview::Contract::MuxRootCreateRequest::Prepare(
            Admission.RootCreateOwner(), State->UseState, std::move(Plane));
        if (!CreateRequest)
        {
            State->SetupFailed = true;
            if (Plane.HasTransport())
                (void)co_await Admission.Reject(std::move(Plane), CreateRequest.error());
            co_return std::shared_ptr<Preview::MemoryStream>{};
        }
        auto Created = State->Binding->Create(std::move(*CreateRequest));
        if (!Created)
        {
            State->SetupFailed = true;
            co_return std::shared_ptr<Preview::MemoryStream>{};
        }
        State->RootSessionOwner = std::static_pointer_cast<Preview::Mux::Detail::RootSession>(
            Created->Session);
        State->Root = Preview::Mux::Testing::RootSessionStateFixture::State(
            State->RootSessionOwner);
        State->RootInbound = State->Root->Inbound;
        State->StreamCatalogOwner = std::make_shared<Preview::Contract::Ingress::StreamCatalog>();
        EXPECT_TRUE(State->StreamCatalogOwner->Enable(State->Root->Options.MaxStreams));
        State->Root->StreamCatalogOwner = State->StreamCatalogOwner;
        State->Root->SelectedWire = Preview::Mux::Mode::Smux;
        State->Engine = std::make_shared<PhysicalRootEngine>(State->Root->Inbound);
        State->Root->EngineControl = State->Engine;
        const Preview::Lifecycle::TaskContext ParentContext{
            .SessionId = Preview::SessionId{501},
            .WorkerId = Preview::WorkerId{31},
            .Generation = Preview::GenerationId{9}};
        auto Parent = co_await ParentTask::CreateRootParentTask(
            State->Root->Executor, ParentContext,
            Preview::Lifecycle::TaskRegistry::FailureHandler{FailureCapture{State}});
        if (!Parent)
        {
            State->SetupFailed = true;
            co_return std::shared_ptr<Preview::MemoryStream>{};
        }
        State->ParentTasks = std::move(Parent->Registry);
        State->Root->Children = std::move(Parent->Children);
        State->Root->Lease = std::move(Created->Plane.AccountLease);
        State->Root->Admission = State->Root->Lease.Streams();
        State->Root->Metadata.TaskIdentity = Parent->Identity;
        State->Child = std::make_shared<Preview::Mux::Detail::ChildState>();
        State->Child->Inbound = std::make_shared<Preview::MemoryStream>(std::move(ChildRaw));
        State->Child->Identity.StreamId = Preview::StreamId{71};
        State->Child->Finish = FinishOwner{State->Finish};
        if (!Preview::Mux::Detail::StartChild(State->Root, State->Child))
        {
            State->SetupFailed = true;
            co_return std::shared_ptr<Preview::MemoryStream>{};
        }
        State->StreamsAfterStart = State->Record->Runtime()->ActiveStreams();
        State->StreamIdentity = {
            Preview::SessionId{501}, Preview::WorkerId{31}, Preview::GenerationId{9},
            Preview::StreamId{71}};
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
            {.Credential = Preview::Account::CredentialView::Token("mux-finish")});
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
        const std::shared_ptr<Preview::MemoryStream> &RootPeer) -> Net::awaitable<void>
    {
        auto RootOwner = State->RootSessionOwner;
        const std::weak_ptr<Preview::Mux::Detail::RootSession> WeakRootOwner = RootOwner;
        const std::weak_ptr<PhysicalRootEngine> WeakEngine = State->Engine;
        auto RootDrain = co_await RootOwner->Drain();
        State->EngineRetiredAfterDrain = State->Engine->IsRetired();
        State->RootRetiredAfterDrain = RootOwner->IsRetired();
        if (!RootDrain) State->RootDrainFailure = RootDrain.error();
        RootDrain = co_await RootOwner->Drain();
        State->StreamsAfterRepeatedDrain = State->Record->Runtime()->ActiveStreams();
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
            {.Credential = Preview::Account::CredentialView::Token("mux-finish")});
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
    std::optional<Preview::Fault::Failure> TypedFailure)
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
    Preview::Fault::Failure ExpectedFailure,
    const bool ExceptionFinish) -> void
{
    ASSERT_FALSE(State->ScenarioFailure); ASSERT_FALSE(State->SetupFailed);
    ASSERT_TRUE(State->InvalidWireSent); ASSERT_EQ(State->Finish->Calls, 1U);
    ASSERT_EQ(State->ObserverCalls, 1U);
    EXPECT_EQ(State->ChildReportFailure.Code, Preview::Fault::Code::NotSupported);
    if (ExceptionFinish)
    {
        EXPECT_EQ(ExceptionMessage(State->TaskFailure), "mux-finish");
        EXPECT_EQ(State->TaskFault.Code, Preview::Fault::Code::IoError);
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
        Preview::Contract::Ingress::StreamCatalogStatus::Found);
    EXPECT_EQ(State->CatalogStateAfterDrain,
        Preview::Contract::Ingress::StreamState::Draining);
    EXPECT_EQ(State->CatalogStatusAfterStart,
        Preview::Contract::Ingress::StreamCatalogStatus::Found);
    EXPECT_EQ(State->StreamsAfterRootRetirement, 0U);
    EXPECT_EQ(State->CatalogStatusAfterRootRetirement,
        Preview::Contract::Ingress::StreamCatalogStatus::NotFound);
    EXPECT_EQ(State->StreamsAfterRepeatedDrain, 0U);
    EXPECT_TRUE(State->EngineRetiredAfterDrain); EXPECT_TRUE(State->RootRetiredAfterDrain);
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
        Preview::Fault::Failure{Preview::Fault::Code::IoError}, true);
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const Preview::Fault::Failure FinishFailure{
        Preview::Fault::Code::ConnectionReset, Native};
    VerifyFinishFailureScenario(
        RunFinishFailureCase(FinishFailure), FinishFailure, false);
}

namespace
{
    auto RunPublishedRootCancellation(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto [PeerRaw, InboundRaw] = Preview::MakeMemoryPair(Executor);
        auto Peer = std::make_shared<Preview::MemoryStream>(std::move(PeerRaw));
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(InboundRaw));
        auto Root = std::make_shared<Preview::Mux::Detail::RootState>(
            Inbound, Preview::Mux::RootOptions{});
        Root->Started.store(true, std::memory_order_release);
        EXPECT_FALSE(Root->PublishRunOutcome());
        EXPECT_FALSE(Root->ResourcesRetired.load(std::memory_order_acquire));

        Root->RequestCancel();
        EXPECT_EQ(Root->ExitStatus.load(), Preview::Fault::Code::Success);
        EXPECT_FALSE(Root->TerminalFailure.Load().Failed());

        const auto Activity = Inbound->Activity();
        EXPECT_TRUE(Activity);
        (void)Inbound->Close();
        if (Activity)
        {
            const auto Drained = co_await Activity->Drain();
            EXPECT_TRUE(Drained);
        }
        Root->Inbound.reset();
        Root.reset();
        (void)Peer->Close();
    }
}

TEST(MuxRootOwner, RequestCancelAfterRunOutcomePreservesSuccessfulTerminalState)
{
    Net::io_context Io;
    std::exception_ptr Exception;
    Net::co_spawn(Io, RunPublishedRootCancellation(Io.get_executor()),
        [&Exception](std::exception_ptr Failure) { Exception = std::move(Failure); });
    Io.run();
    EXPECT_FALSE(Exception);
}

namespace
{
    auto RunCancellationBeforeOutcome(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto [PeerRaw, InboundRaw] = Preview::MakeMemoryPair(Executor);
        auto Peer = std::make_shared<Preview::MemoryStream>(std::move(PeerRaw));
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(InboundRaw));
        auto Root = std::make_shared<Preview::Mux::Detail::RootState>(
            Inbound, Preview::Mux::RootOptions{});

        Root->RequestCancel();
        EXPECT_EQ(Root->ExitStatus.load(), Preview::Fault::Code::Canceled);
        Root->Started.store(true, std::memory_order_release);
        Root->RequestCancel();
        EXPECT_EQ(Root->TerminalFailure.Load().Code, Preview::Fault::Code::Canceled);
        EXPECT_TRUE(Root->PublishRunOutcome());

        const auto Activity = Inbound->Activity();
        EXPECT_TRUE(Activity);
        if (!Activity) co_return;
        const auto Drained = co_await Activity->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_TRUE(Activity->IsRetired());
        Root->Inbound.reset();
        Root.reset();
        (void)Peer->Close();
    }
}

TEST(MuxRootOwner, RequestCancelBeforeRunOutcomeClaimsTerminalState)
{
    Net::io_context Io;
    std::exception_ptr Exception;
    Net::co_spawn(Io, RunCancellationBeforeOutcome(Io.get_executor()),
        [&Exception](std::exception_ptr Failure) { Exception = std::move(Failure); });
    Io.run();
    EXPECT_FALSE(Exception);
}

namespace
{
    auto RunRootCloseWithoutCancelFailure(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto [PeerRaw, InboundRaw] = Preview::MakeMemoryPair(Executor);
        auto Peer = std::make_shared<Preview::MemoryStream>(std::move(PeerRaw));
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(InboundRaw));
        auto State = std::make_shared<Preview::Mux::Detail::RootState>(
            Inbound, Preview::Mux::RootOptions{});
        State->Started.store(true, std::memory_order_release);
        auto Root = Preview::Mux::Testing::RootSessionStateFixture::CreateSession(State);

        Root->Close();
        const auto Activity = Root->Activity();
        const auto Drained = co_await Activity->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_EQ(State->ExitStatus.load(), Preview::Fault::Code::Success);
        EXPECT_FALSE(State->TerminalFailure.Load().Failed());
        EXPECT_TRUE(Root->IsRetired());
        (void)Peer->Close();
    }
}

TEST(MuxRootOwner, CloseDrainsWithoutPublishingCancellationFailure)
{
    Net::io_context Io;
    std::exception_ptr Exception;
    Net::co_spawn(Io, RunRootCloseWithoutCancelFailure(Io.get_executor()),
        [&Exception](std::exception_ptr Failure) { Exception = std::move(Failure); });
    Io.run();
    EXPECT_FALSE(Exception);
}
