/** @file RootSession.hpp @brief generic sing-mux 的正式 MuxSession 与 root lease drain。 */
#pragma once
#include <Preview/Protocols/Mux/Detail/Root/RootRetirement.hpp>
#include <Preview/Protocols/Mux/Detail/Root/RootRunFailure.hpp>
#include <Preview/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Lifecycle/DrainReservation.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/system_error.hpp>
#include <atomic>
#include <exception>
#include <system_error>
#include <type_traits>
#include <Preview/Protocols/Mux/Smux/Smux.hpp>
#include <Preview/Protocols/Mux/Yamux/Yamux.hpp>
#include <Preview/Protocols/Mux/H2Mux/Http2Server.hpp>
#include <Preview/Protocols/Mux/Detail/SingMux/Handshake.hpp>

namespace Preview::Mux::Testing
{
    class RootSessionStateFixture;
}

namespace Preview::Mux::Detail
{
    class RootSession final : public Preview::Contract::MuxSession
    {
        friend class RootRegistry;
        friend class Testing::RootSessionStateFixture;
        class RootActivity final : public Preview::Contract::CarrierActivity
        {
        public:
            explicit RootActivity(std::shared_ptr<RootState> Value) : State_(std::move(Value)) {}

            /** @brief 一次封止根准入及现有 child/frame scope，不关闭 inbound。 */
            auto Seal() noexcept -> void override
            {
                State_->Lifetime.Seal();
                State_->Children->Seal();
            }

            [[nodiscard]] auto Executor() const -> Net::any_io_executor override
            { return State_->Executor; }

            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            { return State_->ResourcesRetired.load(std::memory_order_acquire); }

            /** @brief 等待唯一 Run owner 完成 child、frame 和 writer 的真实退栈。 */
            [[nodiscard]] auto Drain()
                -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
            {
                Seal();
                State_->Stop();
                co_await Net::dispatch(State_->Executor, Net::use_awaitable);
                const auto Run = co_await State_->Lifetime.Drain();
                if (!Run) State_->RecordTerminalFailure(Run.error());
                const auto Resources = co_await DrainResources(State_);
                if (State_->ResourcesRetired.load(std::memory_order_acquire))
                {
                    const auto Failure = State_->TerminalFailure.Load();
                    if (Failure.Failed() && Failure.Code != Preview::Fault::Code::Canceled)
                        co_return std::unexpected(Failure);
                    co_return std::expected<void, Preview::Fault::Failure>{};
                }
                if (!Resources) co_return std::unexpected(Resources.error());
                if (!Run) co_return std::unexpected(Run.error());
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }

        private:
            std::shared_ptr<RootState> State_;
        };

        /** @brief 强持有具体 Server；只请求关闭，实际完成由根作用域排空回执提供。 */
        template<class Server>
        class EngineCloseOwner final : public RootEngineControl
        {
        public:
            EngineCloseOwner(std::shared_ptr<Server> Value, std::weak_ptr<RootState> Root)
                : Server_(std::move(Value)), Root_(std::move(Root)) {}
            auto RequestClose() noexcept
                -> std::expected<void, Preview::Fault::Failure> override
            {
                try
                {
                    Server_->Close();
                    return std::expected<void, Preview::Fault::Failure>{};
                }
                catch (...)
                {
                    return std::unexpected(
                        RootState::FailureFromException(std::current_exception()));
                }
            }
            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            {
                if constexpr (std::is_same_v<Server, H2Mux::Http2Server>)
                {
                    return Server_ && Server_->IsRetired();
                }
                return Retired_.load(std::memory_order_acquire);
            }
            [[nodiscard]] auto Drain()
                -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
            {
                if constexpr (std::is_same_v<Server, H2Mux::Http2Server>)
                {
                    const auto Drained = co_await Server_->Drain();
                    const auto Retired = Server_->IsRetired();
                    Retired_.store(Retired, std::memory_order_release);
                    if (!Drained) co_return std::unexpected(Drained.error());
                    if (!Retired)
                    {
                        co_return std::unexpected(
                            Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                    }
                    co_return std::expected<void, Preview::Fault::Failure>{};
                }
                else if constexpr (requires(Server &Value) { Value.Session(); })
                {
                    const auto Root = Root_.lock();
                    if (!Root)
                    {
                        co_return std::unexpected(
                            Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                    }
                    const auto Receipt = co_await DrainMuxServerTasks(Root, Server_);
                    Retired_.store(Receipt.Retired, std::memory_order_release);
                    if (Receipt.Failure.Failed())
                        co_return std::unexpected(Receipt.Failure);
                    co_return std::expected<void, Preview::Fault::Failure>{};
                }
                else
                {
                    static_assert(std::is_same_v<Server, H2Mux::Http2Server>,
                        "mux engine owner requires an explicit physical retirement contract");
                }
            }
        private:
            std::shared_ptr<Server> Server_;
            std::weak_ptr<RootState> Root_;
            std::atomic_bool Retired_{false};
        };

    public:
        /** @brief 只从已预预约的唯一 create request 构造正式 root session。 */
        [[nodiscard]] static auto Create(
            Preview::Contract::MuxRootCreateRequest &Request,
            const RootOptions &Options)
            -> std::expected<std::shared_ptr<RootSession>, Preview::Fault::Failure>
        {
            if (!Request.BeginSessionCreation())
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            const auto Inbound = Request.Inbound();
            if (!Inbound || !Request.GenerationUseState() ||
                Request.GenerationUseState() != Options.GenerationUseState)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            auto RegistrationNode = std::make_shared<RootRegistryNode>();
            auto State = std::make_shared<RootState>(Inbound, Options);
            auto Root = std::shared_ptr<RootSession>(
                new RootSession(std::move(State), std::move(RegistrationNode)));
            Request.AttachSession(Root);
            Root->State_->ParentStreamLease = Request.TakeParentStreamLease();
            Root->State_->GenerationLease = Request.TakeGenerationUseLease();
            Root->CreateCommitted_ = true;
            return Root;
        }
        ~RootSession() override
        {
            if (CreateCommitted_) Close();
        }
        auto SetRetirementOwner(const std::shared_ptr<RootRetirementOwner> &Owner) noexcept -> void
        { State_->RetirementOwner = Owner; }
        [[nodiscard]] auto HistoricalFailure() const noexcept -> Preview::Fault::Failure
        { return State_->TerminalFailure.Load(); }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return State_->ResourcesRetired.load(std::memory_order_acquire); }
        /** @brief 正式 Run 一次消费根 lease；始终完成两个 scope 的真实 drain 后才决定结果。 */
        auto Run(Preview::Contract::MuxRootRequest Request)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            const auto State = State_;
            if (State->Started.exchange(true))
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            if (!State->Lifetime.Enter())
            {
                State->Stop();
                if (State->Stopping.load(std::memory_order_acquire) &&
                    State->Phase.load(std::memory_order_acquire) !=
                        RootState::RunPhase::CancellationRequested)
                {
                    co_return std::expected<void, Preview::Fault::Failure>{};
                }
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            Preview::Lifecycle::DrainReservation Lifetime(State->Lifetime);
            State->Lease = std::move(Request.Lease);
            if (State->Lease)
            {
                State->Admission = State->Lease.Streams();
            }
            else
            {
                State->Admission = State->Options.Admission;
            }
            State->Metadata = std::move(Request.Metadata);
            State->StreamCatalogOwner = std::move(Request.StreamCatalogOwner);

            std::expected<void, Preview::Fault::Failure> Result;
            std::exception_ptr Fatal;
            if (!Request.GenerationUseState ||
                Request.GenerationUseState != State->Options.GenerationUseState)
            {
                Result = std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
                State->RecordTerminalFailure(Result.error());
            }
            else if (!State->GenerationLease)
            {
                Result = std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
                State->RecordTerminalFailure(Result.error());
            }
            if (Result)
            {
                try
                {
                    Result = co_await Net::co_spawn(State->Executor, Serve(State), Net::use_awaitable);
                }
                catch (const boost::system::system_error &Error)
                {
                    const auto Native = static_cast<std::error_code>(Error.code());
                    Result = std::unexpected(Preview::Fault::FromNative(Native));
                    if (Error.code() != Net::error::operation_aborted)
                    {
                        Fatal = std::current_exception();
                    }
                }
                catch (const std::system_error &Error)
                {
                    Result = std::unexpected(Preview::Fault::FromNative(Error.code()));
                    Fatal = std::current_exception();
                }
                catch (...)
                {
                    Result = std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::IoError});
                    Fatal = std::current_exception();
                }
            }
            const bool ClosedDuringRun = IsExpectedRootRunCancellation(State, Result);
            if (ClosedDuringRun) Result = {};
            else if (!Result) State->RecordTerminalFailure(Result.error());
            if (State->PublishRunOutcome())
            {
                State->ExitStatus.store(Preview::Fault::Code::Canceled);
                State->RecordTerminalFailure(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }

            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            State->Stop();
            const auto Drained = co_await DrainResources(State);
            if (!Drained)
            {
                State->RecordTerminalFailure(Drained.error());
                if (Result) Result = std::unexpected(Drained.error());
            }
            if (Fatal)
            {
                const auto Context = Preview::Executor::ContextOwner::Find(State->Executor);
                if (Context && Context->Fatal) Context->Fatal->Publish(Fatal);
                State->RecordTerminalFailure(RootState::FailureFromException(Fatal));
                if (Result) Result = std::unexpected(RootState::FailureFromException(Fatal));
            }
            if (State->ExitStatus.load() == Preview::Fault::Code::Canceled && Result)
            {
                State->RecordTerminalFailure(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            const auto TerminalFailure = State->TerminalFailure.Load();
            if (TerminalFailure.Failed()) Result = std::unexpected(TerminalFailure);
            Lifetime.Transfer();
            State->Lifetime.Leave();
            co_return co_await FinalizeRootRunResources(State, std::move(Result));
        }
        /** @brief 暴露已有 child/frame/lifetime tree 的唯一协议活动 owner。 */
        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        { return Activity_; }
        /** @brief 显式取消根并发布取消结果。 */
        auto Cancel() noexcept -> void override { Activity_->Seal(); State_->RequestCancel(); }
        /** @brief 正常停止根并取消子活动，不把停止本身记为取消结果。 */
        auto Close() noexcept -> void override { Activity_->Seal(); State_->Stop(); }
        /** @brief 冷绑定关闭后等本根已开始的正式 Run 真实完成，未开始的已关闭根不产生异步任务。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        { co_return co_await Activity_->Drain(); }
    private:
        /** @brief 供唯一静态 Create 分配正式执行 owner。 */
        explicit RootSession(
            std::shared_ptr<RootState> State,
            std::shared_ptr<RootRegistryNode> RegistrationNode)
            : State_(std::move(State)), Activity_(std::make_shared<RootActivity>(State_)),
              RegistrationNode_(std::move(RegistrationNode)) {}

        template<class Server>
        static auto ServeEngine(std::shared_ptr<RootState> State)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            auto Engine = std::make_shared<Server>();
            SessionOptions Options;
            Options.Registry = State->Loops;
            Options.Identity = State->Metadata.TaskIdentity;
            Options.MaxStreams = State->Options.MaxStreams;
            if (!Engine->Accept(State->Inbound, Options))
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::IoError});
            }
            if (State->StreamCatalogOwner &&
                !State->StreamCatalogOwner->Enable(State->Options.MaxStreams))
            {
                State->StreamCatalogOwner->Disable();
            }
            if (!State->EngineControl)
                State->EngineControl = std::make_shared<EngineCloseOwner<Server>>(Engine, State);
            while (!State->Stopping.load())
            {
                const auto Stream = co_await Engine->AcceptStream();
                if (!Stream) break;
                const auto Typed = std::static_pointer_cast<StreamTransmission>(Stream);
                auto Child = std::make_shared<ChildState>();
                Child->Inbound = Stream;
                Child->Identity.StreamId = Preview::StreamId{Typed->Handle()->Id()};
                const auto Weak = std::weak_ptr<StreamTransmission>(Typed);
                Child->Reject = [Weak] { if (const auto Owner = Weak.lock()) Owner->Reset(); };
                Child->Reset = [Weak]() -> std::expected<void, Preview::Fault::Failure>
                {
                    if (const auto Owner = Weak.lock())
                    {
                        Owner->Reset();
                        return {};
                    }
                    return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                };
                Child->Finish = [Typed] { return Typed->DrainTerminations(); };
                if (!StartChild(State, std::move(Child)))
                {
                    co_return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::Canceled});
                }
            }
            State->Stop();
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        static auto RunHttp2(
            std::shared_ptr<RootState> State,
            std::shared_ptr<H2Mux::Http2Server> Server) -> Net::awaitable<void>
        {
            try
            {
                const auto Result = co_await Server->Run();
                if (!Result) RecordHttp2RunFailure(State, Result.error());
            }
            catch (const boost::system::system_error &Error)
            {
                RecordHttp2RunFailure(State, Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
                throw;
            }
            catch (const std::system_error &Error)
            {
                RecordHttp2RunFailure(State, Preview::Fault::FromNative(Error.code()));
                throw;
            }
            catch (...)
            {
                State->RecordTerminalFailure(
                    Preview::Fault::Failure{Preview::Fault::Code::IoError});
                throw;
            }
        }
        static auto ServeHttp2(std::shared_ptr<RootState> State)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            auto Server = std::make_shared<H2Mux::Http2Server>(State->Inbound, State->Options.MaxStreams);
            if (!State->EngineControl)
                State->EngineControl = std::make_shared<EngineCloseOwner<H2Mux::Http2Server>>(
                    Server, State);
            Server->BindIdentity(State->Metadata.TaskIdentity);
            if (State->StreamCatalogOwner &&
                !State->StreamCatalogOwner->Enable(State->Options.MaxStreams))
            {
                State->StreamCatalogOwner->Disable();
            }
            Preview::Lifecycle::TaskRequest Request{
                .Context = Preview::Lifecycle::FromParent(State->Metadata.TaskIdentity),
                .StartOnSubmit = true};
            const auto Weak = std::weak_ptr<H2Mux::Http2Server>(Server);
            Request.Cancel = [Weak] { if (const auto Owner = Weak.lock()) Owner->Cancel(); };
            if (!State->Loops->SpawnTracked(std::move(Request), RunHttp2(State, Server)))
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            while (!State->Stopping.load())
            {
                const auto Stream = co_await Server->AcceptStream();
                if (!Stream) break;
                auto Child = std::make_shared<ChildState>();
                Child->Inbound = Stream;
                Child->Identity.StreamId = Preview::StreamId{static_cast<std::uint64_t>(Stream->StreamId())};
                Child->Reject = [WeakStream = std::weak_ptr<H2Mux::Http2Stream>(Stream)]
                { if (const auto Owner = WeakStream.lock()) (void)Owner->Close(); };
                Child->Reset = [WeakStream = std::weak_ptr<H2Mux::Http2Stream>(Stream)]()
                    -> std::expected<void, Preview::Fault::Failure>
                {
                    if (const auto Owner = WeakStream.lock())
                    {
                        return Owner->Cancel();
                    }
                    return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                };
                Child->Finish = [Stream] { return Stream->DrainTerminations(); };
                if (!StartChild(State, std::move(Child)))
                {
                    co_return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::Canceled});
                }
            }
            State->Stop();
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        static auto Serve(std::shared_ptr<RootState> State)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            if (State->Stopping.load())
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            const auto Envelope = co_await Preview::Mux::Detail::SingMux::ReadSessionRequest(State->Inbound);
            if (!Envelope)
            {
                co_return std::unexpected(Envelope.error());
            }
            const auto Selected = static_cast<Mode>(static_cast<unsigned>(Envelope->ProtocolValue) + 1);
            if (State->Options.Wire != Mode::Auto && State->Options.Wire != Selected)
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::NotSupported});
            }
            State->SelectedWire = Selected;
            if (Selected == Mode::Smux) co_return co_await ServeEngine<Smux::Server<>>(State);
            if (Selected == Mode::Yamux) co_return co_await ServeEngine<Yamux::Server<>>(State);
            co_return co_await ServeHttp2(State);
        }
        std::shared_ptr<RootState> State_;
        std::shared_ptr<RootActivity> Activity_;
        std::shared_ptr<RootRegistryNode> RegistrationNode_;
        bool CreateCommitted_{false};

        [[nodiscard]] static auto DrainResources(std::shared_ptr<RootState> State)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            if (State->ResourcesRetired.load())
            {
                try
                {
                    if (!State->ReleaseResources())
                        co_return std::unexpected(
                            Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                }
                catch (...)
                {
                    const auto Failure = RootState::FailureFromException(std::current_exception());
                    State->RecordTerminalFailure(Failure);
                    co_return std::unexpected(Failure);
                }
                const auto Historical = State->TerminalFailure.Load();
                if (Historical.Failed()) co_return std::unexpected(Historical);
                co_return std::expected<void, Preview::Fault::Failure>{};
            }
            State->ResourcesReadyForFinalization.store(false, std::memory_order_release);
            try
            {
                co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
                co_await Net::dispatch(State->Executor, Net::use_awaitable);
            }
            catch (...)
            {
                const auto Failure = RootState::FailureFromException(std::current_exception());
                State->RecordTerminalFailure(Failure);
                co_return std::unexpected(Failure);
            }
            bool ScopesRetired = true;
            try
            {
                const auto Children = co_await State->DrainTaskScope(State->Children);
                if (!Children) ScopesRetired = false;
            }
            catch (...)
            {
                ScopesRetired = false;
                State->RecordTerminalFailure(
                    RootState::FailureFromException(std::current_exception()));
            }
            State->Loops->Seal();
            try
            {
                const auto Loops = co_await State->DrainTaskScope(State->Loops);
                if (!Loops) ScopesRetired = false;
            }
            catch (...)
            {
                ScopesRetired = false;
                State->RecordTerminalFailure(
                    RootState::FailureFromException(std::current_exception()));
            }
            const auto Engine = co_await DrainRootEngine(State);
            const auto Carrier = co_await DrainRootCarrier(State, Engine.H2Retired);
            if (Carrier.Failure.Failed()) State->RecordTerminalFailure(Carrier.Failure);
            co_await Net::dispatch(State->Executor, Net::use_awaitable);
            const auto RetainedChildren = co_await DrainRetainedChildren(State, Engine.Retired);
            if (RetainedChildren.Failure.Failed())
                State->RecordTerminalFailure(RetainedChildren.Failure);
            if (!RetainedChildren.Retired)
            {
                auto Failure = State->TerminalFailure.Load();
                if (!Failure.Failed()) Failure = {Preview::Fault::Code::Blocked};
                co_return std::unexpected(Failure);
            }
            if (!ScopesRetired || !Engine.Retired || !Carrier.Retired)
            {
                auto Failure = State->TerminalFailure.Load();
                if (!Failure.Failed()) Failure = {Preview::Fault::Code::Blocked};
                State->RecordTerminalFailure(Failure);
                co_return std::unexpected(Failure);
            }
            if (State->Lifetime.Active() != 0U && !State->Lifetime.IsBlocked())
            {
                State->ResourcesReadyForFinalization.store(true, std::memory_order_release);
                co_return std::expected<void, Preview::Fault::Failure>{};
            }
            if (State->Lifetime.Active() != 0U || State->Lifetime.IsBlocked())
            {
                const Preview::Fault::Failure Failure{Preview::Fault::Code::Blocked};
                State->RecordTerminalFailure(Failure);
                co_return std::unexpected(Failure);
            }
            try
            {
                if (!State->ReleaseResources())
                {
                    const Preview::Fault::Failure Failure{Preview::Fault::Code::Blocked};
                    State->RecordTerminalFailure(Failure);
                    co_return std::unexpected(Failure);
                }
            }
            catch (...)
            {
                const auto Failure = RootState::FailureFromException(std::current_exception());
                State->RecordTerminalFailure(Failure);
                co_return std::unexpected(Failure);
            }
            const auto Historical = State->TerminalFailure.Load();
            if (Historical.Failed()) co_return std::unexpected(Historical);
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
    };
}
