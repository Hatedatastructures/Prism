/** @file SessionControl.hpp @brief 会话固定父身份、预建关闭交付与真实任务排空。 */
#pragma once
#include <Preview/Foundation/Executor/PreparedAction.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Contract/Ingress/StreamCatalog.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>
#include <Preview/Runtime/Session/Delivery.hpp>
#include <array>
#include <atomic>
#include <optional>
namespace Preview::Runtime
{
    namespace Net = boost::asio;
    class SessionRegistry;
    struct SessionMetrics final
    {
        std::size_t Started{0}, Completed{0}, Active{0}, CancelRequests{0}, ErrorCalls{0}, CloseCalls{0};
        bool DrainBlocked{false}, CloseDispatchFailed{false};
    };
    /** @brief control 持有子 registry 与预建命令；错误使用 Failure，父身份只发布一次。
     * @details 取消不代替 drain，CloseOnce 只提交已经安装的动作，无半关闭。
     * 最终资源关闭归动作内的真实 owner；失败保留在 ClosingStorage。
     */
    class SessionControl final
    {
        using Registry = Preview::Lifecycle::TaskRegistry;
        using Identity = Preview::Lifecycle::TaskIdentity;
        using Failure = Preview::Fault::Failure;
        using Prepared = Preview::Executor::PreparedAction;
    public:
        using CancelFn = std::function<void()>;
        using CloseFn = Prepared::Action;
        using ErrorHook = std::function<void(Failure)>;
        using IdentityErrorHook = std::function<void(const Identity&, Failure)>;
        using MetricsHook = std::function<void(const SessionMetrics&)>;
    private:
        struct Binding final
        {
            std::shared_ptr<Registry> Tasks;
            std::shared_ptr<Prepared> CancelAction;
            std::shared_ptr<SessionDelivery> Delivery;
        };
        struct State final : Preview::Lifecycle::TaskIdentityObserver
        {
            auto PublishIdentity(const Identity& Value) -> void override
            {
                if (ParentIdentity.load()) return;
                auto Candidate = std::make_shared<const Identity>(Value);
                std::shared_ptr<const Identity> Empty;
                (void)ParentIdentity.compare_exchange_strong(Empty, std::move(Candidate));
            }
            std::atomic<std::shared_ptr<Binding>> Bound;
            std::atomic<std::shared_ptr<const Identity>> ParentIdentity;
            std::atomic<std::shared_ptr<Preview::Contract::Ingress::StreamCatalog>> StreamCatalogOwner;
            std::atomic<std::shared_ptr<Prepared>> CloseAction;
            std::array<std::atomic<std::shared_ptr<Prepared>>, 16> CancelHooks;
            std::atomic<std::size_t> HookCount{0};
            std::atomic<std::shared_ptr<ErrorHook>> OnError;
            std::atomic<std::shared_ptr<IdentityErrorHook>> OnIdentityError;
            std::atomic<std::shared_ptr<MetricsHook>> OnMetrics;
            std::atomic<bool> CancelRequested{false}, Sealed{false}, Closed{false};
            std::atomic<bool> SessionRootStarted{false};
            std::atomic<bool> Blocked{false}, CloseDispatchFailed{false};
            Preview::Fault::FailureState ControlFailure;
            std::atomic<std::size_t> CancelRequests{0}, ErrorCalls{0}, CloseCalls{0};
        };
        /** @brief 本次交付的有限动作集合；后续无关提交不能扩大它。 */
        struct DeliveryBatch final
        {
            std::shared_ptr<Prepared> Cancel;
            std::shared_ptr<Prepared> Close;
            std::array<std::shared_ptr<Prepared>, 16> Hooks;
            bool Cancellation{false};
        };
        [[nodiscard]] static auto CaptureDelivery(const std::shared_ptr<State>& Value) -> DeliveryBatch
        {
            DeliveryBatch Batch;
            Batch.Cancellation = Value->CancelRequested.load();
            Batch.Close = Value->CloseAction.load();
            if (auto Bound = Value->Bound.load()) Batch.Cancel = Bound->CancelAction;
            for (std::size_t Index = 0; Index < Batch.Hooks.size(); ++Index)
                Batch.Hooks[Index] = Value->CancelHooks[Index].load();
            return Batch;
        }
        /** @brief 只确认已捕获取消动作及其有限子 hook；不观察其他 control。 */
        [[nodiscard]] static auto DeliverCancellation(const DeliveryBatch& Batch)
            -> Net::awaitable<std::expected<void, Failure>>
        {
            if (!Batch.Cancellation) co_return std::expected<void, Failure>{};
            auto Submitted = Batch.Cancel->Submit();
            if (!Submitted) co_return Submitted;
            // 固定集合各自持有完成通知；未完成的异步 post 不被普通队列水位冒充完成。
            for (const auto& Hook : Batch.Hooks)
                if (Hook) { auto Result = Hook->Submit(); if (!Result) co_return Result; }
            auto Cancelled = co_await Batch.Cancel->Await();
            if (!Cancelled) co_return Cancelled;
            for (const auto& Hook : Batch.Hooks)
                if (Hook) { auto Result = co_await Hook->Await(); if (!Result) co_return Result; }
            co_return std::expected<void, Failure>{};
        }
        static auto MakeMetrics(const std::shared_ptr<State>& Value) noexcept -> SessionMetrics
        {
            Preview::Lifecycle::TaskStats Snapshot;
            if (auto Bound = Value->Bound.load()) Snapshot = Bound->Tasks->Stats();
            return {Snapshot.Started, Snapshot.Completed, Snapshot.Active, Value->CancelRequests.load(),
                Value->ErrorCalls.load(), Value->CloseCalls.load(), Value->Blocked.load() || Snapshot.DrainBlocked,
                Value->CloseDispatchFailed.load()};
        }
        static auto EmitMetrics(const std::shared_ptr<State>& Value) -> void
        { if (auto Hook = Value->OnMetrics.load(); Hook && *Hook) (*Hook)(MakeMetrics(Value)); }
        static auto MarkBlocked(const std::shared_ptr<State>& Value) noexcept -> void
        { Value->Blocked.store(true); if (auto Bound = Value->Bound.load()) Bound->Tasks->Block(); }
        static auto DispatchCancel(const std::shared_ptr<State>& Value) -> void
        {
            for (auto& Slot : Value->CancelHooks)
                if (auto Hook = Slot.load(); Hook && !Hook->Submit()) MarkBlocked(Value);
            EmitMetrics(Value);
        }
        static auto Report(const std::shared_ptr<State>& Value, std::pair<Identity, Failure> Error) -> void
        {
            Value->ErrorCalls.fetch_add(1);
            if (auto Hook = Value->OnError.load(); Hook && *Hook) (*Hook)(Error.second);
            if (auto Hook = Value->OnIdentityError.load(); Hook && *Hook) (*Hook)(Error.first, Error.second);
            EmitMetrics(Value);
        }
        auto InstallBinding(std::shared_ptr<Registry> Tasks) -> bool
        {
            auto Bound = std::make_shared<Binding>();
            Bound->Tasks = std::move(Tasks);
            Bound->Delivery = std::make_shared<SessionDelivery>(Bound->Tasks->Reclaimer());
            auto Weak = std::weak_ptr<State>(State_);
            Bound->CancelAction = std::make_shared<Prepared>(Bound->Tasks->Reclaimer(),
                [Weak]() -> std::expected<void, Failure>
                { if (auto Value = Weak.lock()) { DispatchCancel(Value); if (Value->Blocked.load()) return std::unexpected(Failure{Preview::Fault::Code::Blocked}); } return {}; });
            std::shared_ptr<Binding> Empty;
            if (!State_->Bound.compare_exchange_strong(Empty, Bound)) return false;
            if (State_->CancelRequested.load())
            { (void)Bound->Tasks->Cancel(); if (!Bound->CancelAction->Submit()) MarkBlocked(State_); }
            return true;
        }
        [[nodiscard]] auto FailureReporter() -> Registry::FailureHandler
        {
            return [Weak = std::weak_ptr<State>(State_)](const Identity& Id, Failure Error)
                { if (auto Value = Weak.lock()) Report(Value, {Id, Error}); };
        }
    public:
        SessionControl() : State_(std::make_shared<State>()) {}
        explicit SessionControl(Net::any_io_executor Executor) : SessionControl() { (void)Bind(std::move(Executor)); }
        SessionControl(const SessionControl&) = delete;
        auto operator=(const SessionControl&) -> SessionControl& = delete;
        /** @brief 冷绑定独立 scope；executor 必须活至 Drain 和关闭交付完成。 */
        [[nodiscard]] auto Bind(Net::any_io_executor Executor) -> bool
        { if (State_->Bound.load()) return false; return InstallBinding(std::make_shared<Registry>(std::move(Executor), FailureReporter())); }
        /** @brief 冷绑定 worker 子 scope；借用父只覆盖本调用，之后持有独立子 owner。 */
        [[nodiscard]] auto Bind(Net::any_io_executor, Registry& Parent) -> bool
        { if (State_->Bound.load()) return false; return InstallBinding(Parent.CreateChild(FailureReporter())); }
        /** @brief 冷装配错误观察函数；只在绑定 executor 调用，无所有权回收。 */
        auto SetErrorHook(ErrorHook Hook) -> void { State_->OnError.store(std::make_shared<ErrorHook>(std::move(Hook))); }
        auto SetErrorHook(IdentityErrorHook Hook) -> void
        { State_->OnIdentityError.store(std::make_shared<IdentityErrorHook>(std::move(Hook))); }
        auto SetMetricsHook(MetricsHook Hook) -> void
        { State_->OnMetrics.store(std::make_shared<MetricsHook>(std::move(Hook))); }
        /** @brief 冷安装有限取消动作；动作拥有闭包，失败不修改已安装的其他动作。 */
        [[nodiscard]] auto AddCancelHook(CancelFn Hook) -> std::expected<void, Failure>
        {
            auto Bound = State_->Bound.load();
            if (!Bound || !Hook) return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            auto Entry = std::make_shared<Prepared>(Bound->Tasks->Reclaimer(),
                [Hook = std::move(Hook)]() -> std::expected<void, Failure> { Hook(); return {}; });
            auto Count = State_->HookCount.load();
            for (;;)
            {
                if (Count == State_->CancelHooks.size()) return std::unexpected(Failure{Preview::Fault::Code::ResourceUnavailable});
                if (State_->HookCount.compare_exchange_weak(Count, Count + 1)) break;
            }
            State_->CancelHooks[Count].store(Entry);
            if (State_->CancelRequested.load()) return Entry->Submit();
            return {};
        }
        /** @brief 冷安装唯一关闭动作，拥有实物的闭包必须在提交前构造。 */
        [[nodiscard]] auto SetCloseAction(CloseFn Work) -> std::expected<void, Failure>
        {
            auto Bound = State_->Bound.load();
            if (!Bound || !Work) return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            auto Action = std::make_shared<Prepared>(Bound->Tasks->Reclaimer(), std::move(Work));
            std::shared_ptr<Prepared> Empty;
            if (!State_->CloseAction.compare_exchange_strong(Empty, Action))
                return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            return {};
        }
        /** @brief 接管一次操作与上下文，返回唯一任务身份；不覆盖固定父会话身份。 */
        template<class OperationType>
        [[nodiscard]] auto Start(Preview::Lifecycle::TaskRequest Request, OperationType Operation)
            -> std::expected<Preview::Lifecycle::TaskHandle, Failure>
        {
            auto Bound = State_->Bound.load();
            if (!Bound || State_->Sealed.load()) return std::unexpected(Failure{Preview::Fault::Code::Canceled});
            if (auto Parent = State_->ParentIdentity.load()) Request.Context = Preview::Lifecycle::FromParent(*Parent);
            Request.StartOnSubmit = true;
            Request.IdentityObserver = State_;
            auto Task = Bound->Tasks->SpawnTracked(std::move(Request), std::move(Operation));
            if (Task) (void)SetIdentity(Task->Identity());
            return Task;
        }
        /**
         * @brief 把唯一 Session runner 登记在父 root scope，子 scope 仍专用于 Session children。
         * @param Parent 与 Bind(executor, Parent) 相同的 Worker root 或 standalone listener root。
         * @param Request 按值移交 session/worker/generation 身份、task context 与取消动作。
         * @param Operation 按值移交的 Session runner；在 Parent executor 上执行。
         * @return 唯一 task handle 或真实准入失败；不把 runner 放入其随后必须 Drain 的子 scope。
         * @details Parent 仅在本次同步提交期间借用；它持有有界 root task slot、取消请求、失败记录
         *          和真实 completion retirement receipt，直到 completion handler 退栈。SessionControl
         *          继续拥有独立 child registry，只排空本会话子任务；runner 返回前须等待关闭交付、
         *          传输 Activity 与 child registry 真实 drain。取消只请求关闭，不代替半关闭或最终 close。
         */
        template<class OperationType>
        [[nodiscard]] auto StartSession(
            Registry &Parent,
            Preview::Lifecycle::TaskRequest Request,
            OperationType Operation) -> std::expected<Preview::Lifecycle::TaskHandle, Failure>
        {
            auto Bound = State_->Bound.load();
            if (!Bound || State_->Sealed.load())
                return std::unexpected(Failure{Preview::Fault::Code::Canceled});
            bool Expected = false;
            if (!State_->SessionRootStarted.compare_exchange_strong(Expected, true))
                return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            if (State_->ParentIdentity.load())
            {
                State_->SessionRootStarted.store(false);
                return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            }
            Request.StartOnSubmit = true;
            Request.IdentityObserver = State_;
            auto Task = Parent.SpawnTracked(std::move(Request), std::move(Operation));
            if (Task)
            {
                (void)SetIdentity(Task->Identity());
            }
            else
            {
                State_->SessionRootStarted.store(false);
            }
            return Task;
        }
        /** @brief 首次发布固定父身份；后续子任务提交不会修改该值。 */
        [[nodiscard]] auto SetIdentity(const Identity& Value) -> bool
        {
            if (auto Current = State_->ParentIdentity.load()) return Current->TaskId == Value.TaskId;
            auto Candidate = std::make_shared<const Identity>(Value);
            std::shared_ptr<const Identity> Empty;
            return State_->ParentIdentity.compare_exchange_strong(Empty, std::move(Candidate));
        }
        /** @brief 按值读取固定父身份；未发布返回空值，不受后续子任务提交影响。 */
        [[nodiscard]] auto CurrentIdentity() const noexcept -> Identity
        { if (auto Value = State_->ParentIdentity.load()) return *Value; return {}; }
        /** @brief 为本会话绑定唯一的真实协议 stream 查询目录；不建立 callback 或资源别名。 */
        [[nodiscard]] auto AttachStreamCatalog(
            std::shared_ptr<Preview::Contract::Ingress::StreamCatalog> Value) noexcept -> bool
        {
            if (!Value || State_->Sealed.load(std::memory_order_acquire)) return false;
            std::shared_ptr<Preview::Contract::Ingress::StreamCatalog> Empty;
            return State_->StreamCatalogOwner.compare_exchange_strong(
                Empty, std::move(Value), std::memory_order_acq_rel);
        }
        /** @brief 跨 executor 返回按值目录快照；不会取得 stream/task/transport owner。 */
        [[nodiscard]] auto FindStream(
            const Preview::Contract::Ingress::StreamIdentity &Identity) const noexcept
            -> Preview::Contract::Ingress::StreamCatalogLookup
        {
            const auto Catalog = State_->StreamCatalogOwner.load(std::memory_order_acquire);
            if (!Catalog)
            {
                return {Preview::Contract::Ingress::StreamCatalogStatus::CapabilityUnavailable, {}};
            }
            return Catalog->Find(Identity);
        }
        /** @brief 校验 session 控制 owner 后返回真实 live stream 的有界值页。 */
        [[nodiscard]] auto ListStreams(
            const Preview::Contract::Ingress::StreamListRequest &Request) const
            -> Preview::Contract::Ingress::StreamCatalogPage
        {
            const auto Parent = CurrentIdentity();
            if (Parent.SessionId != Request.Parent.Session ||
                Parent.WorkerId != Request.Parent.Worker ||
                Parent.Generation != Request.Parent.Generation)
            {
                return {Preview::Contract::Ingress::StreamCatalogStatus::NotFound, {},
                    Request.Cursor, false};
            }
            const auto Catalog = State_->StreamCatalogOwner.load(std::memory_order_acquire);
            if (!Catalog)
            {
                return {Preview::Contract::Ingress::StreamCatalogStatus::CapabilityUnavailable,
                    {}, Request.Cursor, false};
            }
            return Catalog->List(Request);
        }
        /** @brief 按固定 root 身份取消单一 stream 并等待协议 drain 与 child 任务退休。 */
        [[nodiscard]] auto ResetStreamAndDrain(
            Preview::Contract::Ingress::StreamResetRequest Request)
            -> Net::awaitable<std::expected<void, Failure>>
        {
            const auto Parent = CurrentIdentity();
            if (!Parent.TaskId || Request.Identity.Session != Parent.SessionId ||
                Request.Identity.Worker != Parent.WorkerId ||
                Request.Identity.Generation != Parent.Generation ||
                Request.ParentTask != Parent.TaskId || !Request.Task)
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            }
            const auto Catalog = State_->StreamCatalogOwner.load(std::memory_order_acquire);
            if (!Catalog)
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::NotSupported});
            }
            co_return co_await Catalog->ResetAndDrain(std::move(Request));
        }
        /** @brief 取消只提交预建动作，重复请求无副作用；失败阻断 Drain。 */
        [[nodiscard]] auto Cancel() -> std::expected<void, Failure>
        {
            if (State_->CancelRequested.exchange(true))
            {
                const auto Failure = State_->ControlFailure.Load();
                if (Failure.Failed()) return std::unexpected(Failure);
                if (State_->Blocked.load()) return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                return {};
            }
            State_->CancelRequests.fetch_add(1);
            State_->Sealed.store(true);
            auto Bound = State_->Bound.load();
            if (!Bound)
            {
                const auto Failure = Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument};
                (void)State_->ControlFailure.TrySet(Failure); MarkBlocked(State_);
                return std::unexpected(Failure);
            }
            (void)Bound->Tasks->Cancel();
            const auto Delivered = Bound->CancelAction->Submit();
            if (Bound->Tasks->IsDrainBlocked())
            {
                const auto Failure = Preview::Fault::Failure{Preview::Fault::Code::Blocked};
                (void)State_->ControlFailure.TrySet(Failure);
                MarkBlocked(State_);
                return std::unexpected(Failure);
            }
            if (!Delivered)
            { (void)State_->ControlFailure.TrySet(Delivered.error()); MarkBlocked(State_); return Delivered; }
            return {};
        }
        /** @brief 读取取消状态；无半关闭、最终关闭或 executor 调度副作用。 */
        [[nodiscard]] auto IsCancelled() const noexcept -> bool
        {
            if (State_->CancelRequested.load()) return true;
            auto Bound = State_->Bound.load();
            return Bound && Bound->Tasks->Domain()->IsCancellationRequested();
        }
        /** @brief 提交唯一预建 close，重复返回成功；仅表示交付接受，不表示 I/O 排空。 */
        [[nodiscard]] auto CloseOnce() -> std::expected<void, Failure>
        {
            State_->Sealed.store(true);
            auto Action = State_->CloseAction.load();
            if (!Action) { MarkBlocked(State_); return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument}); }
            if (auto Bound = State_->Bound.load()) Bound->Tasks->Seal();
            auto Result = Action->Submit();
            if (!State_->Closed.exchange(true)) State_->CloseCalls.fetch_add(1);
            if (!Result) { (void)State_->ControlFailure.TrySet(Result.error()); State_->CloseDispatchFailed.store(true); MarkBlocked(State_); }
            return Result;
        }
        /** @brief 等待任务实际退栈；调用者仍须等待关闭交付并退休其传输 owner。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<std::expected<void, Failure>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            auto Bound = State_->Bound.load();
            State_->Sealed.store(true);
            const auto ControlFailure = State_->ControlFailure.Load();
            if (ControlFailure.Failed()) co_return std::unexpected(ControlFailure);
            if (!Bound || State_->Blocked.load()) co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            co_return co_await Bound->Tasks->Drain();
        }
        /** @brief 按值投递错误，保留原生 cause；不创建 exception_ptr。 */
        auto ReportError(Failure Error) -> void { ReportError(CurrentIdentity(), Error); }
        auto ReportError(const Identity& Id, Failure Error) -> void
        {
            auto Bound = State_->Bound.load();
            if (!Bound) { MarkBlocked(State_); return; }
            if (!Bound->Tasks->Reclaimer()->Post([Value = State_, Id, Error] { Report(Value, {Id, Error}); })) MarkBlocked(State_);
        }
        /** @brief 等待此前动作交付；blocked 不当作成功，取消以 Failure 返回。 */
        [[nodiscard]] auto AwaitDelivery() -> Net::awaitable<std::expected<void, Failure>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            auto Bound = State_->Bound.load();
            if (!Bound) co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            if (State_->Blocked.load()) co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            auto Batch = CaptureDelivery(State_);
            auto Result = co_await Bound->Delivery->Await();
            if (!Result) { MarkBlocked(State_); co_return Result; }
            Batch.Cancellation = Batch.Cancellation || State_->CancelRequested.load();
            Result = co_await DeliverCancellation(Batch);
            if (!Result) { MarkBlocked(State_); co_return Result; }
            // 初始错误前缀与有限 hook 已完成；只等待此时已经提交的唯一 close 的自身确认。
            const auto IncludeClose = Batch.Close && State_->Closed.load();
            if (IncludeClose) Result = co_await Batch.Close->Await();
            if (State_->Blocked.load() && Result) Result = std::unexpected(Failure{Preview::Fault::Code::Blocked});
            if (!Result) MarkBlocked(State_);
            co_return Result;
        }
        /** @brief 按值读取会话统计；不借用 owner，也不触发关闭或取消。 */
        [[nodiscard]] auto Metrics() const noexcept -> SessionMetrics { return MakeMetrics(State_); }
        /** @brief 读取关闭已提交事实；实际交付和退休分别由 AwaitDelivery 与 Finalize 确认。 */
        [[nodiscard]] auto IsClosed() const noexcept -> bool { return State_->Closed.load(); }
        /** @brief 读取不能继续排空的事实；调用方必须保留资源并处理失败。 */
        [[nodiscard]] auto IsDrainBlocked() const noexcept -> bool { return Metrics().DrainBlocked; }
        /** @brief 读取关闭投递失败事实；失败实物保留于原 owner 和关闭存储。 */
        [[nodiscard]] auto IsCloseDispatchFailed() const noexcept -> bool { return State_->CloseDispatchFailed.load(); }
    private:
        friend class SessionRegistry;
        friend class SessionRegistryTestAccess;

        /** @brief 仅供 SessionRegistry 在固定父 executor 上排队生命周期操作。 */
        [[nodiscard]] auto Executor() const -> std::optional<Net::any_io_executor>
        {
            const auto Bound = State_->Bound.load();
            if (!Bound)
            {
                return std::nullopt;
            }
            return Bound->Tasks->Executor();
        }

        std::shared_ptr<State> State_;
    };
}
