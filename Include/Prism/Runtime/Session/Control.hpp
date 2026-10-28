/** @file Control.hpp @brief 会话固定父身份、预建关闭交付与真实任务排空。 */
#pragma once
#include <Prism/Foundation/Executor/PreparedAction.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Lifecycle/Task/Registry.hpp>
#include <Prism/Runtime/Session/Delivery.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
namespace Prism::Runtime
{
    namespace Net = boost::asio;
    class SessionRegistry;
    class SessionRegistryLifecycleTestAccess;
    class SessionRegistryTestAccess;
    struct SessionMetrics final
    {
        std::size_t Started{0}, Completed{0}, Active{0}, CancelRequests{0}, ErrorCalls{0}, CloseCalls{0};
        bool DrainBlocked{false}, CloseDispatchFailed{false};
    };
    /** @brief 会话取消来源，shutdown 仅在完整退休后可归一化为正常结束。 */
    enum class SessionCancellationReason : std::uint8_t
    {
        None,
        Explicit,
        Shutdown
    };
    /** @brief control 持有子 registry 与预建命令；错误使用 Failure，父身份只发布一次。
     * @details 取消不代替 drain，CloseOnce 只提交已经安装的动作，无半关闭。
     * 最终资源关闭归动作内的真实 owner；失败保留在 ClosingStorage。
     */
    class SessionControl final
    {
        using Registry = Prism::Lifecycle::TaskRegistry;
        using Identity = Prism::Lifecycle::TaskIdentity;
        using Failure = Prism::Fault::Failure;
        using Prepared = Prism::Executor::PreparedAction;
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
        struct State final : Prism::Lifecycle::TaskIdentityObserver
        {
            enum class HookFailureInjection : std::uint8_t
            {
                None,
                RuntimeError,
                AllocationFailure,
            };

            auto PublishIdentity(const Identity& Value) -> void override;
            std::atomic<std::shared_ptr<Binding>> Bound;
            std::atomic<std::shared_ptr<const Identity>> ParentIdentity;
            std::atomic<std::shared_ptr<Prism::Contract::Ingress::StreamCatalog>> StreamCatalogOwner;
            std::atomic<std::shared_ptr<Prepared>> CloseAction;
            std::array<std::atomic<std::shared_ptr<Prepared>>, 16> CancelHooks;
            std::atomic<std::size_t> HookCount{0};
            std::atomic<std::shared_ptr<ErrorHook>> OnError;
            std::atomic<std::shared_ptr<IdentityErrorHook>> OnIdentityError;
            std::atomic<std::shared_ptr<MetricsHook>> OnMetrics;
            std::atomic<bool> CancelRequested{false}, Sealed{false}, Closed{false};
            std::atomic<bool> ExplicitCancelRequested{false}, ShutdownCancelRequested{false};
            std::atomic<bool> SessionRootStarted{false};
            std::atomic<bool> Blocked{false}, CloseDispatchFailed{false};
            std::atomic<HookFailureInjection> ErrorHookFailureInjection{
                HookFailureInjection::None};
            std::atomic<HookFailureInjection> MetricsHookFailureInjection{
                HookFailureInjection::None};
            Prism::Fault::FailureState ControlFailure;
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
        [[nodiscard]] static auto CaptureDelivery(const std::shared_ptr<State>& Value) -> DeliveryBatch;
        /** @brief 只确认已捕获取消动作及其有限子 hook；不观察其他 control。 */
        [[nodiscard]] static auto DeliverCancellation(const DeliveryBatch& Batch)
            -> Net::awaitable<std::expected<void, Failure>>;
        static auto MakeMetrics(const std::shared_ptr<State>& Value) noexcept -> SessionMetrics;
        static auto EmitMetrics(const std::shared_ptr<State>& Value) -> void;
        static auto MarkBlocked(const std::shared_ptr<State>& Value) noexcept -> void;
        static auto DispatchCancel(const std::shared_ptr<State>& Value) -> void;
        static auto Report(const std::shared_ptr<State>& Value,
            std::pair<Identity, Failure> Error) -> void;
        auto InstallBinding(std::shared_ptr<Registry> Tasks) -> bool;
        [[nodiscard]] auto FailureReporter() -> Registry::FailureHandler;
    public:
        SessionControl();
        explicit SessionControl(Net::any_io_executor Executor);
        SessionControl(const SessionControl&) = delete;
        auto operator=(const SessionControl&) -> SessionControl& = delete;
        /** @brief 冷绑定独立 scope；executor 必须活至 Drain 和关闭交付完成。 */
        [[nodiscard]] auto Bind(Net::any_io_executor Executor) -> bool;
        /** @brief 冷绑定 worker 子 scope；借用父只覆盖本调用，之后持有独立子 owner。 */
        [[nodiscard]] auto Bind(Net::any_io_executor Executor, Registry& Parent) -> bool;
        /** @brief 冷装配错误观察函数；只在绑定 executor 调用，无所有权回收。 */
        auto SetErrorHook(ErrorHook Hook) -> void;
        auto SetErrorHook(IdentityErrorHook Hook) -> void;
        auto SetMetricsHook(MetricsHook Hook) -> void;
        /** @brief 冷安装有限取消动作；动作拥有闭包，失败不修改已安装的其他动作。 */
        [[nodiscard]] auto AddCancelHook(CancelFn Hook) -> std::expected<void, Failure>;
        /** @brief 冷安装唯一关闭动作，拥有实物的闭包必须在提交前构造。 */
        [[nodiscard]] auto SetCloseAction(CloseFn Work) -> std::expected<void, Failure>;
        /** @brief 接管一次操作与上下文，返回唯一任务身份；不覆盖固定父会话身份。 */
        template<class OperationType>
        [[nodiscard]] auto Start(Prism::Lifecycle::TaskRequest Request, OperationType Operation)
            -> std::expected<Prism::Lifecycle::TaskHandle, Failure>
        {
            auto Bound = State_->Bound.load();
            if (!Bound || State_->Sealed.load()) return std::unexpected(Failure{Prism::Fault::Code::Canceled});
            if (auto Parent = State_->ParentIdentity.load()) Request.Context = Prism::Lifecycle::FromParent(*Parent);
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
            Prism::Lifecycle::TaskRequest Request,
            OperationType Operation) -> std::expected<Prism::Lifecycle::TaskHandle, Failure>
        {
            auto Bound = State_->Bound.load();
            if (!Bound || State_->Sealed.load())
                return std::unexpected(Failure{Prism::Fault::Code::Canceled});
            bool Expected = false;
            if (!State_->SessionRootStarted.compare_exchange_strong(Expected, true))
                return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            if (State_->ParentIdentity.load())
            {
                State_->SessionRootStarted.store(false);
                return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
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
        [[nodiscard]] auto SetIdentity(const Identity& Value) -> bool;
        /** @brief 按值读取固定父身份；未发布返回空值，不受后续子任务提交影响。 */
        [[nodiscard]] auto CurrentIdentity() const noexcept -> Identity
        { if (auto Value = State_->ParentIdentity.load()) return *Value; return {}; }
        /** @brief 为本会话绑定唯一的真实协议 stream 查询目录；不建立 callback 或资源别名。 */
        [[nodiscard]] auto AttachStreamCatalog(
            std::shared_ptr<Prism::Contract::Ingress::StreamCatalog> Value) noexcept -> bool;
        /** @brief 跨 executor 返回按值目录快照；不会取得 stream/task/transport owner。 */
        [[nodiscard]] auto FindStream(
            const Prism::Contract::Ingress::StreamIdentity &Identity) const noexcept
            -> Prism::Contract::Ingress::StreamCatalogLookup;
        /** @brief 校验 session 控制 owner 后返回真实 live stream 的有界值页。 */
        [[nodiscard]] auto ListStreams(
            const Prism::Contract::Ingress::StreamListRequest &Request) const
            -> Prism::Contract::Ingress::StreamCatalogPage;
        /** @brief 按固定 root 身份取消单一 stream 并等待协议 drain 与 child 任务退休。 */
        [[nodiscard]] auto ResetStreamAndDrain(
            Prism::Contract::Ingress::StreamResetRequest Request)
            -> Net::awaitable<std::expected<void, Failure>>;
        /** @brief 显式取消；重复请求无副作用，且优先于 shutdown-only 语义。 */
        [[nodiscard]] auto Cancel() -> std::expected<void, Failure>;
        /** @brief Listener shutdown 取消等待中的操作，并单独记录其停止原因。 */
        [[nodiscard]] auto CancelForShutdown() -> std::expected<void, Failure>;
        /** @brief 返回当前取消原因；显式取消优先于 shutdown 请求。 */
        [[nodiscard]] auto CancellationReason() const noexcept -> SessionCancellationReason;
        /** @brief 读取取消状态；无半关闭、最终关闭或 executor 调度副作用。 */
        [[nodiscard]] auto IsCancelled() const noexcept -> bool;
        /** @brief 提交唯一预建 close，重复返回成功；仅表示交付接受，不表示 I/O 排空。 */
        [[nodiscard]] auto CloseOnce() -> std::expected<void, Failure>;
        /** @brief 等待任务实际退栈；调用者仍须等待关闭交付并退休其传输 owner。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<std::expected<void, Failure>>;
        /** @brief 按值投递错误，保留原生 cause；不创建 exception_ptr。 */
        auto ReportError(Failure Error) -> void;
        auto ReportError(const Identity& Id, Failure Error) -> void;
        /** @brief 等待此前动作交付；blocked 不当作成功，取消以 Failure 返回。 */
        [[nodiscard]] auto AwaitDelivery() -> Net::awaitable<std::expected<void, Failure>>;
        /** @brief 按值读取会话统计；不借用 owner，也不触发关闭或取消。 */
        [[nodiscard]] auto Metrics() const noexcept -> SessionMetrics { return MakeMetrics(State_); }
        /** @brief 读取关闭已提交事实；实际交付和退休分别由 AwaitDelivery 与 Finalize 确认。 */
        [[nodiscard]] auto IsClosed() const noexcept -> bool { return State_->Closed.load(); }
        /** @brief 读取不能继续排空的事实；调用方必须保留资源并处理失败。 */
        [[nodiscard]] auto IsDrainBlocked() const noexcept -> bool { return Metrics().DrainBlocked; }
        /** @brief 读取关闭投递失败事实；失败实物保留于原 owner 和关闭存储。 */
        [[nodiscard]] auto IsCloseDispatchFailed() const noexcept -> bool { return State_->CloseDispatchFailed.load(); }
    private:
        /** @brief 只投递一次取消；调用方必须先记录取消来源。 */
        [[nodiscard]] auto RequestCancellation() -> std::expected<void, Failure>;
        friend class SessionRegistry;
        friend class SessionRegistryLifecycleTestAccess;
        friend class SessionRegistryTestAccess;

        /** @brief 仅供 SessionRegistry 在固定父 executor 上排队生命周期操作。 */
        [[nodiscard]] auto Executor() const -> std::optional<Net::any_io_executor>;

        std::shared_ptr<State> State_;
    };
}
