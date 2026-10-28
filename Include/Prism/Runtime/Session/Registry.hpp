/**
 * @file Registry.hpp
 * @brief 会话注册、取消与异步排空注册表
 * @details 注册表同时保存管理面值快照和 owner-held SessionControl。
 *          Registration token 负责 exactly-once 移除；Shutdown 拒绝新会话，
 *          取消并等待已登记 detached 操作真实结束。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Runtime/Session/Control.hpp>
#include <Prism/Runtime/Session/Registry/Model.hpp>
#include <Prism/Runtime/Session/Registry/Retirement.hpp>
#include <Prism/Runtime/Session/Registry/Storage.hpp>
#include <Prism/Runtime/Session/Registry/Stream/Catalog.hpp>

namespace Prism::Runtime
{

    class TcpListener;
    class SessionRegistryLifecycleTestAccess;
    class SessionRegistryTestAccess;

    /**
     * @class SessionRegistry
     * @brief 会话值快照与生命周期控制注册表
     */
    class SessionRegistry final
    {
    private:
        using EntryState = Detail::SessionRegistryEntry;
        using Record = Detail::SessionRegistryRecord;
        using RecordMap = Detail::SessionRegistryRecordMap;
        using State = Detail::SessionRegistryState;
        using Storage = Detail::SessionRegistryStorage;

    public:
        using MapT = std::map<std::uint64_t, SessionInfo>;
        using ErrorHook = std::function<void(std::uint64_t, Prism::Fault::Failure)>;
        using MetricsHook = std::function<void(std::uint64_t, const SessionMetrics &)>;

        /**
         * @class Registration
         * @brief 会话注册 token
         * @details token 只允许成功移除一次；可安全跨 detached 协程移动。
         */
        class Registration final
        {
        public:
            Registration() = default;

            Registration(const Registration &) = delete;
            auto operator=(const Registration &) -> Registration & = delete;

            Registration(Registration &&Other) noexcept;

            auto operator=(Registration &&Other) noexcept -> Registration &;

            ~Registration();

            [[nodiscard]] explicit operator bool() const noexcept
            {
                return Active_ && static_cast<bool>(State_);
            }

            /**
             * @brief exactly-once 移除注册
             */
            void Reset() noexcept;

            [[nodiscard]] auto Id() const noexcept -> std::uint64_t
            {
                return Id_;
            }

            /** @brief 在同一 registration token 上发布 admission 后值更新；已退休 token 拒绝写入。 */
            [[nodiscard]] auto Update(SessionInfo Info) -> bool;

        private:
            friend class SessionRegistry;

            Registration(std::shared_ptr<State> StateValue,
                         std::uint64_t Id,
                         std::shared_ptr<EntryState> EntryValue) noexcept;

            std::shared_ptr<State> State_;
            std::shared_ptr<EntryState> Entry_;
            std::uint64_t Id_{0};
            bool Active_{false};
        };

        SessionRegistry();

        SessionRegistry(const SessionRegistry &) = delete;
        auto operator=(const SessionRegistry &) -> SessionRegistry & = delete;

        /**
         * @brief 安装注册表级异常 hook
         */
        void SetErrorHook(ErrorHook Hook);

        /**
         * @brief 安装注册表级指标 hook
         */
        void SetMetricsHook(MetricsHook Hook);

        /**
         * @brief 注册一个带生命周期控制的会话
         * @param Info 会话信息
         * @param Control owner-held 控制器
         * @return 成功 token；Id 重复或已停机时返回空 token
         */
        [[nodiscard]] auto Register(SessionInfo Info,
                                    std::shared_ptr<SessionControl> Control) -> Registration;

        /**
         * @brief 移除指定会话
         * @return 存在并移除返回 true
         */
        auto Remove(std::uint64_t Id) -> bool;

        /**
         * @brief 请求指定会话取消
         * @return 找到活动控制器且取消请求成功提交时返回 true
         */
        auto Cancel(std::uint64_t Id) -> bool;

        /** @brief 取消并等待指定会话的 tracked Session owner 真实退栈。 */
        [[nodiscard]] auto CancelAndDrain(std::uint64_t Id)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 取消指定 AccountRuntime identity 的会话并逐个等待真实 owner 退栈。 */
        [[nodiscard]] auto CancelAccountAndDrain(
            Prism::AccountId Account,
            Prism::Account::AccountRuntimeIdentity Runtime)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;
        /** @brief 在对应 Runtime 的全部 lease 退休后移除其准入拒绝项，避免保留旧 owner key。 */
        [[nodiscard]] auto ReleaseAccountRuntimeGate(
            Prism::AccountId Account,
            Prism::Account::AccountRuntimeIdentity Runtime)
            -> std::expected<void, Prism::Fault::Failure>;
        /**
         * @brief 请求全部已注册会话取消
         * @return 成功提交取消请求的会话数
         */
        auto CancelAll() -> std::size_t;

        /**
         * @brief 原子标记停机并封止新注册
         * @details 非阻塞且不投递；不取消活动会话或等待物理排空。
         */
        void BeginShutdown() noexcept;

        /**
         * @brief 查找会话值
         */
        [[nodiscard]] auto Find(std::uint64_t Id, SessionInfo &Out) const -> bool;

        /** @brief 返回真实 SessionControl TaskRegistry 活动量；owner 不可用时明确为空。 */
        [[nodiscard]] auto ActiveTasks(Prism::SessionId Id) const noexcept
            -> std::optional<std::uint64_t>;

        /** @brief 按完整父身份复制真实 protocol stream 描述；不查询 task 表冒充流状态。 */
        [[nodiscard]] auto FindStream(
            const Prism::Contract::Ingress::StreamIdentity &Identity) const noexcept
            -> Prism::Contract::Ingress::StreamCatalogLookup;

        /** @brief 按完整父身份分页列出实际 live stream，不从 TaskRegistry 猜测 stream 项。 */
        [[nodiscard]] auto ListStreams(
            const Prism::Contract::Ingress::StreamListRequest &Request) const
            -> Prism::Contract::Ingress::StreamCatalogPage;

        /** @brief 校验完整父 scope 后取消单一 stream 并等待真实 child retirement。 */
        [[nodiscard]] auto ResetStreamAndDrain(
            Prism::Contract::Ingress::StreamResetRequest Request)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /**
         * @brief 当前注册数量
         */
        [[nodiscard]] auto Size() const -> std::size_t;

        /**
         * @brief 尚未物理压实的逻辑删除记录数
         */
        [[nodiscard]] auto PendingRemovals() const noexcept -> std::size_t;

        /**
         * @brief 独立值快照
         */
        [[nodiscard]] auto Snapshot() const -> std::shared_ptr<const MapT>;

        /**
         * @brief 等待当前已登记会话的 detached 操作结束
         */
        /** @brief 稳定快照保活控制器；逐会话等待真实退栈，任一失败立即保留注册记录。 */
        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;
        /** @brief 封止、取消与排空，Blocked 无论 active 数目都不能视作完成。 */
        [[nodiscard]] auto Shutdown()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

    private:
        friend class TcpListener;
        friend class SessionRegistryLifecycleTestAccess;
        friend class SessionRegistryTestAccess;

        /** @brief 封止注册并向当前活动会话请求 shutdown 取消；不等待物理排空。 */
        void RequestShutdown() noexcept;

        static auto Update(const std::shared_ptr<State> &StateValue,
                           Storage::UpdateRequest Request) -> bool;

        template <typename Mutator>
        void Update(Mutator &&Mutate)
        {
            while (true)
            {
                auto Current = State_->Records.load(std::memory_order_acquire);
                auto Next = Storage::CopyActive(*Current);
                Mutate(*Next);
                std::shared_ptr<const RecordMap> Published(std::move(Next));
                if (State_->Records.compare_exchange_weak(Current, Published,
                                                           std::memory_order_acq_rel,
                                                           std::memory_order_acquire))
                {
                    Storage::TryCompact(State_);
                    return;
                }
            }
        }

        std::shared_ptr<State> State_;
        Detail::SessionRegistryStreamCatalog StreamCatalog_;
    };

} // namespace Prism::Runtime
