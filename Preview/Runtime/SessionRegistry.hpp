/**
 * @file SessionRegistry.hpp
 * @brief 会话注册、取消与异步排空注册表
 * @details 注册表同时保存管理面值快照和 owner-held SessionControl。
 *          Registration token 负责 exactly-once 移除；Shutdown 拒绝新会话，
 *          取消并等待已登记 detached 操作真实结束。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Contract/Ingress/StreamCatalog.hpp>
#include <Preview/Runtime/SessionControl.hpp>
#include <Preview/Runtime/SessionRegistryModel.hpp>
#include <Preview/Runtime/SessionRegistryRetirement.hpp>
#include <Preview/Runtime/SessionRegistryStorage.hpp>
#include <Preview/Runtime/SessionRegistryMetadata.hpp>
#include <Preview/Runtime/SessionRegistryStreamCatalog.hpp>

namespace Preview::Runtime
{

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
        using ErrorHook = std::function<void(std::uint64_t, Preview::Fault::Failure)>;
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

            Registration(Registration &&Other) noexcept
                : State_(std::move(Other.State_)), Entry_(std::move(Other.Entry_)),
                  Id_(Other.Id_), Active_(Other.Active_)
            {
                Other.Id_ = 0;
                Other.Active_ = false;
            }

            auto operator=(Registration &&Other) noexcept -> Registration &
            {
                if (this != &Other)
                {
                    Reset();
                    State_ = std::move(Other.State_);
                    Entry_ = std::move(Other.Entry_);
                    Id_ = Other.Id_;
                    Active_ = Other.Active_;
                    Other.Id_ = 0;
                    Other.Active_ = false;
                }
                return *this;
            }

            ~Registration()
            {
                Reset();
            }

            [[nodiscard]] explicit operator bool() const noexcept
            {
                return Active_ && static_cast<bool>(State_);
            }

            /**
             * @brief exactly-once 移除注册
             */
            void Reset() noexcept
            {
                if (!Active_ || !State_)
                {
                    return;
                }
                Active_ = false;
                SessionRegistry::Storage::RetireRecord(Entry_);
                Detail::SessionRegistryRetirement::AcknowledgeRetirement(Entry_);
                State_.reset();
                Entry_.reset();
                Id_ = 0;
            }

            [[nodiscard]] auto Id() const noexcept -> std::uint64_t
            {
                return Id_;
            }

            /** @brief 在同一 registration token 上发布 admission 后值更新；已退休 token 拒绝写入。 */
            [[nodiscard]] auto Update(SessionInfo Info) -> bool
            {
                if (!Active_ || !State_ || Info.Id != Id_)
                {
                    return false;
                }
                return SessionRegistry::Update(
                    State_, Storage::UpdateRequest{Entry_, Id_, std::move(Info)});
            }

        private:
            friend class SessionRegistry;

            Registration(std::shared_ptr<State> StateValue,
                         std::uint64_t Id,
                         std::shared_ptr<EntryState> EntryValue)
                : State_(std::move(StateValue)), Entry_(std::move(EntryValue)),
                  Id_(Id), Active_(true)
            {
            }

            std::shared_ptr<State> State_;
            std::shared_ptr<EntryState> Entry_;
            std::uint64_t Id_{0};
            bool Active_{false};
        };

        SessionRegistry() : State_(std::make_shared<State>()), StreamCatalog_(State_) {}

        SessionRegistry(const SessionRegistry &) = delete;
        auto operator=(const SessionRegistry &) -> SessionRegistry & = delete;

        /**
         * @brief 安装注册表级异常 hook
         */
        void SetErrorHook(ErrorHook Hook)
        {
            State_->OnError = std::move(Hook);
        }

        /**
         * @brief 安装注册表级指标 hook
         */
        void SetMetricsHook(MetricsHook Hook)
        {
            State_->OnMetrics = std::move(Hook);
        }

        /**
         * @brief 注册一个带生命周期控制的会话
         * @param Info 会话信息
         * @param Control owner-held 控制器
         * @return 成功 token；Id 重复或已停机时返回空 token
         */
        [[nodiscard]] auto Register(SessionInfo Info,
                                    std::shared_ptr<SessionControl> Control) -> Registration
        {
            if (!Control || Storage::AccountRegistrationDenied(State_, Info))
            {
                return {};
            }

            const auto Id = Info.Id;
            const auto Executor = Control->Executor();
            if (!Executor)
            {
                return {};
            }
            const auto Entry = std::make_shared<EntryState>(Control, *Executor);
            while (true)
            {
                if (Storage::AccountRegistrationDenied(State_, Info))
                {
                    return {};
                }
                auto Current = State_->Records.load(std::memory_order_seq_cst);
                const auto Existing = Current->find(Id);
                if (Existing != Current->end() &&
                    !Existing->second.Entry->Removed.load(std::memory_order_seq_cst))
                {
                    return {};
                }
                auto Next = Storage::CopyActive(*Current);
                Next->emplace(Id, Record{Info, Entry});
                std::shared_ptr<const RecordMap> Published(std::move(Next));
                if (State_->Records.compare_exchange_weak(Current, Published, std::memory_order_seq_cst))
                {
                    if (Storage::AccountRegistrationDenied(State_, Info))
                    {
                        Storage::RetireRecord(Entry);
                        Detail::SessionRegistryRetirement::AcknowledgeRejectedRegistration(Entry);
                        return {};
                    }
                    auto Installed = Storage::InstallHooks(State_, Id, Entry);
                    if (!Installed)
                    {
                        Storage::RetireRecord(Entry);
                        Detail::SessionRegistryRetirement::AcknowledgeRejectedRegistration(Entry);
                        Storage::TryCompact(State_);
                        return {};
                    }
                    if (Storage::AccountRegistrationDenied(State_, Info))
                    {
                        Storage::RetireRecord(Entry);
                        Detail::SessionRegistryRetirement::AcknowledgeRejectedRegistration(Entry);
                        return {};
                    }
                    Entry->RegistrationPublished.store(true, std::memory_order_release);
                    return Registration(State_, Id, Entry);
                }
            }
        }

        /**
         * @brief 移除指定会话
         * @return 存在并移除返回 true
         */
        auto Remove(std::uint64_t Id) -> bool
        {
            const auto Current = State_->Records.load(std::memory_order_acquire);
            const auto It = Current->find(Id);
            return It != Current->end() && Storage::RetireRecord(It->second.Entry);
        }

        /**
         * @brief 请求指定会话取消
         */
        auto Cancel(std::uint64_t Id) -> bool
        {
            const auto Current = State_->Records.load(std::memory_order_acquire);
            const auto It = Current->find(Id);
            if (It == Current->end())
            {
                return false;
            }
            const auto Control = Storage::GetActiveControl(It->second.Entry);
            if (!Control)
            {
                return false;
            }
            Control->Cancel();
            return true;
        }

        /** @brief 取消并等待指定会话的 tracked Session owner 真实退栈。 */
        [[nodiscard]] auto CancelAndDrain(std::uint64_t Id)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            const auto Current = State_->Records.load(std::memory_order_acquire);
            const auto It = Current->find(Id);
            if (It == Current->end())
            {
                co_return std::expected<void, Preview::Fault::Failure>{};
            }
            const auto Control = Storage::GetActiveControl(It->second.Entry);
            if (!Control)
            {
                if (It->second.Entry->Removed.load(std::memory_order_acquire))
                {
                    co_return co_await Detail::SessionRegistryRetirement::AwaitRetirement(It->second.Entry);
                }
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            const auto Cancelled = Control->Cancel();
            const auto Drained = co_await Control->Drain();
            if (!Cancelled)
            {
                co_return std::unexpected(Cancelled.error());
            }
            if (!Drained)
            {
                co_return std::unexpected(Drained.error());
            }
            co_return co_await Detail::SessionRegistryRetirement::AwaitRetirement(It->second.Entry);
        }

        /** @brief 取消指定 AccountRuntime identity 的会话并逐个等待真实 owner 退栈。 */
        [[nodiscard]] auto CancelAccountAndDrain(
            Preview::AccountId Account,
            Preview::Account::AccountRuntimeIdentity Runtime)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            if (!Account || !Runtime.IsValid())
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            const auto Denied = Storage::DenyAccountRuntime(
                State_, Account.Value(), Runtime);
            if (!Denied)
            {
                co_return std::unexpected(Denied.error());
            }
            const auto Current = State_->Records.load(std::memory_order_seq_cst);
            struct PendingOwner final
            {
                std::shared_ptr<EntryState> Entry;
                std::shared_ptr<SessionControl> Control;
            };
            std::vector<PendingOwner> Owners;
            std::optional<Preview::Fault::Failure> FirstFailure;
            for (const auto &[Id, RecordValue] : *Current)
            {
                (void)Id;
                if (RecordValue.Info.AccountId != Account ||
                    RecordValue.Info.AccountRuntime != Runtime)
                {
                    continue;
                }
                auto Control = Storage::GetActiveControl(RecordValue.Entry);
                if (!Control && !RecordValue.Entry->Removed.load(std::memory_order_acquire))
                {
                    if (!FirstFailure)
                    {
                        FirstFailure = Preview::Fault::Failure{
                            Preview::Fault::Code::Blocked};
                    }
                    continue;
                }
                Owners.push_back(PendingOwner{RecordValue.Entry, std::move(Control)});
            }

            for (const auto &Owner : Owners)
            {
                if (!Owner.Control)
                {
                    continue;
                }
                const auto Cancelled = Owner.Control->Cancel();
                if (!Cancelled && !FirstFailure)
                {
                    FirstFailure = Cancelled.error();
                }
            }
            for (const auto &Owner : Owners)
            {
                if (!Owner.Control)
                {
                    continue;
                }
                const auto Drained = co_await Owner.Control->Drain();
                if (!Drained && !FirstFailure)
                {
                    FirstFailure = Drained.error();
                }
            }
            if (FirstFailure)
            {
                co_return std::unexpected(*FirstFailure);
            }
            for (const auto &Owner : Owners)
            {
                const auto Retired = co_await Detail::SessionRegistryRetirement::AwaitRetirement(Owner.Entry);
                if (!Retired && !FirstFailure)
                {
                    FirstFailure = Retired.error();
                }
            }
            if (FirstFailure)
            {
                co_return std::unexpected(*FirstFailure);
            }
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        /** @brief 在对应 Runtime 的全部 lease 退休后移除其准入拒绝项，避免保留旧 owner key。 */
        [[nodiscard]] auto ReleaseAccountRuntimeGate(
            Preview::AccountId Account,
            Preview::Account::AccountRuntimeIdentity Runtime)
            -> std::expected<void, Preview::Fault::Failure>
        {
            return Storage::RemoveAccountRuntimeDenial(
                State_, Account.Value(), Runtime);
        }
        /**
         * @brief 请求全部已注册会话取消
         * @return 发出取消请求的会话数
         */
        auto CancelAll() -> std::size_t
        {
            std::size_t Count = 0;
            const auto Current = State_->Records.load(std::memory_order_acquire);
            for (const auto &[Id, RecordValue] : *Current)
            {
                (void)Id;
                if (const auto Control = Storage::GetActiveControl(RecordValue.Entry))
                {
                    Control->Cancel();
                    ++Count;
                }
            }
            return Count;
        }

        /**
         * @brief 原子标记停机并封止新注册
         * @details 非阻塞且不投递；供 listener 析构使用。真正取消和排空由显式 Shutdown 执行。
         */
        void BeginShutdown() noexcept
        {
            State_->ShuttingDown.store(true, std::memory_order_release);
        }

        /**
         * @brief 查找会话值
         */
        [[nodiscard]] auto Find(std::uint64_t Id, SessionInfo &Out) const -> bool
        {
            const auto Current = State_->Records.load(std::memory_order_acquire);
            const auto It = Current->find(Id);
            if (It == Current->end() ||
                It->second.Entry->Removed.load(std::memory_order_seq_cst))
            {
                return false;
            }
            Out = It->second.Info;
            return true;
        }

        /** @brief 返回真实 SessionControl TaskRegistry 活动量；owner 不可用时明确为空。 */
        [[nodiscard]] auto ActiveTasks(Preview::SessionId Id) const noexcept
            -> std::optional<std::uint64_t>
        {
            return Detail::SessionRegistryMetadata::ActiveTasks(State_, Id);
        }

        /** @brief 按完整父身份复制真实 protocol stream 描述；不查询 task 表冒充流状态。 */
        [[nodiscard]] auto FindStream(
            const Preview::Contract::Ingress::StreamIdentity &Identity) const noexcept
            -> Preview::Contract::Ingress::StreamCatalogLookup
        {
            return StreamCatalog_.Find(Identity);
        }

        /** @brief 按完整父身份分页列出实际 live stream，不从 TaskRegistry 猜测 stream 项。 */
        [[nodiscard]] auto ListStreams(
            const Preview::Contract::Ingress::StreamListRequest &Request) const
            -> Preview::Contract::Ingress::StreamCatalogPage
        {
            return StreamCatalog_.List(Request);
        }

        /** @brief 校验完整父 scope 后取消单一 stream 并等待真实 child retirement。 */
        [[nodiscard]] auto ResetStreamAndDrain(
            Preview::Contract::Ingress::StreamResetRequest Request)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            return StreamCatalog_.ResetAndDrain(std::move(Request));
        }

        /**
         * @brief 当前注册数量
         */
        [[nodiscard]] auto Size() const -> std::size_t
        {
            std::size_t Count = 0;
            const auto Current = State_->Records.load(std::memory_order_acquire);
            for (const auto &[Id, RecordValue] : *Current)
            {
                (void)Id;
                if (!RecordValue.Entry->Removed.load(std::memory_order_seq_cst))
                {
                    ++Count;
                }
            }
            return Count;
        }

        /**
         * @brief 尚未物理压实的逻辑删除记录数
         */
        [[nodiscard]] auto PendingRemovals() const noexcept -> std::size_t
        {
            std::size_t Count = 0;
            const auto Current = State_->Records.load(std::memory_order_acquire);
            for (const auto &[Id, RecordValue] : *Current)
            {
                (void)Id;
                if (RecordValue.Entry->Removed.load(std::memory_order_seq_cst))
                {
                    ++Count;
                }
            }
            return Count;
        }

        /**
         * @brief 独立值快照
         */
        [[nodiscard]] auto Snapshot() const -> std::shared_ptr<const MapT>
        {
            auto Result = std::make_shared<MapT>();
            const auto Current = State_->Records.load(std::memory_order_acquire);
            for (const auto &[Id, RecordValue] : *Current)
            {
                if (!RecordValue.Entry->Removed.load(std::memory_order_seq_cst))
                {
                    Result->emplace(Id, RecordValue.Info);
                }
            }
            return Result;
        }

        /**
         * @brief 等待当前已登记会话的 detached 操作结束
         */
        /** @brief 稳定快照保活控制器；逐会话等待真实退栈，任一失败立即保留注册记录。 */
        [[nodiscard]] auto Drain() -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            const auto Current = State_->Records.load(std::memory_order_acquire);
            for (const auto& [Id, Record] : *Current)
            {
                (void)Id;
                if (auto Control = Storage::GetActiveControl(Record.Entry))
                {
                    auto Result = co_await Control->Drain();
                    if (!Result) co_return Result;
                }
            }
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        /** @brief 封止、取消与排空，Blocked 无论 active 数目都不能视作完成。 */
        [[nodiscard]] auto Shutdown() -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            BeginShutdown();
            const auto Current = State_->Records.load(std::memory_order_acquire);
            for (const auto& [Id, Record] : *Current)
            {
                (void)Id;
                if (auto Control = Storage::GetActiveControl(Record.Entry)) Control->Cancel();
            }
            auto Result = co_await Drain();
            if (!Result) co_return Result;
            Storage::ClearRecords(State_);
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
    private:
        friend class SessionRegistryTestAccess;
        static auto Update(const std::shared_ptr<State> &StateValue,
                           Storage::UpdateRequest Request) -> bool
        {
            return Storage::Update(StateValue, std::move(Request));
        }

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

} // namespace Preview::Runtime
