/**
 * @file SessionRegistry.hpp
 * @brief 会话注册、取消与异步排空注册表
 * @details 注册表同时保存管理面值快照和 owner-held SessionControl。
 *          Registration token 负责 exactly-once 移除；Shutdown 拒绝新会话，
 *          取消并等待已登记 detached 操作真实结束。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstdint>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Runtime/SessionControl.hpp>

namespace Preview::Runtime
{

    /**
     * @struct SessionInfo
     * @brief 会话信息（值语义 POD，快照可整体拷贝）
     */
    struct SessionInfo
    {
        std::uint64_t Id{0};         ///< 会话 Id
        Preview::AccountId AccountId{}; ///< typed 账户身份
        std::string identity{};      ///< 用户标识
        std::string peer{};          ///< 远端地址
        std::string Target{};        ///< 目标地址
        std::uint16_t Protocol{0};   ///< 检测协议
        std::uint64_t StartedAt{0};  ///< 启动时刻
    };

    /**
     * @class SessionRegistry
     * @brief 会话值快照与生命周期控制注册表
     */
    class SessionRegistry final
    {
    private:
        struct Record
        {
            SessionInfo Info;
            std::shared_ptr<SessionControl> Control;
        };

        using RecordMap = std::map<std::uint64_t, Record>;

        struct State
        {
            std::atomic<std::shared_ptr<const RecordMap>> Records{
                std::make_shared<const RecordMap>()};
            std::atomic<bool> ShuttingDown{false};
            std::function<void(std::uint64_t, Preview::Fault::Code, std::exception_ptr)> OnError;
            std::function<void(std::uint64_t, const SessionMetrics &)> OnMetrics;
        };

    public:
        using MapT = std::map<std::uint64_t, SessionInfo>;
        using ErrorHook = std::function<void(std::uint64_t, Preview::Fault::Code, std::exception_ptr)>;
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
                : State_(std::move(Other.State_)), Id_(Other.Id_), Active_(Other.Active_)
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
                try
                {
                    RemoveRecord(State_, Id_);
                }
                catch (...)
                {
                }
                State_.reset();
                Id_ = 0;
            }

            [[nodiscard]] auto Id() const noexcept -> std::uint64_t
            {
                return Id_;
            }

        private:
            friend class SessionRegistry;

            Registration(std::shared_ptr<State> StateValue, std::uint64_t Id)
                : State_(std::move(StateValue)), Id_(Id), Active_(true)
            {
            }

            std::shared_ptr<State> State_;
            std::uint64_t Id_{0};
            bool Active_{false};
        };

        SessionRegistry() : State_(std::make_shared<State>()) {}

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
            if (!Control || State_->ShuttingDown.load(std::memory_order_acquire))
            {
                return {};
            }

            const auto Id = Info.Id;
            while (true)
            {
                if (State_->ShuttingDown.load(std::memory_order_acquire))
                {
                    return {};
                }
                auto Current = State_->Records.load(std::memory_order_acquire);
                if (Current->find(Id) != Current->end())
                {
                    return {};
                }
                auto Next = std::make_shared<RecordMap>(*Current);
                Next->emplace(Id, Record{std::move(Info), Control});
                std::shared_ptr<const RecordMap> Published(std::move(Next));
                if (State_->Records.compare_exchange_weak(Current, Published,
                                                           std::memory_order_acq_rel,
                                                           std::memory_order_acquire))
                {
                    if (State_->ShuttingDown.load(std::memory_order_acquire))
                    {
                        RemoveRecord(State_, Id);
                        return {};
                    }
                    InstallHooks(State_, Id, Control);
                    return Registration(State_, Id);
                }
            }
        }

        /**
         * @brief 兼容旧调用的无控制信息注册
         */
        void Put(SessionInfo Info)
        {
            Update([Info = std::move(Info)](RecordMap &Records)
                   {
                       const auto It = Records.find(Info.Id);
                       std::shared_ptr<SessionControl> Control;
                       if (It != Records.end())
                       {
                           Control = It->second.Control;
                       }
                       Records[Info.Id] = Record{Info, std::move(Control)};
                   });
        }

        /**
         * @brief 移除指定会话
         * @return 存在并移除返回 true
         */
        auto Remove(std::uint64_t Id) -> bool
        {
            return RemoveRecord(State_, Id);
        }

        /**
         * @brief 请求指定会话取消
         */
        auto Cancel(std::uint64_t Id) -> bool
        {
            const auto Current = State_->Records.load(std::memory_order_acquire);
            const auto It = Current->find(Id);
            if (It == Current->end() || !It->second.Control)
            {
                return false;
            }
            It->second.Control->Cancel();
            return true;
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
                if (RecordValue.Control)
                {
                    RecordValue.Control->Cancel();
                    ++Count;
                }
            }
            return Count;
        }

        /**
         * @brief 标记停机并立即请求全部会话取消
         * @details 非阻塞；供 listener 析构使用。不会等待 detached 操作，
         *          但会阻止后续 Register，并保证已发布控制器收到 Cancel。
         */
        void BeginShutdown() noexcept
        {
            State_->ShuttingDown.store(true, std::memory_order_release);
            (void)CancelAll();
        }

        /**
         * @brief 查找会话值
         */
        [[nodiscard]] auto Find(std::uint64_t Id, SessionInfo &Out) const -> bool
        {
            const auto Current = State_->Records.load(std::memory_order_acquire);
            const auto It = Current->find(Id);
            if (It == Current->end())
            {
                return false;
            }
            Out = It->second.Info;
            return true;
        }

        /**
         * @brief 当前注册数量
         */
        [[nodiscard]] auto Size() const -> std::size_t
        {
            return State_->Records.load(std::memory_order_acquire)->size();
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
                Result->emplace(Id, RecordValue.Info);
            }
            return Result;
        }

        /**
         * @brief 等待当前已登记会话的 detached 操作结束
         */
        [[nodiscard]] auto Drain() -> boost::asio::awaitable<void>
        {
            const auto Current = State_->Records.load(std::memory_order_acquire);
            for (const auto &[Id, RecordValue] : *Current)
            {
                (void)Id;
                if (RecordValue.Control)
                {
                    co_await RecordValue.Control->Drain();
                }
            }
        }

        /**
         * @brief 进入停机、取消并排空全部已登记会话
         * @details 设置停机标志后 Register 失败；循环读取快照以覆盖
         *          停机竞态中已发布的最后一个注册。
         */
        [[nodiscard]] auto Shutdown() -> boost::asio::awaitable<void>
        {
            BeginShutdown();
            while (true)
            {
                const auto Current = State_->Records.load(std::memory_order_acquire);
                std::vector<std::shared_ptr<SessionControl>> Controls;
                Controls.reserve(Current->size());
                for (const auto &[Id, RecordValue] : *Current)
                {
                    (void)Id;
                    if (RecordValue.Control)
                    {
                        Controls.push_back(RecordValue.Control);
                    }
                }

                for (const auto &Control : Controls)
                {
                    Control->Cancel();
                }

                bool Pending = false;
                for (const auto &Control : Controls)
                {
                    co_await Control->Drain();
                }

                const auto After = State_->Records.load(std::memory_order_acquire);
                for (const auto &[Id, RecordValue] : *After)
                {
                    (void)Id;
                    if (RecordValue.Control && RecordValue.Control->Metrics().Active != 0)
                    {
                        Pending = true;
                        break;
                    }
                }
                if (!Pending)
                {
                    ClearRecords(State_);
                    co_return;
                }
            }
        }

    private:
        template <typename Mutator>
        void Update(Mutator &&Mutate)
        {
            while (true)
            {
                auto Current = State_->Records.load(std::memory_order_acquire);
                auto Next = std::make_shared<RecordMap>(*Current);
                Mutate(*Next);
                std::shared_ptr<const RecordMap> Published(std::move(Next));
                if (State_->Records.compare_exchange_weak(Current, Published,
                                                           std::memory_order_acq_rel,
                                                           std::memory_order_acquire))
                {
                    return;
                }
            }
        }

        static auto RemoveRecord(const std::shared_ptr<State> &StateValue, std::uint64_t Id) -> bool
        {
            while (true)
            {
                auto Current = StateValue->Records.load(std::memory_order_acquire);
                if (Current->find(Id) == Current->end())
                {
                    return false;
                }
                auto Next = std::make_shared<RecordMap>(*Current);
                Next->erase(Id);
                std::shared_ptr<const RecordMap> Published(std::move(Next));
                if (StateValue->Records.compare_exchange_weak(Current, Published,
                                                               std::memory_order_acq_rel,
                                                               std::memory_order_acquire))
                {
                    return true;
                }
            }
        }

        static auto ClearRecords(const std::shared_ptr<State> &StateValue) -> void
        {
            while (true)
            {
                auto Current = StateValue->Records.load(std::memory_order_acquire);
                if (Current->empty())
                {
                    return;
                }
                auto Empty = std::make_shared<const RecordMap>();
                if (StateValue->Records.compare_exchange_weak(Current, Empty,
                                                               std::memory_order_acq_rel,
                                                               std::memory_order_acquire))
                {
                    return;
                }
            }
        }

        static auto InstallHooks(const std::shared_ptr<State> &StateValue,
                                 std::uint64_t Id,
                                 const std::shared_ptr<SessionControl> &Control) -> void
        {
            const std::weak_ptr<State> WeakState = StateValue;
            Control->SetErrorHook(
                [WeakState, Id](Preview::Fault::Code Code, std::exception_ptr Failure)
                {
                    if (const auto StateValue = WeakState.lock(); StateValue && StateValue->OnError)
                    {
                        try
                        {
                            StateValue->OnError(Id, Code, std::move(Failure));
                        }
                        catch (...)
                        {
                        }
                    }
                });
            Control->SetMetricsHook(
                [WeakState, Id](const SessionMetrics &Metrics)
                {
                    if (const auto StateValue = WeakState.lock(); StateValue && StateValue->OnMetrics)
                    {
                        try
                        {
                            StateValue->OnMetrics(Id, Metrics);
                        }
                        catch (...)
                        {
                        }
                    }
                });
        }

        std::shared_ptr<State> State_;
    };

} // namespace Preview::Runtime
