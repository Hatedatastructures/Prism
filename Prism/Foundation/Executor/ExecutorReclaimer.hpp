/** @file ExecutorReclaimer.hpp @brief 将拥有型动作交付到唯一原 executor。 */
#pragma once
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <expected>
#include <atomic>
#include <exception>
#include <memory>
#include <type_traits>
#include <utility>
namespace Prism::Executor
{
    /** @brief 冷创建的交付 owner；普通拒绝返回 Failure，第三方致命异常交线程入口。
     * @details 动作按值转移至 Asio，无临时 std::function。调用方预先保留关闭实物；
     * 交付不代表 I/O 已退栈。隔离不调用动作，最终关闭仍属于实物原 executor。
     */
    class ExecutorReclaimer final
    {
        /** @brief 外部 io_context 只借用至调用方 Drain；识别正式 strand 包装，不创建 owner。 */
        [[nodiscard]] static auto FindIo(const boost::asio::any_io_executor& Executor) noexcept
            -> boost::asio::io_context*
        {
            if (auto Value = Executor.target<boost::asio::io_context::executor_type>()) return &Value->context();
            if (auto Value = Executor.target<boost::asio::strand<boost::asio::any_io_executor>>())
                return FindIo(Value->get_inner_executor());
            if (auto Value = Executor.target<boost::asio::strand<boost::asio::io_context::executor_type>>())
                return &Value->get_inner_executor().context();
            return nullptr;
        }
        struct State final
        {
            explicit State(boost::asio::any_io_executor Value)
                : Context(ContextOwner::Find(Value)), Executor(std::move(Value)),
                  RegisteredContext(!Context.expired()), ExternalIo(FindIo(Executor)) {}
            std::weak_ptr<ContextOwner> Context;
            boost::asio::any_io_executor Executor;
            bool RegisteredContext;
            boost::asio::io_context* ExternalIo;
            std::atomic<std::size_t> Pending{0};
            std::atomic<std::size_t> QuarantinedCount{0};
            std::atomic<std::size_t> ActionFailures{0};
            std::atomic<bool> Quarantined{false};
        };
        /** @brief 投递/handler 析构均精确释放一次 pending，不将失败伪装成功。 */
        struct PendingReservation final
        {
            explicit PendingReservation(std::shared_ptr<State> Value) : Owner(std::move(Value))
            { Owner->Pending.fetch_add(1); }
            PendingReservation(PendingReservation&& Other) noexcept : Owner(std::move(Other.Owner)) {}
            PendingReservation(const PendingReservation&) = delete;
            ~PendingReservation() { if (Owner) Owner->Pending.fetch_sub(1); }
            std::shared_ptr<State> Owner;
        };
    public:
        explicit ExecutorReclaimer(boost::asio::any_io_executor Value)
            : State_(std::make_shared<State>(std::move(Value))) {}
        ExecutorReclaimer(const ExecutorReclaimer&) = delete;
        auto operator=(const ExecutorReclaimer&) -> ExecutorReclaimer& = delete;
        /** @brief 按值接管动作至原 executor；拒绝不执行并返回 Blocked；资源由预建关闭 owner 保活。 */
        template<class Action>
        [[nodiscard]] auto Post(Action Work) -> std::expected<void, Prism::Fault::Failure>
        {
            if (!CanDispatch()) return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            auto StateValue = State_;
            PendingReservation Reservation(StateValue);
            if (StateValue->Quarantined.load(std::memory_order_acquire))
            {
                StateValue->QuarantinedCount.fetch_add(1, std::memory_order_relaxed);
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            try
            {
                boost::asio::post(StateValue->Executor,
                    [StateValue, Work = std::move(Work), Reservation = std::move(Reservation)]() mutable noexcept
                    { RunPostedAction(StateValue, Work); });
            }
            catch (...)
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            return {};
        }
        /** @brief 任意线程只封止动作；不关闭实物、不宣称排空。 */
        auto Quarantine() noexcept -> void { State_->Quarantined.store(true); }
        /** @brief 读取交付封止状态，不表示实际资源已经退休。 */
        [[nodiscard]] auto IsQuarantined() const noexcept -> bool { return State_->Quarantined.load(); }
        /** @brief 读取绑定 context 当前是否可运行；调用方仍须处理提交竞态与最终交付。 */
        [[nodiscard]] auto CanDispatch() const noexcept -> bool
        {
            if (State_->Quarantined.load()) return false;
            if (!State_->RegisteredContext)
            {
                if (State_->ExternalIo) return !State_->ExternalIo->stopped();
                return true;
            }
            auto Context = State_->Context.lock();
            return Context && Context->CanDispatch();
        }
        /** @brief 读取尚未释放的预约数；零计数不替代资源 owner 的实际 I/O 排空。 */
        [[nodiscard]] auto Pending() const noexcept -> std::size_t { return State_->Pending.load(); }
        /** @brief 读取被隔离的动作数；对应资源仍归各自关闭 owner。 */
        [[nodiscard]] auto QuarantinedCount() const noexcept -> std::size_t { return State_->QuarantinedCount.load(); }
        /** @brief 读取动作异常数；异常被限制在交付边界，不穿透 executor。 */
        [[nodiscard]] auto ActionFailures() const noexcept -> std::size_t { return State_->ActionFailures.load(); }
        /** @brief 按值返回绑定 executor，调用方保持其 context 至全部 I/O 退栈。 */
        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor { return State_->Executor; }
    private:
        template<class Action>
        static auto RunPostedAction(const std::shared_ptr<State>& StateValue, Action& Work) noexcept -> void
        {
            if (StateValue->Quarantined.load(std::memory_order_acquire))
            {
                StateValue->QuarantinedCount.fetch_add(1, std::memory_order_relaxed);
                QuarantineAction(Work);
                return;
            }
            try { Work(); }
            catch (...)
            {
                StateValue->ActionFailures.fetch_add(1, std::memory_order_relaxed);
                if (const auto Context = StateValue->Context.lock(); Context && Context->Fatal)
                    Context->Fatal->Publish(std::current_exception());
            }
        }

        template<class Action>
        static auto QuarantineAction(Action& Work) noexcept -> void
        {
            if constexpr (requires(Action& Value) { Value.OnQuarantine(); })
            {
                try { Work.OnQuarantine(); }
                catch (...) {}
            }
        }
        std::shared_ptr<State> State_;
    };
}
