/**
 * @file ProtocolActivity.hpp
 * @brief 协议数据面 Run 的真实准入与退栈 owner。
 * @details 本类型只保存协议 Run 的活动预约，不拥有 socket、连接或半关闭权。
 *          executor 在构造时固定为协议实际 pump 所在的执行域；协议 owner 在 Run
 *          完成所有子操作后归还 Reservation，外部调用者再通过 Drain 等待退栈。
 */
#pragma once

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <expected>
#include <memory>
#include <stdexcept>
#include <utility>

namespace Prism::Protocols
{
    namespace Net = boost::asio;

    /**
     * @brief 具体协议数据面的一次 Run 预约及其 CarrierActivity 实现。
     * @details `TryBegin` 成功后，Reservation 必须覆盖整个真实 Run；正常完成调用
     *          `Complete`，异常从 owner 逃逸则标记 Blocked，避免 Drain 把未确认的
     *          退栈误报为成功。该 owner 不代替协议的 TaskRegistry，也不关闭任何载体。
     */
    class ProtocolActivity final : public Prism::Contract::CarrierActivity
    {
        struct State final
        {
            explicit State(Net::any_io_executor Value)
                : Executor(RequireExecutor(std::move(Value))),
                  Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(Executor)),
                  Barrier(Reclaimer) {}

            [[nodiscard]] static auto RequireExecutor(Net::any_io_executor Value)
                -> Net::any_io_executor
            {
                if (!Value) throw std::invalid_argument("ProtocolActivity requires an executor");
                return Value;
            }

            Net::any_io_executor Executor;
            std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
            Prism::Lifecycle::DrainBarrier Barrier;
            Prism::Fault::FailureState Failure;
        };

    public:
        class Reservation final
        {
        public:
            Reservation(Reservation&& Other) noexcept
                : State_(std::move(Other.State_)) {}
            Reservation(const Reservation&) = delete;
            auto operator=(Reservation&& Other) noexcept -> Reservation&
            {
                if (this == &Other) return *this;
                Abandon();
                State_ = std::move(Other.State_);
                return *this;
            }
            ~Reservation() { Abandon(); }

            /** @brief 协议已完成所有真实 I/O 和子任务退栈，归还一次活动预约。 */
            auto Complete() noexcept -> void
            {
                if (!State_) return;
                State_->Barrier.Leave();
                State_.reset();
            }

        private:
            friend class ProtocolActivity;
            explicit Reservation(std::shared_ptr<State> Value) : State_(std::move(Value)) {}
            auto Abandon() noexcept -> void
            {
                // Reservation 只记录活动事实；协议资源仍由当前 Run/caller 的
                // 原有 owner 持有，不把它伪装成这里的关闭 owner。
                if (!State_) return;
                State_->Failure.TrySet({Prism::Fault::Code::Blocked});
                State_->Barrier.Block();
                State_->Barrier.Leave();
                State_.reset();
            }
            std::shared_ptr<State> State_;
        };

        explicit ProtocolActivity(Net::any_io_executor Executor)
            : State_(std::make_shared<State>(std::move(Executor))) {}

        [[nodiscard]] auto TryBegin() -> std::expected<Reservation, Prism::Fault::Failure>
        {
            if (State_->Failure.Load().Failed())
                return std::unexpected(State_->Failure.Load());
            if (!State_->Barrier.Enter())
            {
                if (State_->Failure.Load().Failed())
                    return std::unexpected(State_->Failure.Load());
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            return Reservation(State_);
        }

        /** @brief 任意线程封止新的 Run；不关闭真实协议载体。 */
        auto Seal() noexcept -> void override { State_->Barrier.Seal(); }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        { return State_->Executor; }

        /** @brief 只证明所属 Run 预约真实退栈；不推断借用载体已经关闭。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return State_->Barrier.IsSealed() && State_->Barrier.Active() == 0 &&
            !State_->Barrier.IsBlocked(); }

        /** @brief 等待已预约的 Run 退栈，并保留任何结构性 blocked 事实。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            State_->Barrier.Seal();
            auto Result = co_await State_->Barrier.Drain();
            if (!Result) co_return std::unexpected(Result.error());
            const auto Failure = State_->Failure.Load();
            if (Failure.Failed()) co_return std::unexpected(Failure);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /** @brief 记录无法确认真实退栈的结构性失败，保留活动 owner。 */
        auto Block() noexcept -> void
        {
            State_->Failure.TrySet({Prism::Fault::Code::Blocked});
            State_->Barrier.Block();
        }

    private:
        std::shared_ptr<State> State_;
    };
}
