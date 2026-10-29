/**
 * @file ProtocolActivity.cpp
 * @brief 协议 Run 准入预约与 drain 实现。
 */

#include <Prism/Protocols/Common/ProtocolActivity.hpp>

#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>

#include <memory>
#include <stdexcept>
#include <utility>

namespace Prism::Protocols
{
    struct ProtocolActivity::State final
    {
        explicit State(Net::any_io_executor Value)
            : Executor(RequireExecutor(std::move(Value))),
              Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(Executor)),
              Barrier(Reclaimer)
        {
        }

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

    ProtocolActivity::Reservation::Reservation(Reservation&& Other) noexcept
        : State_(std::move(Other.State_))
    {
    }

    auto ProtocolActivity::Reservation::operator=(Reservation&& Other) noexcept
        -> Reservation&
    {
        if (this == &Other) return *this;
        Abandon();
        State_ = std::move(Other.State_);
        return *this;
    }

    ProtocolActivity::Reservation::~Reservation()
    {
        Abandon();
    }

    auto ProtocolActivity::Reservation::Complete() noexcept -> void
    {
        if (!State_) return;
        State_->Barrier.Leave();
        State_.reset();
    }

    ProtocolActivity::Reservation::Reservation(std::shared_ptr<State> Value)
        : State_(std::move(Value))
    {
    }

    auto ProtocolActivity::Reservation::Abandon() noexcept -> void
    {
        // Reservation 只记录活动事实；协议资源仍由当前 Run/caller 的
        // 原有 owner 持有，不把它伪装成这里的关闭 owner。
        if (!State_) return;
        State_->Failure.Record({Prism::Fault::Code::Blocked});
        State_->Barrier.Block();
        State_->Barrier.Leave();
        State_.reset();
    }

    ProtocolActivity::ProtocolActivity(Net::any_io_executor Executor)
        : State_(std::make_shared<State>(std::move(Executor)))
    {
    }

    [[nodiscard]] auto ProtocolActivity::TryBegin()
        -> std::expected<Reservation, Prism::Fault::Failure>
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

    auto ProtocolActivity::Seal() noexcept -> void
    {
        State_->Barrier.Seal();
    }

    [[nodiscard]] auto ProtocolActivity::Executor() const -> Net::any_io_executor
    {
        return State_->Executor;
    }

    [[nodiscard]] auto ProtocolActivity::IsRetired() const noexcept -> bool
    {
        return State_->Barrier.IsSealed() && State_->Barrier.Active() == 0 &&
               !State_->Barrier.IsBlocked();
    }

    [[nodiscard]] auto ProtocolActivity::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        State_->Barrier.Seal();
        auto Result = co_await State_->Barrier.Drain();
        if (!Result) co_return std::unexpected(Result.error());
        const auto Failure = State_->Failure.Load();
        if (Failure.Failed()) co_return std::unexpected(Failure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto ProtocolActivity::Block() noexcept -> void
    {
        State_->Failure.Record({Prism::Fault::Code::Blocked});
        State_->Barrier.Block();
    }
} // namespace Prism::Protocols
