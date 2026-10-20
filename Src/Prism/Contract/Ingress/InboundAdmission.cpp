/** @file InboundAdmission.cpp @brief 入站准入与失败资源退休实现。 */
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include "Detail/AdmissionRetirementState.hpp"

#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>

#include <exception>
#include <utility>

namespace Prism::Contract
{
    InboundAdmission::InboundAdmission(InboundAdmission&& Other) noexcept
        : State_(std::move(Other.State_))
    {
    }

    auto InboundAdmission::operator=(InboundAdmission&& Other) noexcept -> InboundAdmission&
    {
        if (this != &Other)
        {
            Abandon();
            State_ = std::move(Other.State_);
        }
        return *this;
    }

    InboundAdmission::~InboundAdmission() noexcept
    {
        Abandon();
    }

    auto InboundAdmission::Prepare(Prism::SharedTransmission Inbound)
        -> Net::awaitable<InboundAdmission::PrepareResult>
    {
        if (!Inbound)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }

        Prism::Fault::Failure Failure;
        std::shared_ptr<RetirementState> Owner;
        try
        {
            const auto Executor = Inbound->Executor();
            auto Context = Prism::Executor::ContextOwner::Find(Executor);
            auto Storage = Prism::Executor::ContextOwner::Storage(Executor);
            auto Reclaimer = std::make_shared<Prism::Executor::ExecutorReclaimer>(
                Net::make_strand(Executor));
            Owner = std::make_shared<RetirementState>(
                Inbound, AdmissionRetirementEnvironment{
                    std::move(Context), std::move(Storage), std::move(Reclaimer)});
        }
        catch (...)
        {
            Failure = FailureFromException(std::current_exception());
        }

        if (Owner)
        {
            co_return InboundAdmission(std::move(Owner));
        }

        // Prepare 先于协议 I/O 与子资源所有者创建；票据分配失败时，由载体预建的
        // ControlOwner 和 Activity 负责关闭与排空这一条入站资源，不再依赖新分配。
        const auto Cleanup = co_await RetireUnreserved(Inbound);
        // 保留准入拒绝的完整首因；未完成的清理由 ControlOwner/IoActivity 保留，
        // 不将另一条清理失败拼入本次 Failure.Native。
        PreserveFailure(Failure, Cleanup.Error);
        co_return std::unexpected(Failure);
    }

    auto InboundAdmission::Admit(ProtocolDataPlane Plane) -> Net::awaitable<InboundAdmission::Outcome>
    {
        if (!State_)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }

        auto Failure = Validate(Plane);
        if (!Failure.Failed())
        {
            State_->Transfer();
            co_return Plane;
        }

        State_->Attach(std::move(Plane));
        Failure = co_await State_->Retire(Failure);
        co_return std::unexpected(Failure);
    }

    auto InboundAdmission::Reject(Prism::Fault::Failure Failure)
        -> Net::awaitable<InboundAdmission::Outcome>
    {
        if (!State_)
        {
            if (Failure.Failed()) co_return std::unexpected(Failure);
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (!Failure.Failed())
        {
            Failure = {Prism::Fault::Code::InvalidArgument};
        }
        Failure = co_await Retire(Failure);
        co_return std::unexpected(Failure);
    }

    auto InboundAdmission::Reject(
        ProtocolDataPlane Plane,
        Prism::Fault::Failure Failure) -> Net::awaitable<InboundAdmission::Outcome>
    {
        if (!State_)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (!Failure.Failed())
        {
            Failure = {Prism::Fault::Code::InvalidArgument};
        }
        State_->Attach(std::move(Plane));
        Failure = co_await Retire(Failure);
        co_return std::unexpected(Failure);
    }

    auto InboundAdmission::Retire(Prism::Fault::Failure Failure)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        if (!Failure.Failed())
        {
            Failure = {Prism::Fault::Code::InvalidArgument};
        }
        if (!State_)
        {
            co_return Failure;
        }
        co_return co_await State_->Retire(Failure);
    }

    auto InboundAdmission::Release() noexcept -> void
    {
        if (State_) State_->Transfer();
        State_.reset();
    }

    auto InboundAdmission::Track(const Prism::SharedTransmission& Transport)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!State_)
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        return State_->Track(Transport);
    }

    auto InboundAdmission::RootCreateOwner() const noexcept
        -> std::shared_ptr<MuxRootCreateOwner>
    {
        return State_;
    }

    auto InboundAdmission::ExceptionFailure(std::exception_ptr Exception) noexcept
        -> Prism::Fault::Failure
    {
        return FailureFromException(std::move(Exception));
    }

    InboundAdmission::InboundAdmission(std::shared_ptr<RetirementState> State)
        : State_(std::move(State))
    {
    }

    auto InboundAdmission::RetireUnreserved(const Prism::SharedTransmission& Inbound)
        -> Net::awaitable<AdmissionRetirementResult>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        bool CancelAttempted = false;
        bool CloseAttempted = false;
        co_return co_await RetireAdmissionTransport(
            Inbound, CancelAttempted, CloseAttempted);
    }

    auto InboundAdmission::PreserveFailure(
        Prism::Fault::Failure& Primary,
        const Prism::Fault::Failure& Secondary) noexcept -> void
    {
        PreserveAdmissionFailure(Primary, Secondary);
    }

    auto InboundAdmission::FailureFromException(std::exception_ptr Exception) noexcept
        -> Prism::Fault::Failure
    {
        return AdmissionFailureFromException(std::move(Exception));
    }

    auto InboundAdmission::Abandon() noexcept -> void
    {
        if (!State_ || State_->IsRetired())
        {
            State_.reset();
            return;
        }
        State_->Storage_->Retain(State_);
        State_->RequestRetirement();
        State_.reset();
    }
}
