/**
 * @file InboundAdmission.hpp
 * @brief 预预约接入失败退休 owner 与唯一数据面发布入口。
 */
#pragma once

#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Contract/Ingress/AdmissionRetirement.hpp>
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <boost/asio/this_coro.hpp>
#include <exception>
#include <memory>
#include <utility>

namespace Prism::Contract
{
    /**
     * @class InboundAdmission
     * @brief 在握手前预约并拥有一次入站退休能力。
     * @details Prepare 预建 intrusive ClosingResource 节点；异常/拒绝必须显式 Reject。
     *          未显式交接时析构保留同一 owner 并请求原 executor 重试。
     */
    class InboundAdmission final
    {
        using RetirementState = AdmissionRetirementState;

    public:
        using Outcome = AcceptOutcome;
        using PrepareResult = std::expected<InboundAdmission, Prism::Fault::Failure>;

        InboundAdmission() = delete;
        InboundAdmission(const InboundAdmission&) = delete;
        auto operator=(const InboundAdmission&) -> InboundAdmission& = delete;

        InboundAdmission(InboundAdmission&& Other) noexcept
            : State_(std::move(Other.State_))
        {
        }

        auto operator=(InboundAdmission&& Other) noexcept -> InboundAdmission&
        {
            if (this != &Other)
            {
                Abandon();
                State_ = std::move(Other.State_);
            }
            return *this;
        }

        ~InboundAdmission() noexcept
        {
            Abandon();
        }

        /**
         * @brief 在协议读取或握手前建立可重试关闭 owner；预约失败不启动 handshake。
         */
        [[nodiscard]] static auto Prepare(Prism::SharedTransmission Inbound)
            -> Net::awaitable<PrepareResult>
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

            // Prepare 先于协议 I/O 与子 owner 创建；票据分配失败时，由载体预建的
            // ControlOwner 和 Activity 负责关闭与排空这一条入站资源，不再依赖新分配。
            const auto Cleanup = co_await RetireUnreserved(Inbound);
            // 保留准入拒绝的完整首因；未完成的清理由 ControlOwner/IoActivity 保留，
            // 不将另一条清理失败拼入本次 Failure.Native。
            PreserveFailure(Failure, Cleanup.Error);
            co_return std::unexpected(Failure);
        }

        /**
         * @brief 校验并发布唯一数据面；非法值先 close/drain，失败继续保留 ticket。
         */
        [[nodiscard]] auto Admit(ProtocolDataPlane Plane) -> Net::awaitable<Outcome>
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

        /**
         * @brief 退休握手/识别拒绝时的输入并保留正式首因。
         */
        [[nodiscard]] auto Reject(Prism::Fault::Failure Failure) -> Net::awaitable<Outcome>
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

        /** @brief 协议已构造子 owner 但后续应答失败时一并退休 plane 与 lease。 */
        [[nodiscard]] auto Reject(
            ProtocolDataPlane Plane,
            Prism::Fault::Failure Failure) -> Net::awaitable<Outcome>
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

        /**
         * @brief 完成非数据面工厂拒绝前的真实 carrier close/drain。
         * @details 返回拒绝 cause；退休不完整时同一 ticket 保留实物与 executor，供原域重试。
         */
        [[nodiscard]] auto Retire(Prism::Fault::Failure Failure)
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

        /**
         * @brief 嵌套 StreamFactory 已接管后释放本层预约。
         */
        auto Release() noexcept -> void
        {
            if (State_) State_->Transfer();
            State_.reset();
        }

        /** @brief 将握手期间新增的有限层级载体登记到预预约 owner。 */
        [[nodiscard]] auto Track(const Prism::SharedTransmission& Transport)
            -> std::expected<void, Prism::Fault::Failure>
        {
            if (!State_)
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            return State_->Track(Transport);
        }

        /** @brief 返回握手前登记的同一 mux 根创建票据，不分配或复制 retirement state。 */
        [[nodiscard]] auto RootCreateOwner() const noexcept
            -> std::shared_ptr<MuxRootCreateOwner>
        {
            return State_;
        }

        /** @brief 在 admission 边界保留 system/Boost exception 的原生 cause。 */
        [[nodiscard]] static auto ExceptionFailure(std::exception_ptr Exception) noexcept
            -> Prism::Fault::Failure
        {
            return FailureFromException(std::move(Exception));
        }

    private:
        explicit InboundAdmission(std::shared_ptr<RetirementState> State)
            : State_(std::move(State))
        {
        }

        [[nodiscard]] static auto RetireUnreserved(
            const Prism::SharedTransmission& Inbound) -> Net::awaitable<AdmissionRetirementResult>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            bool CancelAttempted = false;
            bool CloseAttempted = false;
            co_return co_await RetireAdmissionTransport(
                Inbound, CancelAttempted, CloseAttempted);
        }

        static auto PreserveFailure(
            Prism::Fault::Failure& Primary,
            const Prism::Fault::Failure& Secondary) noexcept -> void
        {
            PreserveAdmissionFailure(Primary, Secondary);
        }

        static auto FailureFromException(std::exception_ptr Exception) noexcept
            -> Prism::Fault::Failure
        {
            return AdmissionFailureFromException(std::move(Exception));
        }

        auto Abandon() noexcept -> void
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
        std::shared_ptr<RetirementState> State_;
    };
}
