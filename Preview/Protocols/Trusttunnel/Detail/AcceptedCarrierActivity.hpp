/**
 * @file AcceptedCarrierActivity.hpp
 * @brief TrustTunnel accepted carrier 的真实退栈回执。
 */
#pragma once

#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <Preview/Contract/Io/CarrierCloseReceipt.hpp>

#include <boost/asio/this_coro.hpp>

#include <memory>
#include <utility>

namespace Preview::Trusttunnel::Detail
{
    /**
     * @brief 把 accepted carrier owner 与外层 Transmission close receipt 绑定为一个物理回执。
     * @details 本 owner 持有单一 carrier owner 与外层前门 activity，不持有 wrapper Transmission。
     *          Drain 保留首个完整 Failure，并继续检查每一层的 IsRetired；历史错误不会阻止已真实
     *          完成的层交付外部 close receipt。半关闭仍由 H2 Transport 的 WriteShutdown 负责。
     *          实际 executor 固定于 carrier owner；owner 关闭 TLS、writer、driver 与 stream。
     */
    template<class Owner>
    class AcceptedCarrierActivity final : public Preview::Contract::CarrierActivity
    {
        struct State final
        {
            State(
                std::shared_ptr<Preview::Contract::CarrierActivity> Front,
                std::shared_ptr<Owner> OwnerValue,
                std::shared_ptr<Preview::Contract::CarrierCloseReceipt> ReceiptValue)
                : Front(std::move(Front)), OwnerHandle(std::move(OwnerValue)),
                  Receipt(std::move(ReceiptValue))
            {
            }

            std::shared_ptr<Preview::Contract::CarrierActivity> Front;
            std::shared_ptr<Owner> OwnerHandle;
            std::shared_ptr<Preview::Contract::CarrierCloseReceipt> Receipt;
        };

    public:
        AcceptedCarrierActivity(
            std::shared_ptr<Preview::Contract::CarrierActivity> Front,
            std::shared_ptr<Owner> OwnerValue,
            std::shared_ptr<Preview::Contract::CarrierCloseReceipt> ReceiptValue)
            : State_(std::make_shared<State>(
                  std::move(Front), std::move(OwnerValue), std::move(ReceiptValue)))
        {
        }

        auto Seal() noexcept -> void override
        {
            State_->Front->Seal();
        }

        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override
        {
            return State_->OwnerHandle->Executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return State_->OwnerHandle->IsRetired() && State_->Front->IsRetired();
        }

        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            return DrainState(State_);
        }

    private:
        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Value)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            co_await boost::asio::this_coro::reset_cancellation_state(
                boost::asio::disable_cancellation());

            Value->Front->Seal();
            const auto Layers = co_await Value->OwnerHandle->Drain();
            auto FirstFailure = Preview::Fault::Failure{};
            if (!Layers) FirstFailure = Layers.error();
            if (!Value->OwnerHandle->IsRetired())
            {
                if (FirstFailure.Succeeded())
                    FirstFailure = {Preview::Fault::Code::Blocked};
                co_return std::unexpected(FirstFailure);
            }

            Value->Receipt->ConfirmExternalClose();
            const auto Front = co_await Value->Front->Drain();
            if (!Front && FirstFailure.Succeeded())
                FirstFailure = Front.error();
            if (!Value->Front->IsRetired() && FirstFailure.Succeeded())
                FirstFailure = {Preview::Fault::Code::Blocked};

            if (FirstFailure.Failed())
                co_return std::unexpected(FirstFailure);
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        std::shared_ptr<State> State_;
    };
}