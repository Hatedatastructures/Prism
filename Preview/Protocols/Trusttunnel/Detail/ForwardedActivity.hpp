/**
 * @file ForwardedActivity.hpp
 * @brief TrustTunnel Transmission 装饰器的下层 close 回执。
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
     * @brief 等待下层真实退休后才归还装饰层 close 槽。
     * @details 本 owner 只持 activity，不持装饰层或 Transmission，避免所有权环。ReleaseChild
     *          将下层资源正式移交给调用者后，本层不再声称拥有下层的最终关闭权。Drain 保留
     *          History Failure 并继续验证 IsRetired。executor 固定为前门 executor；半关闭由 child
     *          原样转交，最终关闭仅由尚未 Release 的 child owner 执行。
     */
    class ForwardedActivity final : public Preview::Contract::CarrierActivity
    {
        struct State final
        {
            State(
                std::shared_ptr<Preview::Contract::CarrierActivity> Front,
                std::shared_ptr<Preview::Contract::CarrierActivity> Child,
                std::shared_ptr<Preview::Contract::CarrierCloseReceipt> Receipt)
                : Front(std::move(Front)), Child(std::move(Child)), Receipt(std::move(Receipt))
            {
            }

            std::shared_ptr<Preview::Contract::CarrierActivity> Front;
            std::shared_ptr<Preview::Contract::CarrierActivity> Child;
            std::shared_ptr<Preview::Contract::CarrierCloseReceipt> Receipt;
        };

    public:
        ForwardedActivity(
            std::shared_ptr<Preview::Contract::CarrierActivity> Front,
            std::shared_ptr<Preview::Contract::CarrierActivity> Child,
            std::shared_ptr<Preview::Contract::CarrierCloseReceipt> Receipt)
            : State_(std::make_shared<State>(
                  std::move(Front), std::move(Child), std::move(Receipt)))
        {
        }

        auto ReleaseChild() noexcept -> void
        {
            State_->Child.reset();
        }

        auto Seal() noexcept -> void override
        {
            State_->Front->Seal();
            if (State_->Child) State_->Child->Seal();
        }

        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override
        {
            return State_->Front->Executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return State_->Front->IsRetired() &&
                (!State_->Child || State_->Child->IsRetired());
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

            auto FirstFailure = Preview::Fault::Failure{};
            if (Value->Child)
            {
                Value->Child->Seal();
                const auto Child = co_await Value->Child->Drain();
                if (!Child) FirstFailure = Child.error();
                if (!Value->Child->IsRetired())
                {
                    if (FirstFailure.Succeeded())
                        FirstFailure = {Preview::Fault::Code::Blocked};
                    co_return std::unexpected(FirstFailure);
                }
            }

            Value->Receipt->ConfirmExternalClose();
            const auto Front = co_await Value->Front->Drain();
            if (!Front && FirstFailure.Succeeded()) FirstFailure = Front.error();
            if (!Value->Front->IsRetired() && FirstFailure.Succeeded())
                FirstFailure = {Preview::Fault::Code::Blocked};
            if (FirstFailure.Failed()) co_return std::unexpected(FirstFailure);
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        std::shared_ptr<State> State_;
    };
}