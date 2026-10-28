/**
 * @file Activity.hpp
 * @brief TrustTunnel Transmission 装饰器的下层 close 回执。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Io/CarrierCloseReceipt.hpp>

#include <memory>
#include <expected>
#include <utility>

namespace Prism::Trusttunnel::Detail
{
    /**
     * @brief 等待下层真实退休后才归还装饰层 close 槽。
     * @details 本 owner 只持 activity，不持装饰层或 Transmission，避免所有权环。ReleaseChild
     *          将下层资源正式移交给调用者后，本层不再声称拥有下层的最终关闭权。Drain 保留
     *          History Failure 并继续验证 IsRetired。executor 固定为前门 executor；半关闭由 child
     *          原样转交，最终关闭仅由尚未 Release 的 child owner 执行。
     */
    class ForwardedActivity final : public Prism::Contract::CarrierActivity
    {
        struct State final
        {
            State(
                std::shared_ptr<Prism::Contract::CarrierActivity> Front,
                std::shared_ptr<Prism::Contract::CarrierActivity> Child,
                std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt)
                : Front(std::move(Front)), Child(std::move(Child)), Receipt(std::move(Receipt))
            {
            }

            std::shared_ptr<Prism::Contract::CarrierActivity> Front;
            std::shared_ptr<Prism::Contract::CarrierActivity> Child;
            std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt;
        };

    public:
        ForwardedActivity(
            std::shared_ptr<Prism::Contract::CarrierActivity> Front,
            std::shared_ptr<Prism::Contract::CarrierActivity> Child,
            std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt);

        auto ReleaseChild() noexcept -> void;

        /** @brief 只封止当前装饰层；子层在其 Close 预约提交后由子层 owner 封止。 */
        auto Seal() noexcept -> void override;

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
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override;

    private:
        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Value)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

        std::shared_ptr<State> State_;
    };
}
