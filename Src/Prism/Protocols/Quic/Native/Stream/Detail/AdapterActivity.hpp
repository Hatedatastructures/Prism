/**
 * @file AdapterActivity.hpp
 * @brief QUIC stream adapter 的私有活动生命周期声明。
 */
#pragma once

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <expected>
#include <memory>

namespace Prism::Quic::Detail
{

    /** @brief 汇合 adapter 前门与单流 provider 的真实退休回执。 */
    class StreamAdapterActivity final : public Prism::Contract::CarrierActivity,
        public std::enable_shared_from_this<StreamAdapterActivity>
    {
        struct State;

    public:
        StreamAdapterActivity(
            std::shared_ptr<Prism::Contract::CarrierActivity> Parent,
            std::shared_ptr<Prism::Contract::CarrierActivity> Provider);
        ~StreamAdapterActivity() override;

        auto Seal() noexcept -> void override;
        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override;
        [[nodiscard]] auto IsRetired() const noexcept -> bool override;
        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override;

    private:
        [[nodiscard]] static auto MakeState(
            std::shared_ptr<Prism::Contract::CarrierActivity> Parent,
            std::shared_ptr<Prism::Contract::CarrierActivity> Provider)
            -> std::shared_ptr<State>;
        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

        std::shared_ptr<State> State_;
    };

} // namespace Prism::Quic::Detail
