/**
 * @file StreamAdapterActivity.hpp
 * @brief 聚合 QUIC stream adapter 前门与单流 provider 的真实退休回执。
 * @details Seal 同时封止前门和 provider 准入；Drain 等待两者，无默认成功或 child 回退。
 */
#pragma once

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <expected>
#include <memory>
#include <stdexcept>
#include <utility>

namespace Prism::Quic::Detail
{
    class StreamAdapterActivity final : public Prism::Contract::CarrierActivity,
        public std::enable_shared_from_this<StreamAdapterActivity>
    {
        struct State final
        {
            State(std::shared_ptr<Prism::Contract::CarrierActivity> ParentValue,
                  std::shared_ptr<Prism::Contract::CarrierActivity> ProviderValue)
                : Parent(std::move(ParentValue)), Provider(std::move(ProviderValue))
            {
            }
            std::shared_ptr<Prism::Contract::CarrierActivity> Parent;
            std::shared_ptr<Prism::Contract::CarrierActivity> Provider;
        };

    public:
        StreamAdapterActivity(std::shared_ptr<Prism::Contract::CarrierActivity> Parent,
                              std::shared_ptr<Prism::Contract::CarrierActivity> Provider)
            : State_(MakeState(std::move(Parent), std::move(Provider)))
        {
        }

        auto Seal() noexcept -> void override
        {
            State_->Parent->Seal();
            State_->Provider->Seal();
        }

        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override
        {
            return State_->Parent->Executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return State_->Parent->IsRetired() && State_->Provider->IsRetired();
        }

        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            return DrainState(State_);
        }

    private:
        [[nodiscard]] static auto MakeState(
            std::shared_ptr<Prism::Contract::CarrierActivity> Parent,
            std::shared_ptr<Prism::Contract::CarrierActivity> Provider) -> std::shared_ptr<State>
        {
            if (!Parent || !Provider)
            {
                throw std::invalid_argument("QUIC stream activity requires both real owners");
            }
            return std::make_shared<State>(std::move(Parent), std::move(Provider));
        }

        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            const auto Parent = co_await Owner->Parent->Drain();
            const auto Provider = co_await Owner->Provider->Drain();
            if (!Parent)
            {
                co_return std::unexpected(Parent.error());
            }
            if (!Provider)
            {
                co_return std::unexpected(Provider.error());
            }
            if (!Owner->Parent->IsRetired() || !Owner->Provider->IsRetired())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        std::shared_ptr<State> State_;
    };
}
