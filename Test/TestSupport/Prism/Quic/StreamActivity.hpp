/**
 * @file StreamActivity.hpp
 * @brief QUIC StreamProvider 测试替身的操作预约与同步关闭回执。
 * @details 测试替身只有完成本地同步收尾后才发布关闭回执；未关闭时 Drain 返回 Blocked。
 */
#pragma once

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <atomic>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Testing::Quic
{
    class StreamProviderActivity final : public Prism::Contract::CarrierActivity,
        public std::enable_shared_from_this<StreamProviderActivity>
    {
    public:
        class Operation final
        {
        public:
            Operation() noexcept = default;
            Operation(const Operation&) = delete;
            auto operator=(const Operation&) -> Operation& = delete;
            Operation(Operation&& Other) noexcept
                : Owner_(std::move(Other.Owner_)), Entered_(std::exchange(Other.Entered_, false))
            {
            }
            ~Operation()
            {
                if (Entered_ && Owner_)
                {
                    Owner_->Operations_.Leave();
                }
            }
            [[nodiscard]] explicit operator bool() const noexcept { return Entered_; }

        private:
            friend class StreamProviderActivity;
            explicit Operation(std::shared_ptr<StreamProviderActivity> Owner)
                : Owner_(std::move(Owner)), Entered_(true)
            {
            }
            std::shared_ptr<StreamProviderActivity> Owner_;
            bool Entered_{false};
        };

        explicit StreamProviderActivity(boost::asio::any_io_executor Executor)
            : StreamProviderActivity(
                  std::move(Executor),
                  std::shared_ptr<Prism::Contract::CarrierActivity>{})
        {
        }

        StreamProviderActivity(
            boost::asio::any_io_executor Executor,
            std::shared_ptr<Prism::Contract::CarrierActivity> Delegate)
            : Delegate_(std::move(Delegate)),
              Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(std::move(Executor))),
              Operations_(Reclaimer_)
        {
        }

        [[nodiscard]] auto BeginOperation() -> Operation
        {
            if (!Operations_.Enter())
            {
                return {};
            }
            return Operation(shared_from_this());
        }

        auto CompleteClose() noexcept -> void
        {
            Operations_.Seal();
            if (Delegate_)
            {
                Delegate_->Seal();
            }
            CloseDelivered_.store(true, std::memory_order_release);
        }

        auto FailClose(Prism::Fault::Failure Failure) noexcept -> void
        {
            Failure_.TrySet(Failure);
            Operations_.Block();
        }

        auto Seal() noexcept -> void override
        {
            Operations_.Seal();
            if (Delegate_)
            {
                Delegate_->Seal();
            }
        }

        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override
        {
            return Reclaimer_->Executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return CloseDelivered_.load(std::memory_order_acquire) &&
                   Operations_.IsSealed() && Operations_.Active() == 0 && !Operations_.IsBlocked() &&
                   (!Delegate_ || Delegate_->IsRetired());
        }

        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            return DrainOwned(shared_from_this());
        }

    private:
        [[nodiscard]] static auto DrainOwned(std::shared_ptr<StreamProviderActivity> Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            const auto CloseFailure = Owner->Failure_.Load();
            if (CloseFailure.Failed())
            {
                co_return std::unexpected(CloseFailure);
            }
            if (!Owner->CloseDelivered_.load(std::memory_order_acquire))
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            const auto Drained = co_await Owner->Operations_.Drain();
            std::expected<void, Prism::Fault::Failure> DelegateDrained{};
            if (Owner->Delegate_)
            {
                DelegateDrained = co_await Owner->Delegate_->Drain();
            }
            if (!Drained)
            {
                co_return std::unexpected(Drained.error());
            }
            if (!DelegateDrained)
            {
                co_return std::unexpected(DelegateDrained.error());
            }
            if (!Owner->IsRetired())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            const auto FailureValue = Owner->Failure_.Load();
            if (FailureValue.Failed())
            {
                co_return std::unexpected(FailureValue);
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        std::shared_ptr<Prism::Contract::CarrierActivity> Delegate_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        Prism::Lifecycle::DrainBarrier Operations_;
        Prism::Fault::FailureState Failure_;
        std::atomic<bool> CloseDelivered_{false};
    };
}
