/** @file ActivityGroup.cpp @brief 活动组合与关闭转交回执的私有实现。 */
#include <Prism/Transport/ActivityGroupFactory.hpp>

#include <boost/asio/this_coro.hpp>

#include <atomic>
#include <memory>
#include <utility>
#include <vector>

namespace Prism::Transport::Detail
{
    class ActivityGroup final : public Contract::CarrierActivity
    {
        struct State final
        {
            std::shared_ptr<Contract::CarrierActivity> Parent;
            std::vector<std::shared_ptr<Contract::CarrierActivity>> Children;
        };

    public:
        ActivityGroup(std::shared_ptr<Contract::CarrierActivity> Parent,
                      std::vector<std::shared_ptr<Contract::CarrierActivity>> Children)
            : State_(std::make_shared<State>(
                  State{std::move(Parent), std::move(Children)}))
        {
        }

        auto Seal() noexcept -> void override
        {
            State_->Parent->Seal();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return IsStateRetired(*State_);
        }

        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override
        {
            return State_->Parent->Executor();
        }

        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            return DrainState(State_);
        }

    private:
        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            auto Result = co_await Owner->Parent->Drain();
            if (!Owner->Parent->IsRetired())
            {
                if (Result)
                {
                    Result = std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                }
                co_return Result;
            }
            for (const auto &Child : Owner->Children)
            {
                Child->Seal();
                const auto ChildResult = co_await Child->Drain();
                if (!ChildResult && Result)
                {
                    Result = std::unexpected(ChildResult.error());
                }
            }
            if (Result && !IsStateRetired(*Owner))
            {
                Result = std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            co_return Result;
        }

        [[nodiscard]] static auto IsStateRetired(const State &Owner) noexcept -> bool
        {
            if (!Owner.Parent || !Owner.Parent->IsRetired()) return false;
            for (const auto &Child : Owner.Children)
            {
                if (!Child || !Child->IsRetired()) return false;
            }
            return true;
        }

        std::shared_ptr<State> State_;
    };

    class ForwardActivity final : public Contract::CarrierActivity
    {
        struct State final
        {
            State(std::shared_ptr<Contract::CarrierActivity> Own,
                  std::shared_ptr<Contract::CarrierActivity> Inner)
                : Parent(std::move(Own)), Child(std::move(Inner))
            {
            }

            std::shared_ptr<Contract::CarrierActivity> Parent;
            std::shared_ptr<Contract::CarrierActivity> Child;
            std::atomic<bool> CloseForwarded{false};
        };

    public:
        ForwardActivity(std::shared_ptr<Contract::CarrierActivity> Parent,
                        std::shared_ptr<Contract::CarrierActivity> Child)
            : State_(std::make_shared<State>(std::move(Parent), std::move(Child)))
        {
        }

        auto RequireChildDrain() noexcept -> void
        {
            State_->CloseForwarded.store(true, std::memory_order_release);
        }

        auto Seal() noexcept -> void override
        {
            State_->Parent->Seal();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            if (!State_->Parent || !State_->Parent->IsRetired()) return false;
            if (!State_->CloseForwarded.load(std::memory_order_acquire)) return true;
            return State_->Child && State_->Child->IsRetired();
        }

        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override
        {
            return State_->Parent->Executor();
        }

        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Fault::Failure>> override
        {
            return DrainState(State_);
        }

    private:
        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Owner)
            -> boost::asio::awaitable<std::expected<void, Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            auto Result = co_await Owner->Parent->Drain();
            if (Owner->CloseForwarded.load(std::memory_order_acquire))
            {
                const auto ChildResult = co_await Owner->Child->Drain();
                if (!ChildResult && Result)
                {
                    Result = std::unexpected(ChildResult.error());
                }
            }
            co_return Result;
        }

        std::shared_ptr<State> State_;
    };
}

namespace Prism::Transport
{
    auto MakeActivityGroup(
        std::shared_ptr<Contract::CarrierActivity> Parent,
        std::vector<std::shared_ptr<Contract::CarrierActivity>> Children)
        -> std::shared_ptr<Contract::CarrierActivity>
    {
        return std::make_shared<Detail::ActivityGroup>(
            std::move(Parent), std::move(Children));
    }

    ForwardActivityOwner::ForwardActivityOwner(
        std::shared_ptr<Contract::CarrierActivity> Parent,
        std::shared_ptr<Contract::CarrierActivity> Child)
        : State_(std::make_shared<Detail::ForwardActivity>(
              std::move(Parent), std::move(Child)))
    {
    }

    auto ForwardActivityOwner::Activity() const noexcept
        -> std::shared_ptr<Contract::CarrierActivity>
    {
        return State_;
    }

    auto ForwardActivityOwner::RequireChildDrain() noexcept -> void
    {
        State_->RequireChildDrain();
    }
}
