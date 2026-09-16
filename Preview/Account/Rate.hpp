/**
 * @file Rate.hpp
 * @brief 账户速率策略与无锁分片
 * @details StrictGlobal 使用一个共享原子分片；WorkerSharded 为每个 worker
 *          使用独立分片，并通过整数上取整给出可计算的最大超额。重配置时
 *          只有相同 WindowMilliseconds 的策略才复用打包窗口状态；时间尺度
 *          变化会在新的策略代次下创建全新状态，旧策略代次由
 *          AccountRuntimeState 的代次校验拒绝。
 */
#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <utility>
#include <variant>
#include <vector>

namespace Preview::Account
{

    struct UnlimitedRatePolicy
    {
    };

    struct StrictGlobalRatePolicy
    {
        std::uint64_t LimitPerWindow{0};
        std::uint64_t WindowMilliseconds{1000};
    };

    struct WorkerShardedRatePolicy
    {
        static constexpr std::uint32_t MaxWorkerCount{4096};

        std::uint32_t WorkerCount{1};
        std::uint64_t GlobalLimitPerWindow{0};
        std::uint64_t WindowMilliseconds{1000};

        [[nodiscard]] auto PerWorkerLimit() const noexcept -> std::uint64_t
        {
            if (WorkerCount == 0 || GlobalLimitPerWindow == 0)
            {
                return 0;
            }
            return GlobalLimitPerWindow / WorkerCount +
                   static_cast<std::uint64_t>(GlobalLimitPerWindow % WorkerCount != 0);
        }

        [[nodiscard]] auto MaxOvershoot() const noexcept -> std::uint64_t
        {
            const auto PerWorker = PerWorkerLimit();
            if (PerWorker == 0 || WorkerCount == 0)
            {
                return 0;
            }
            const auto WorkerCountValue = static_cast<std::uint64_t>(WorkerCount);
            if (PerWorker > std::numeric_limits<std::uint64_t>::max() / WorkerCountValue)
            {
                return std::numeric_limits<std::uint64_t>::max();
            }
            return PerWorker * WorkerCountValue - GlobalLimitPerWindow;
        }
    };

    using RatePolicy = std::variant<UnlimitedRatePolicy, StrictGlobalRatePolicy,
                                    WorkerShardedRatePolicy>;

    struct RateRequest
    {
        std::uint32_t WorkerId{0};
        std::uint64_t Now{0};
        std::uint32_t Units{1};
    };

    struct RateShardOptions
    {
        std::uint64_t Limit{0};
        std::uint64_t WindowMilliseconds{1000};
    };

    class RateShard final
    {
    private:
        struct TimestampState final
        {
            std::atomic<std::uint64_t> LastNow{0};
        };

        struct SharedState final
        {
            std::atomic<std::uint64_t> Packed{0};
            std::shared_ptr<TimestampState> Timestamp_;

            SharedState() : Timestamp_(std::make_shared<TimestampState>())
            {
            }

            explicit SharedState(std::shared_ptr<TimestampState> Timestamp)
                : Timestamp_(std::move(Timestamp))
            {
            }
        };

    public:
        explicit RateShard(RateShardOptions Options)
            : RateShard(Options, std::make_shared<SharedState>())
        {
        }

        [[nodiscard]] auto TryConsume(RateRequest Request) const noexcept -> bool
        {
            if (Invalid_ || Request.Now == 0)
            {
                return false;
            }
            const auto Window = Request.Now / WindowMilliseconds_;
            if (Window > KMaxWindow || !AcceptTimestamp(Request.Now))
            {
                return false;
            }
            if (Request.Units == 0 || Limit_ == 0)
            {
                return true;
            }
            if (static_cast<std::uint64_t>(Request.Units) > Limit_)
            {
                return false;
            }

            const auto WindowTag = static_cast<std::uint32_t>(Window);
            auto State = State_->Packed.load(std::memory_order_relaxed);
            while (true)
            {
                const auto CurrentWindow = static_cast<std::uint32_t>(State >> KUsedBits);
                const auto CurrentUsed = State & KMaxUnits;
                if (CurrentWindow > WindowTag)
                {
                    return false;
                }
                if (CurrentWindow != WindowTag)
                {
                    const auto Next = (static_cast<std::uint64_t>(WindowTag) << KUsedBits) |
                                      static_cast<std::uint64_t>(Request.Units);
                    if (State_->Packed.compare_exchange_weak(State, Next,
                                                              std::memory_order_relaxed,
                                                              std::memory_order_relaxed))
                    {
                        return true;
                    }
                    continue;
                }

                if (CurrentUsed > KMaxUnits - static_cast<std::uint64_t>(Request.Units))
                {
                    return false;
                }
                const auto Next = (static_cast<std::uint64_t>(WindowTag) << KUsedBits) |
                                  (CurrentUsed + static_cast<std::uint64_t>(Request.Units));
                if (CurrentUsed + static_cast<std::uint64_t>(Request.Units) > Limit_)
                {
                    return false;
                }
                if (State_->Packed.compare_exchange_weak(State, Next,
                                                          std::memory_order_relaxed,
                                                          std::memory_order_relaxed))
                {
                    return true;
                }
            }
        }

    private:
        static constexpr std::uint64_t KUsedBits{32};
        static constexpr std::uint64_t KMaxUnits{0xFFFFFFFFULL};
        static constexpr std::uint64_t KMaxWindow{0xFFFFFFFFULL};

        RateShard(RateShardOptions Options, std::shared_ptr<SharedState> State)
            : Limit_(Options.Limit),
              WindowMilliseconds_(Options.WindowMilliseconds == 0 ? 1 : Options.WindowMilliseconds),
              Invalid_(Options.Limit > KMaxUnits || Options.WindowMilliseconds == 0),
              State_(std::move(State))
        {
        }

        [[nodiscard]] auto AcceptTimestamp(const std::uint64_t Now) const noexcept -> bool
        {
            auto Previous = State_->Timestamp_->LastNow.load(std::memory_order_relaxed);
            while (true)
            {
                if (Now < Previous)
                {
                    return false;
                }
                if (Now == Previous ||
                    State_->Timestamp_->LastNow.compare_exchange_weak(
                        Previous, Now, std::memory_order_relaxed, std::memory_order_relaxed))
                {
                    return true;
                }
            }
        }

        /**
         * @brief 为窗口尺度换代建立新的分片状态
         * @details 新状态的 Packed 从零开始，旧 generation 的使用量不会进入新窗口；
         *          TimestampState 继续共享，以保持所有换代请求的时间戳单调。
         */
        [[nodiscard]] static auto RebaseState(const std::shared_ptr<SharedState> &Previous)
            -> std::shared_ptr<SharedState>
        {
            if (!Previous)
            {
                return {};
            }
            return std::make_shared<SharedState>(Previous->Timestamp_);
        }

        const std::uint64_t Limit_;
        const std::uint64_t WindowMilliseconds_;
        const bool Invalid_;
        std::shared_ptr<SharedState> State_;

        friend class RateLimiter;
    };

    class RateLimiter final
    {
    private:
        struct State final
        {
            bool Unlimited{false};
            bool WorkerSharded{false};
            bool Invalid{false};
            std::vector<std::shared_ptr<RateShard>> Shards;
        };

    public:
        explicit RateLimiter(RatePolicy Policy)
            : State_(BuildState(Policy, {}))
        {
        }

        RateLimiter(const RateLimiter &) = delete;
        auto operator=(const RateLimiter &) -> RateLimiter & = delete;

        [[nodiscard]] auto TryConsume(RateRequest Request) const noexcept -> bool
        {
            const auto State = State_.load(std::memory_order_acquire);
            if (State->Unlimited)
            {
                return true;
            }
            if (State->Invalid)
            {
                return false;
            }
            if (State->Shards.empty())
            {
                return true;
            }
            if (State->WorkerSharded)
            {
                if (Request.WorkerId >= State->Shards.size())
                {
                    return false;
                }
                return State->Shards[Request.WorkerId]->TryConsume(Request);
            }
            return State->Shards.front()->TryConsume(Request);
        }

        [[nodiscard]] auto Reconfigure(RatePolicy Policy) const
            -> std::shared_ptr<const RateLimiter>
        {
            const auto Previous = State_.load(std::memory_order_acquire);
            return std::shared_ptr<const RateLimiter>(
                new RateLimiter(BuildState(Policy, Previous)));
        }

    private:
        explicit RateLimiter(std::shared_ptr<const State> State) : State_(std::move(State))
        {
        }

        [[nodiscard]] static auto MakeShard(
            RateShardOptions Options,
            std::shared_ptr<RateShard::SharedState> SharedState) -> std::shared_ptr<RateShard>
        {
            if (SharedState)
            {
                return std::shared_ptr<RateShard>(new RateShard(Options, std::move(SharedState)));
            }

            return std::make_shared<RateShard>(Options);
        }

        [[nodiscard]] static auto BuildState(const RatePolicy &Policy,
                                              const std::shared_ptr<const State> &Previous)
            -> std::shared_ptr<const State>
        {
            auto Result = std::make_shared<State>();
            if (std::holds_alternative<UnlimitedRatePolicy>(Policy))
            {
                Result->Unlimited = true;
                return Result;
            }

            if (const auto *Strict = std::get_if<StrictGlobalRatePolicy>(&Policy))
            {
                if (Strict->WindowMilliseconds == 0 || Strict->LimitPerWindow > KMaxUnits)
                {
                    Result->Invalid = true;
                    return Result;
                }
                if (Strict->LimitPerWindow == 0)
                {
                    Result->Unlimited = true;
                    return Result;
                }
                std::shared_ptr<RateShard::SharedState> SharedState;
                if (Previous && !Previous->Shards.empty())
                {
                    const auto &PreviousShard = Previous->Shards.front();
                    SharedState = PreviousShard->WindowMilliseconds_ == Strict->WindowMilliseconds
                                      ? PreviousShard->State_
                                      : RateShard::RebaseState(PreviousShard->State_);
                }
                Result->Shards.push_back(MakeShard(
                    RateShardOptions{Strict->LimitPerWindow, Strict->WindowMilliseconds},
                    std::move(SharedState)));
                return Result;
            }

            const auto &Worker = std::get<WorkerShardedRatePolicy>(Policy);
            Result->WorkerSharded = true;
            if (Worker.WorkerCount == 0 ||
                Worker.WorkerCount > WorkerShardedRatePolicy::MaxWorkerCount ||
                Worker.WindowMilliseconds == 0)
            {
                Result->Invalid = true;
                return Result;
            }

            if (Worker.GlobalLimitPerWindow == 0)
            {
                Result->Unlimited = true;
                return Result;
            }

            const auto PerWorker = Worker.PerWorkerLimit();
            if (PerWorker == 0 || PerWorker > KMaxUnits)
            {
                Result->Invalid = true;
                return Result;
            }

            Result->Shards.reserve(Worker.WorkerCount);
            for (std::uint32_t Index = 0; Index < Worker.WorkerCount; ++Index)
            {
                std::shared_ptr<RateShard::SharedState> SharedState;
                if (Previous && Index < Previous->Shards.size())
                {
                    const auto &PreviousShard = Previous->Shards[Index];
                    SharedState = PreviousShard->WindowMilliseconds_ == Worker.WindowMilliseconds
                                      ? PreviousShard->State_
                                      : RateShard::RebaseState(PreviousShard->State_);
                }
                Result->Shards.push_back(MakeShard(
                    RateShardOptions{PerWorker, Worker.WindowMilliseconds},
                    std::move(SharedState)));
            }
            return Result;
        }

        static constexpr std::uint64_t KMaxUnits{0xFFFFFFFFULL};

        std::atomic<std::shared_ptr<const State>> State_;
    };

} // namespace Preview::Account
