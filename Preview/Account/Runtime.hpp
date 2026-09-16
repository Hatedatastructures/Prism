/**
 * @file Runtime.hpp
 * @brief 账户运行时状态与配额账本
 * @details 配置由 AccountRecord 持有；本文件只保存原子计数、撤销位、
 *          配额使用量和速率控制状态，不执行阻塞操作或 I/O。
 */
#pragma once

#include "Rate.hpp"

#include "../Foundation/Identifier/Id.hpp"

#include <atomic>
#include <cstdint>
#include <limits>
#include <memory>
#include <utility>

namespace Preview::Account
{

    struct QuotaPolicy
    {
        std::uint32_t MaxConnections{0};
        std::uint32_t MaxStreams{0};
        std::uint64_t MaxBytes{0};
    };

    class AccountDirectory;

    class AccountRuntimeState final
    {
    private:
        class QuotaLedger final
        {
        public:
            QuotaLedger(std::shared_ptr<std::atomic<std::uint64_t>> Used,
                        const std::uint64_t Limit) noexcept
                : Used_(std::move(Used)), Limit_(Limit)
            {
            }

            [[nodiscard]] auto TryReserve(const std::uint64_t Amount) noexcept -> bool
            {
                if (Amount == 0)
                {
                    return true;
                }

                auto Current = Used_->load(std::memory_order_relaxed);
                while (true)
                {
                    if (Current > std::numeric_limits<std::uint64_t>::max() - Amount)
                    {
                        return false;
                    }
                    const auto Next = Current + Amount;
                    if (Limit_ != 0 && (Current > Limit_ || Next > Limit_))
                    {
                        return false;
                    }
                    if (Used_->compare_exchange_weak(Current, Next, std::memory_order_relaxed,
                                                      std::memory_order_relaxed))
                    {
                        return true;
                    }
                }
            }

            void Release(const std::uint64_t Amount) noexcept
            {
                auto Current = Used_->load(std::memory_order_relaxed);
                while (Current != 0)
                {
                    const auto Next = Amount >= Current ? 0 : Current - Amount;
                    if (Used_->compare_exchange_weak(Current, Next, std::memory_order_relaxed,
                                                      std::memory_order_relaxed))
                    {
                        return;
                    }
                }
            }

            [[nodiscard]] auto Used() const noexcept -> std::uint64_t
            {
                return Used_->load(std::memory_order_relaxed);
            }

        private:
            std::shared_ptr<std::atomic<std::uint64_t>> Used_;
            const std::uint64_t Limit_;
        };

    public:
        class Policy final
        {
        public:
            [[nodiscard]] auto Generation() const noexcept -> Preview::GenerationId
            {
                return Generation_;
            }

            [[nodiscard]] auto TryReserveBytes(const std::uint64_t Amount) const noexcept -> bool
            {
                return Bytes_->TryReserve(Amount);
            }

            void ReleaseBytes(const std::uint64_t Amount) const noexcept
            {
                Bytes_->Release(Amount);
            }

            [[nodiscard]] auto UsedBytes() const noexcept -> std::uint64_t
            {
                return Bytes_->Used();
            }

            [[nodiscard]] auto TryConsume(RateRequest Request) const noexcept -> bool
            {
                return Rate_->TryConsume(Request);
            }

        private:
            struct Binding final
            {
                Preview::GenerationId Generation;
                std::shared_ptr<QuotaLedger> Bytes;
                std::shared_ptr<const RateLimiter> Rate;
            };

            explicit Policy(Binding Value)
                : Generation_(Value.Generation),
                  Bytes_(std::move(Value.Bytes)),
                  Rate_(std::move(Value.Rate))
            {
            }

            friend class AccountRuntimeState;

            const Preview::GenerationId Generation_;
            const std::shared_ptr<QuotaLedger> Bytes_;
            const std::shared_ptr<const RateLimiter> Rate_;
        };

        /**
         * @brief 一次账户策略换代的发布输入
         * @details Generation 是旧请求的拒绝门禁。速率窗口尺度变化时，RateLimiter
         *          只重置 packed 使用量并保留单调时间戳，避免旧 generation 污染新策略。
         */
        struct PolicyUpdate final
        {
            Preview::GenerationId Generation;
            RatePolicy Rate;
            std::uint64_t MaxBytes{0};
        };

        explicit AccountRuntimeState(RatePolicy Rate,
                                     const std::uint64_t MaxBytes,
                                     Preview::GenerationId Generation = {})
            : BytesUsed_(std::make_shared<std::atomic<std::uint64_t>>(0)),
              Policy_(std::shared_ptr<const Policy>(new Policy(Policy::Binding{
                  Generation,
                  std::make_shared<QuotaLedger>(BytesUsed_, MaxBytes),
                  std::make_shared<const RateLimiter>(std::move(Rate))})))
        {
        }

        [[nodiscard]] auto TryAcquireConnection(std::uint32_t Limit) noexcept -> bool
        {
            return TryAcquire(ActiveConnections_, Limit);
        }

        void ReleaseConnection() noexcept
        {
            Release(ActiveConnections_);
        }

        [[nodiscard]] auto TryAcquireStream(std::uint32_t Limit) noexcept -> bool
        {
            return TryAcquire(ActiveStreams_, Limit);
        }

        void ReleaseStream() noexcept
        {
            Release(ActiveStreams_);
        }

        [[nodiscard]] auto TryReserveBytes(const std::uint64_t Amount) noexcept -> bool
        {
            const auto Policy = Policy_.load(std::memory_order_acquire);
            return Policy->TryReserveBytes(Amount);
        }

        [[nodiscard]] auto TryReserveBytes(const std::uint64_t Amount,
                                           Preview::GenerationId Generation) const noexcept -> bool
        {
            const auto Policy = Policy_.load(std::memory_order_acquire);
            if (Policy->Generation() != Generation)
            {
                return false;
            }
            return Policy->TryReserveBytes(Amount);
        }

        void ReleaseBytes(std::uint64_t Amount) noexcept
        {
            const auto Policy = Policy_.load(std::memory_order_acquire);
            Policy->ReleaseBytes(Amount);
        }

        [[nodiscard]] auto UsedBytes() const noexcept -> std::uint64_t
        {
            const auto Policy = Policy_.load(std::memory_order_acquire);
            return Policy->UsedBytes();
        }

        [[nodiscard]] auto TryConsume(RateRequest Request) noexcept -> bool
        {
            const auto Policy = Policy_.load(std::memory_order_acquire);
            return Policy->TryConsume(Request);
        }

        [[nodiscard]] auto TryConsume(RateRequest Request,
                                      Preview::GenerationId Generation) const noexcept -> bool
        {
            const auto Policy = Policy_.load(std::memory_order_acquire);
            if (Policy->Generation() != Generation)
            {
                return false;
            }
            return Policy->TryConsume(Request);
        }

        [[nodiscard]] auto PolicyGeneration() const noexcept -> Preview::GenerationId
        {
            const auto Policy = Policy_.load(std::memory_order_acquire);
            return Policy->Generation();
        }

        [[nodiscard]] auto PolicyFor(Preview::GenerationId Generation) const
            -> std::shared_ptr<const Policy>
        {
            const auto Policy = Policy_.load(std::memory_order_acquire);
            if (Policy->Generation() != Generation)
            {
                return {};
            }
            return Policy;
        }

        void Revoke() noexcept
        {
            Revoked_.store(true, std::memory_order_release);
        }

        [[nodiscard]] auto IsRevoked() const noexcept -> bool
        {
            return Revoked_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto ActiveConnections() const noexcept -> std::uint32_t
        {
            return ActiveConnections_.load(std::memory_order_relaxed);
        }

        [[nodiscard]] auto ActiveStreams() const noexcept -> std::uint32_t
        {
            return ActiveStreams_.load(std::memory_order_relaxed);
        }

    private:
        friend class AccountDirectory;

        [[nodiscard]] auto PreparePolicy(PolicyUpdate Update) const
            -> std::shared_ptr<const Policy>
        {
            const auto Current = Policy_.load(std::memory_order_acquire);
            return std::shared_ptr<const Policy>(new Policy(Policy::Binding{
                Update.Generation,
                std::make_shared<QuotaLedger>(BytesUsed_, Update.MaxBytes),
                Current->Rate_->Reconfigure(std::move(Update.Rate))}));
        }

        void PublishPolicy(Preview::GenerationId Generation,
                           std::shared_ptr<const Policy> Policy) noexcept
        {
            auto Current = Policy_.load(std::memory_order_acquire);
            while (Current->Generation() < Generation)
            {
                if (Policy_.compare_exchange_weak(Current, Policy, std::memory_order_release,
                                                  std::memory_order_acquire))
                {
                    return;
                }
            }
        }

        static auto TryAcquire(std::atomic<std::uint32_t> &Counter, std::uint32_t Limit) noexcept -> bool
        {
            auto Current = Counter.load(std::memory_order_relaxed);
            while (true)
            {
                if (Current == std::numeric_limits<std::uint32_t>::max() ||
                    (Limit != 0 && Current >= Limit))
                {
                    return false;
                }
                if (Counter.compare_exchange_weak(Current, Current + 1, std::memory_order_relaxed,
                                                   std::memory_order_relaxed))
                {
                    return true;
                }
            }
        }

        static void Release(std::atomic<std::uint32_t> &Counter) noexcept
        {
            auto Current = Counter.load(std::memory_order_relaxed);
            while (Current != 0 &&
                   !Counter.compare_exchange_weak(Current, Current - 1, std::memory_order_relaxed,
                                                  std::memory_order_relaxed))
            {
            }
        }

        std::atomic<std::uint32_t> ActiveConnections_{0};
        std::atomic<std::uint32_t> ActiveStreams_{0};
        std::atomic<bool> Revoked_{false};
        std::shared_ptr<std::atomic<std::uint64_t>> BytesUsed_;
        std::atomic<std::shared_ptr<const Policy>> Policy_;
    };

    using SharedAccountRuntimeState = std::shared_ptr<AccountRuntimeState>;

} // namespace Preview::Account
