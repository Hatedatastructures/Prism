/** @file TransferBudget.hpp
 * @brief 单账户跨 Worker 流量信用与双向带宽执行；数据库只通过异步端口调用。
 */
#pragma once

#include <Prism/Account/Failure.hpp>
#include <Prism/Account/Policy.hpp>
#include <Prism/Account/UsagePersistence.hpp>
#include <Prism/Contract/Account/PayloadBudget.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>

#include <boost/asio/awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace Prism::Account
{
    namespace Net = boost::asio;

    namespace Detail
    {
        struct BandwidthDecision final
        {
            std::uint64_t Bytes{0};
            std::chrono::milliseconds Wait{0};
        };

        /** @brief 账户内嵌的方向桶状态；实现留在 TransferBudget.cpp。 */
        class BandwidthBucket final
        {
        public:
            [[nodiscard]] auto TryTake(const std::optional<std::uint64_t> Limit,
                const Contract::PayloadRequest& Request) noexcept
                -> std::expected<BandwidthDecision, Fault::Failure>;
            auto Refund(const std::uint64_t Bytes) noexcept -> void;

        private:
            auto Refill(const std::chrono::steady_clock::time_point Now) noexcept -> void;

            std::atomic_flag Gate_ = ATOMIC_FLAG_INIT;
            std::optional<std::uint64_t> Limit_;
            long double Tokens_{0};
            std::chrono::steady_clock::time_point Updated_{};
            bool Initialized_{false};
        };

        class UsageCredit;
    }

    /** @brief 应用装配输入持有正式存储和发布源，账户 Key 必须来自稳定配置身份。 */
    struct TransferBudgetOptions final
    {
        Prism::AccountId Id;
        std::string AccountKey;
        std::shared_ptr<PolicySource> Policies;
        std::shared_ptr<UsagePersistence> Persistence;
        std::string Incarnation; ///< 持久请求 key 的进程 incarnation，调用方必须保证跨进程唯一。
    };

    /**
     * @brief 信用块只在慢路径分配；无带宽约束时每次 I/O 只操作共享原子信用。
     * @details 网络调用者按值提交请求，等待可取消；持久预约失败不会回退为不限额授权。
     *          数据面负责最终关闭；Application 必须在数据面退休后调用 Flush(true)。
     */
    class TransferBudget final : public Contract::PayloadBudget,
        public std::enable_shared_from_this<TransferBudget>
    {
        using Failure = Fault::Failure;
        using Permit = Contract::PayloadPermit;
        static constexpr std::uint64_t BlockBytes{1024U * 1024U};

        class Gate;
        class DirectionSettlement;

    public:
        explicit TransferBudget(TransferBudgetOptions Options);
        TransferBudget(const TransferBudget&) = delete;
        auto operator=(const TransferBudget&) -> TransferBudget& = delete;
        ~TransferBudget() override;

        [[nodiscard]] auto Acquire(Contract::PayloadRequest Request)
            -> Net::awaitable<std::expected<Permit, Failure>> override;
        [[nodiscard]] auto AdmissionAllowed() const noexcept -> bool;
        [[nodiscard]] auto Read() -> Net::awaitable<std::expected<UsageSnapshot, Failure>>;
        [[nodiscard]] auto Flush(const bool Final = false)
            -> Net::awaitable<std::expected<void, Failure>>;
        [[nodiscard]] auto AccountKey() const noexcept -> std::string_view;

    private:
        [[nodiscard]] auto CurrentPolicy() const noexcept -> std::shared_ptr<const PolicySnapshot>;
        [[nodiscard]] static auto Now() noexcept -> std::int64_t;
        [[nodiscard]] static auto Delay(const std::chrono::milliseconds Duration)
            -> Net::awaitable<std::expected<void, Failure>>;
        [[nodiscard]] auto Resolve(const std::shared_ptr<const PolicySnapshot>& Policy)
            -> Net::awaitable<std::expected<UsageCycle, Failure>>;
        [[nodiscard]] auto AcquireCredit(Contract::PayloadRequest Request,
            const std::shared_ptr<const PolicySnapshot>& Policy)
            -> Net::awaitable<std::expected<Permit, Failure>>;
        [[nodiscard]] auto Refill(const std::shared_ptr<const PolicySnapshot>& Policy,
            const Contract::PayloadRequest& Request)
            -> Net::awaitable<std::expected<void, Failure>>;
        [[nodiscard]] auto CheckpointCredit(const bool Final)
            -> Net::awaitable<std::expected<void, Failure>>;

        const TransferBudgetOptions Options_;
        const std::uint64_t RequestNamespace_; ///< 每个预算 owner 的进程内唯一 ticket。
        std::array<Detail::BandwidthBucket, 2> Bandwidth_;
        std::atomic<std::shared_ptr<Detail::UsageCredit>> Credit_;
        std::atomic<std::uint64_t> Version_{0};
        std::atomic<std::uint64_t> Available_{0};
        std::atomic<std::uint64_t> Sequence_{1};
        std::atomic_flag Gate_ = ATOMIC_FLAG_INIT;
    };
}
