/** @file Runtime.hpp
 * @brief 唯一账户活动/字节/速率账本；不保存或两次发布当前策略。
 */
#pragma once
#include <Prism/Account/Failure.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Account/Quota.hpp>
#include <Prism/Account/TransferBudget.hpp>
#include <Prism/Contract/Account/AdmissionAuthority.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <expected>
#include <optional>
#include <chrono>
#include <exception>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace Prism::Account
{
    namespace Net = boost::asio;
    class CredentialIndexView;
    class StreamAdmission;
    class AccountLease;
    class StreamLease;
    class ByteLease;
    class AccountRuntimeRegistry;
    class PolicySource;
    class PolicySnapshot;
    namespace Detail { class RateLedger; struct RootLeaseSlot; }

    /** @brief 区分同一 AccountId 的不同 AccountRuntime owner，不持有 runtime 本身。 */
    class AccountRuntimeIdentity final
    {
        struct Token final {};
        friend class AccountRuntime;
        explicit AccountRuntimeIdentity(std::shared_ptr<const Token> TokenValue) noexcept;
    public:
        AccountRuntimeIdentity() = default;
        [[nodiscard]] auto IsValid() const noexcept -> bool;
        explicit operator bool() const noexcept;
        friend auto operator==(const AccountRuntimeIdentity &Left,
                               const AccountRuntimeIdentity &Right) noexcept -> bool;
        friend auto operator<(const AccountRuntimeIdentity &Left,
                              const AccountRuntimeIdentity &Right) noexcept -> bool;
    private:
        std::shared_ptr<const Token> Token_;
    };

    /** @brief runtime 不拥有 I/O；策略更新只生成 Binding，活动计数保持原实例。 */
    class AccountRuntime final : public std::enable_shared_from_this<AccountRuntime>
    {
        using Failure = Fault::Failure;
        using Code = Fault::Code;
        using DrainSignal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;
        using DrainSignalList = std::vector<std::weak_ptr<DrainSignal>>;
        static constexpr std::uint64_t CountMask = (std::uint64_t{1U} << 31U) - 1U;
        static constexpr unsigned StreamShift = 31U;
    public:
        AccountRuntime(const Prism::AccountId Id, const std::uint32_t Workers);
        [[nodiscard]] auto AccountId() const noexcept -> Prism::AccountId;
        [[nodiscard]] auto RuntimeIdentity() const noexcept -> AccountRuntimeIdentity;
        [[nodiscard]] auto RateLedger() const noexcept -> const std::shared_ptr<Detail::RateLedger>&;
        [[nodiscard]] auto IsRevoked() const noexcept -> bool;
        [[nodiscard]] auto ActiveConnections() const noexcept -> std::uint32_t;
        [[nodiscard]] auto ActiveStreams() const noexcept -> std::uint32_t;
        [[nodiscard]] auto UsedBytes() const noexcept -> std::uint64_t;
        /** @brief 只返回正式 publication 的策略源，不持有第二份可变策略。 */
        [[nodiscard]] auto ResourcePolicySource() const noexcept -> std::shared_ptr<PolicySource>;
        [[nodiscard]] auto Transfer() const noexcept -> std::shared_ptr<TransferBudget>;
        [[nodiscard]] auto StableKey() const -> std::string;

        using LeaseDrainDeadline = std::chrono::steady_clock::time_point;
        using LeaseDrainOutcome = std::expected<void, Fault::Failure>;

        /**
         * @brief 在账户已撤销后等待所有 root lease 与其 child 引用真实归零。
         * @param Limit 调用方共享的停机绝对 deadline，不在本函数中延长。
         * @return lease 归零返回成功；deadline、executor 通知或分配失败保留 typed cause。
         * @details 本函数只观察 AccountRuntime 的 root lease 额度，不执行会话取消或 socket 关闭；
         *          调用者先完成对应会话取消。本函数在创建协程前 pin Runtime owner；
         *          撤销后不会再提交新的有效 root lease。
         */
        [[nodiscard]] auto WaitForNoActiveConnections(const LeaseDrainDeadline Limit) const
            -> Net::awaitable<LeaseDrainOutcome>;
    private:
        friend class CredentialIndexView;
        friend class StreamAdmission;
        friend class AccountLease;
        friend class StreamLease;
        friend class ByteLease;
        friend class AccountRuntimeRegistry;
        friend class AccountStore;
        friend struct Detail::RootLeaseSlot;

        auto AttachAuthority(
            const std::weak_ptr<Prism::Contract::AccountAdmissionAuthority> &Authority) noexcept
            -> void;
        auto AttachPolicySource(const std::weak_ptr<PolicySource>& Source) noexcept -> void;
        auto AttachTransfer(std::shared_ptr<TransferBudget> Budget) noexcept -> void;
        auto ApplyStableKeyAndTransfer(
            std::string StableKey,
            std::shared_ptr<TransferBudget> Transfer) noexcept -> void;

        [[nodiscard]] static auto WaitForNoActiveConnectionsOwned(
            std::shared_ptr<const AccountRuntime> Runtime, const LeaseDrainDeadline Limit)
            -> Net::awaitable<LeaseDrainOutcome>;

        [[nodiscard]] static auto CreateIdentity() -> AccountRuntimeIdentity;

        [[nodiscard]] static auto FailureFromException(const std::exception_ptr &ExceptionValue) noexcept
            -> Failure;

        [[nodiscard]] static auto WaitUntil(const LeaseDrainDeadline Limit)
            -> Net::awaitable<boost::system::error_code>;

        auto RegisterDrainSignal(const std::shared_ptr<DrainSignal> &Signal) const -> void;

        auto NotifyDrainSignals() noexcept -> void;

        /** @brief 连接准入读预约覆盖额度登记至最终 lease commit。 */
        [[nodiscard]] auto TryAcquireConnection(const std::optional<std::uint32_t> Limit) noexcept
            -> std::expected<Prism::Contract::AccountAdmissionPermit, Failure>;
        /** @brief child 准入读预约覆盖额度登记至最终 stream commit。 */
        [[nodiscard]] auto TryAcquireStream(const std::optional<std::uint32_t> Limit) noexcept
            -> std::expected<Prism::Contract::AccountAdmissionPermit, Failure>;
        auto ReleaseConnection() noexcept -> void;
        auto ReleaseStream() noexcept -> void;
        /** @brief 只接收 lease 的冻结额度；没有 currentPolicy 或按 generation 猜政策入口。 */
        [[nodiscard]] auto ReserveBytes(const std::uint64_t Amount, const std::uint64_t Limit) noexcept
            -> std::expected<void, Failure>;
        auto ReleaseBytes(const std::uint64_t Amount) noexcept -> void;
        [[nodiscard]] auto Acquire(const std::optional<std::uint32_t> Limit, const unsigned Shift) noexcept
            -> std::expected<Prism::Contract::AccountAdmissionPermit, Failure>;
        const Prism::AccountId AccountId_;
        const AccountRuntimeIdentity Identity_;
        const std::shared_ptr<Detail::RateLedger> Rate_;
        std::weak_ptr<Prism::Contract::AccountAdmissionAuthority> Authority_;
        std::weak_ptr<PolicySource> PolicySource_;
        mutable std::mutex MutableStateGate_;
        std::string StableKey_;
        std::shared_ptr<TransferBudget> Transfer_;
        std::atomic<std::uint64_t> Admission_{0U};
        std::atomic<std::uint64_t> Bytes_{0U};
        mutable std::atomic<std::shared_ptr<const DrainSignalList>> DrainSignals_{};
        mutable Prism::Fault::FailureState DrainFailure_;
    };
}
