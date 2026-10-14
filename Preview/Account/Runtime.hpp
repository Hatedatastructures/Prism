/** @file Runtime.hpp
 * @brief 唯一账户活动/字节/速率账本；不保存或两次发布当前策略。
 */
#pragma once
#include <Preview/Account/Failure.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Account/Quota.hpp>
#include <Preview/Account/Detail/RateLedger.hpp>
#include <Preview/Contract/Account/AdmissionAuthority.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <atomic>
#include <memory>
#include <expected>
#include <limits>
#include <chrono>
#include <exception>
#include <new>
#include <system_error>
#include <utility>
#include <vector>
#include <variant>

namespace Preview::Account
{
    namespace Net = boost::asio;
    class CredentialIndexView;
    class StreamAdmission;
    class AccountLease;
    class StreamLease;
    class ByteLease;
    class AccountRuntimeRegistry;
    namespace Detail { struct RootLeaseSlot; }

    /** @brief 区分同一 AccountId 的不同 AccountRuntime owner，不持有 runtime 本身。 */
    class AccountRuntimeIdentity final
    {
        struct Token final {};
        friend class AccountRuntime;
        explicit AccountRuntimeIdentity(std::shared_ptr<const Token> TokenValue) noexcept
            : Token_(std::move(TokenValue)) {}
    public:
        AccountRuntimeIdentity() = default;
        [[nodiscard]] auto IsValid() const noexcept -> bool { return static_cast<bool>(Token_); }
        explicit operator bool() const noexcept { return IsValid(); }
        friend auto operator==(const AccountRuntimeIdentity &Left,
                               const AccountRuntimeIdentity &Right) noexcept -> bool
        {
            return !Left.Token_.owner_before(Right.Token_) &&
                   !Right.Token_.owner_before(Left.Token_);
        }
        friend auto operator<(const AccountRuntimeIdentity &Left,
                              const AccountRuntimeIdentity &Right) noexcept -> bool
        {
            return Left.Token_.owner_before(Right.Token_);
        }
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
        AccountRuntime(const Preview::AccountId Id, const std::uint32_t Workers)
            : AccountId_(Id), Identity_(CreateIdentity()),
              Rate_(std::make_shared<Detail::RateLedger>(Workers)) {}
        [[nodiscard]] auto AccountId() const noexcept -> Preview::AccountId { return AccountId_; }
        [[nodiscard]] auto RuntimeIdentity() const noexcept -> AccountRuntimeIdentity { return Identity_; }
        [[nodiscard]] auto RateLedger() const noexcept -> const std::shared_ptr<Detail::RateLedger>& { return Rate_; }
        [[nodiscard]] auto IsRevoked() const noexcept -> bool
        {
            const auto Authority = Authority_.lock();
            if (!Authority) { return true; }
            const auto Snapshot = Authority->Load();
            return !Snapshot || Snapshot->IsRevoked(AccountId_);
        }
        [[nodiscard]] auto ActiveConnections() const noexcept -> std::uint32_t
        {
            return static_cast<std::uint32_t>(Admission_.load(std::memory_order_acquire) & CountMask);
        }
        [[nodiscard]] auto ActiveStreams() const noexcept -> std::uint32_t
        {
            return static_cast<std::uint32_t>((Admission_.load(std::memory_order_relaxed) >> StreamShift) & CountMask);
        }
        [[nodiscard]] auto UsedBytes() const noexcept -> std::uint64_t { return Bytes_.load(std::memory_order_relaxed); }

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
            -> Net::awaitable<LeaseDrainOutcome>
        {
            return WaitForNoActiveConnectionsOwned(weak_from_this().lock(), Limit);
        }
    private:
        friend class CredentialIndexView;
        friend class StreamAdmission;
        friend class AccountLease;
        friend class StreamLease;
        friend class ByteLease;
        friend class AccountRuntimeRegistry;
        friend struct Detail::RootLeaseSlot;

        auto AttachAuthority(
            const std::weak_ptr<Preview::Contract::AccountAdmissionAuthority> &Authority) noexcept
            -> void
        {
            Authority_ = Authority;
        }

        [[nodiscard]] static auto WaitForNoActiveConnectionsOwned(
            std::shared_ptr<const AccountRuntime> Runtime, const LeaseDrainDeadline Limit)
            -> Net::awaitable<LeaseDrainOutcome>
        {
            if (!Runtime || !Runtime->IsRevoked())
            {
                co_return std::unexpected(Failure{Code::Blocked});
            }
            if (Runtime->ActiveConnections() == 0U)
            {
                co_return LeaseDrainOutcome{};
            }

            std::shared_ptr<DrainSignal> Signal;
            try
            {
                const auto Executor = co_await Net::this_coro::executor;
                Signal = std::make_shared<DrainSignal>(Executor, 1U);
                Runtime->RegisterDrainSignal(Signal);
            }
            catch (...)
            {
                co_return std::unexpected(FailureFromException(std::current_exception()));
            }

            using Net::experimental::awaitable_operators::operator||;
            try
            {
                while (Runtime->ActiveConnections() != 0U)
                {
                    const auto NotificationFailure = Runtime->DrainFailure_.Load();
                    if (NotificationFailure.Failed() && Runtime->ActiveConnections() != 0U)
                    {
                        co_return std::unexpected(NotificationFailure);
                    }
                    boost::system::error_code SignalError;
                    const auto Wake = co_await (
                        Signal->async_receive(Net::redirect_error(Net::use_awaitable, SignalError)) ||
                        WaitUntil(Limit));
                    if (Wake.index() == 1U)
                    {
                        if (Runtime->ActiveConnections() == 0U)
                        {
                            co_return LeaseDrainOutcome{};
                        }
                        const auto CurrentNotificationFailure = Runtime->DrainFailure_.Load();
                        if (CurrentNotificationFailure.Failed())
                        {
                            co_return std::unexpected(CurrentNotificationFailure);
                        }
                        const auto Error = std::get<1>(Wake);
                        if (Error)
                        {
                            co_return std::unexpected(Fault::FromNative(
                                static_cast<std::error_code>(Error)));
                        }
                        co_return std::unexpected(Failure{
                            Code::Timeout, std::make_error_code(std::errc::timed_out)});
                    }
                    if (Runtime->ActiveConnections() == 0U)
                    {
                        break;
                    }
                    if (SignalError)
                    {
                        co_return std::unexpected(Fault::FromNative(
                            static_cast<std::error_code>(SignalError)));
                    }
                }
            }
            catch (...)
            {
                co_return std::unexpected(FailureFromException(std::current_exception()));
            }
            co_return LeaseDrainOutcome{};
        }

        [[nodiscard]] static auto CreateIdentity() -> AccountRuntimeIdentity
        {
            return AccountRuntimeIdentity(std::make_shared<const AccountRuntimeIdentity::Token>());
        }

        [[nodiscard]] static auto FailureFromException(const std::exception_ptr &ExceptionValue) noexcept
            -> Failure
        {
            if (!ExceptionValue)
            {
                return Failure{Code::Blocked};
            }
            try
            {
                std::rethrow_exception(ExceptionValue);
            }
            catch (const boost::system::system_error &Error)
            {
                return Fault::FromNative(static_cast<std::error_code>(Error.code()));
            }
            catch (const std::system_error &Error)
            {
                return Fault::FromNative(Error.code());
            }
            catch (const std::bad_alloc &)
            {
                return Failure{Code::ResourceUnavailable};
            }
            catch (...)
            {
                return Failure{Code::Blocked};
            }
        }

        [[nodiscard]] static auto WaitUntil(const LeaseDrainDeadline Limit)
            -> Net::awaitable<boost::system::error_code>
        {
            const auto Executor = co_await Net::this_coro::executor;
            Net::steady_timer Timer(Executor);
            Timer.expires_at(Limit);
            boost::system::error_code Error;
            co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
            co_return Error;
        }

        auto RegisterDrainSignal(const std::shared_ptr<DrainSignal> &Signal) const -> void
        {
            auto Current = DrainSignals_.load(std::memory_order_acquire);
            for (;;)
            {
                auto Next = std::make_shared<DrainSignalList>();
                if (Current)
                {
                    Next->reserve(Current->size() + 1U);
                    for (const auto &Existing : *Current)
                    {
                        if (!Existing.expired())
                        {
                            Next->push_back(Existing);
                        }
                    }
                }
                Next->push_back(Signal);
                std::shared_ptr<const DrainSignalList> Desired = std::move(Next);
                if (DrainSignals_.compare_exchange_weak(
                    Current, Desired, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return;
                }
            }
        }

        auto NotifyDrainSignals() noexcept -> void
        {
            const auto Signals = DrainSignals_.load(std::memory_order_acquire);
            if (!Signals)
            {
                return;
            }
            for (const auto &WeakSignal : *Signals)
            {
                const auto Signal = WeakSignal.lock();
                if (!Signal)
                {
                    continue;
                }
                try
                {
                    (void)Signal->try_send(boost::system::error_code{});
                }
                catch (...)
                {
                    (void)DrainFailure_.TrySet(FailureFromException(std::current_exception()));
                }
            }
        }

        /** @brief 连接准入读预约覆盖额度登记至最终 lease commit。 */
        [[nodiscard]] auto TryAcquireConnection(const std::uint32_t Limit) noexcept
            -> std::expected<Preview::Contract::AccountAdmissionPermit, Failure>
        {
            return Acquire(Limit, 0U);
        }
        /** @brief child 准入读预约覆盖额度登记至最终 stream commit。 */
        [[nodiscard]] auto TryAcquireStream(const std::uint32_t Limit) noexcept
            -> std::expected<Preview::Contract::AccountAdmissionPermit, Failure>
        {
            return Acquire(Limit, StreamShift);
        }
        auto ReleaseConnection() noexcept -> void
        {
            const auto Previous = Admission_.fetch_sub(1U, std::memory_order_acq_rel);
            if ((Previous & CountMask) == 1U)
            {
                NotifyDrainSignals();
            }
        }
        auto ReleaseStream() noexcept -> void { Admission_.fetch_sub(std::uint64_t{1U} << StreamShift, std::memory_order_acq_rel); }
        /** @brief 只接收 lease 的冻结额度；没有 currentPolicy 或按 generation 猜政策入口。 */
        [[nodiscard]] auto ReserveBytes(const std::uint64_t Amount, const std::uint64_t Limit) noexcept
            -> std::expected<void, Failure>
        {
            auto Used = Bytes_.load(std::memory_order_relaxed);
            for (;;)
            {
                if (Amount > UINT64_MAX - Used || (Limit != 0U && (Used > Limit || Amount > Limit - Used)))
                {
                    return std::unexpected(MakeFailure(FailureReason::ByteQuota));
                }
                if (Bytes_.compare_exchange_weak(Used, Used + Amount, std::memory_order_acq_rel,
                    std::memory_order_relaxed)) { return {}; }
            }
        }
        auto ReleaseBytes(const std::uint64_t Amount) noexcept -> void { Bytes_.fetch_sub(Amount, std::memory_order_acq_rel); }
        [[nodiscard]] auto Acquire(const std::uint32_t Limit, const unsigned Shift) noexcept
            -> std::expected<Preview::Contract::AccountAdmissionPermit, Failure>
        {
            const auto Authority = Authority_.lock();
            if (!Authority)
            {
                return std::unexpected(Failure{Code::ResourceUnavailable});
            }
            auto Permit = Authority->BeginAdmission(AccountId_);
            if (!Permit)
            {
                if (Permit.error().Code == Code::Forbidden)
                {
                    return std::unexpected(MakeFailure(FailureReason::Revoked));
                }
                return std::unexpected(Permit.error());
            }
            auto State = Admission_.load(std::memory_order_acquire);
            for (;;)
            {
                const auto Count = (State >> Shift) & CountMask;
                if (Count == CountMask || (Limit != 0U && Count >= Limit))
                {
                    auto Reason = FailureReason::ConnectionQuota;
                    if (Shift != 0U) { Reason = FailureReason::StreamQuota; }
                    return std::unexpected(MakeFailure(Reason));
                }
                if (Admission_.compare_exchange_weak(State, State + (std::uint64_t{1U} << Shift),
                    std::memory_order_acq_rel, std::memory_order_acquire)) { return std::move(*Permit); }
            }
        }
        const Preview::AccountId AccountId_;
        const AccountRuntimeIdentity Identity_;
        const std::shared_ptr<Detail::RateLedger> Rate_;
        std::weak_ptr<Preview::Contract::AccountAdmissionAuthority> Authority_;
        std::atomic<std::uint64_t> Admission_{0U};
        std::atomic<std::uint64_t> Bytes_{0U};
        mutable std::atomic<std::shared_ptr<const DrainSignalList>> DrainSignals_{};
        mutable Preview::Fault::FailureState DrainFailure_;
    };
}
