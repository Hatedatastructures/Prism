/** @file Runtime.cpp
 * @brief 账户运行时准入、额度和 drain 实现。
 */
#include <Prism/Account/Runtime.hpp>
#include <Prism/Account/Detail/RateLedger.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <exception>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace Prism::Account
{
        AccountRuntimeIdentity::AccountRuntimeIdentity(std::shared_ptr<const Token> TokenValue) noexcept
            : Token_(std::move(TokenValue)) {}

        auto AccountRuntimeIdentity::IsValid() const noexcept -> bool { return static_cast<bool>(Token_); }

        AccountRuntimeIdentity::operator bool() const noexcept { return IsValid(); }

        auto operator==(const AccountRuntimeIdentity &Left,
                               const AccountRuntimeIdentity &Right) noexcept -> bool
        {
            return !Left.Token_.owner_before(Right.Token_) &&
                   !Right.Token_.owner_before(Left.Token_);
        }

        auto operator<(const AccountRuntimeIdentity &Left,
                              const AccountRuntimeIdentity &Right) noexcept -> bool
        {
            return Left.Token_.owner_before(Right.Token_);
        }

        AccountRuntime::AccountRuntime(const Prism::AccountId Id, const std::uint32_t Workers)
            : AccountId_(Id), Identity_(CreateIdentity()),
              Rate_(std::make_shared<Detail::RateLedger>(Workers)) {}

        auto AccountRuntime::AccountId() const noexcept -> Prism::AccountId { return AccountId_; }

        auto AccountRuntime::RuntimeIdentity() const noexcept -> AccountRuntimeIdentity { return Identity_; }

        auto AccountRuntime::RateLedger() const noexcept -> const std::shared_ptr<Detail::RateLedger>& { return Rate_; }

        auto AccountRuntime::IsRevoked() const noexcept -> bool
        {
            const auto Authority = Authority_.lock();
            if (!Authority) { return true; }
            const auto Snapshot = Authority->Load();
            return !Snapshot || Snapshot->IsRevoked(AccountId_);
        }

        auto AccountRuntime::ActiveConnections() const noexcept -> std::uint32_t
        {
            return static_cast<std::uint32_t>(Admission_.load(std::memory_order_acquire) & CountMask);
        }

        auto AccountRuntime::ActiveStreams() const noexcept -> std::uint32_t
        {
            return static_cast<std::uint32_t>((Admission_.load(std::memory_order_relaxed) >> StreamShift) & CountMask);
        }

        auto AccountRuntime::UsedBytes() const noexcept -> std::uint64_t { return Bytes_.load(std::memory_order_relaxed); }

        auto AccountRuntime::ResourcePolicySource() const noexcept -> std::shared_ptr<PolicySource>
        { return PolicySource_.lock(); }

        auto AccountRuntime::Transfer() const noexcept -> std::shared_ptr<TransferBudget>
        {
            const std::scoped_lock Guard(MutableStateGate_);
            return Transfer_;
        }

        auto AccountRuntime::StableKey() const -> std::string
        {
            const std::scoped_lock Guard(MutableStateGate_);
            return StableKey_;
        }

        auto AccountRuntime::WaitForNoActiveConnections(const LeaseDrainDeadline Limit) const
            -> Net::awaitable<LeaseDrainOutcome>
        {
            return WaitForNoActiveConnectionsOwned(weak_from_this().lock(), Limit);
        }

        auto AccountRuntime::AttachAuthority(
            const std::weak_ptr<Prism::Contract::AccountAdmissionAuthority> &Authority) noexcept
            -> void
        {
            Authority_ = Authority;
        }

        auto AccountRuntime::AttachPolicySource(const std::weak_ptr<PolicySource>& Source) noexcept -> void
        { PolicySource_ = Source; }

        auto AccountRuntime::AttachTransfer(std::shared_ptr<TransferBudget> Budget) noexcept -> void
        {
            const std::scoped_lock Guard(MutableStateGate_);
            Transfer_ = std::move(Budget);
        }

        auto AccountRuntime::ApplyStableKeyAndTransfer(
            std::string StableKey,
            std::shared_ptr<TransferBudget> Transfer) noexcept -> void
        {
            const std::scoped_lock Guard(MutableStateGate_);
            StableKey_ = std::move(StableKey);
            Transfer_ = std::move(Transfer);
        }

        auto AccountRuntime::WaitForNoActiveConnectionsOwned(
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

        auto AccountRuntime::CreateIdentity() -> AccountRuntimeIdentity
        {
            return AccountRuntimeIdentity(std::make_shared<const AccountRuntimeIdentity::Token>());
        }

        auto AccountRuntime::FailureFromException(const std::exception_ptr &ExceptionValue) noexcept
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

        auto AccountRuntime::WaitUntil(const LeaseDrainDeadline Limit)
            -> Net::awaitable<boost::system::error_code>
        {
            const auto Executor = co_await Net::this_coro::executor;
            Net::steady_timer Timer(Executor);
            Timer.expires_at(Limit);
            boost::system::error_code Error;
            co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
            co_return Error;
        }

        auto AccountRuntime::RegisterDrainSignal(const std::shared_ptr<DrainSignal> &Signal) const -> void
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

        auto AccountRuntime::NotifyDrainSignals() noexcept -> void
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

        auto AccountRuntime::TryAcquireConnection(const std::optional<std::uint32_t> Limit) noexcept
            -> std::expected<Prism::Contract::AccountAdmissionPermit, Failure>
        {
            return Acquire(Limit, 0U);
        }

        auto AccountRuntime::TryAcquireStream(const std::optional<std::uint32_t> Limit) noexcept
            -> std::expected<Prism::Contract::AccountAdmissionPermit, Failure>
        {
            return Acquire(Limit, StreamShift);
        }

        auto AccountRuntime::ReleaseConnection() noexcept -> void
        {
            const auto Previous = Admission_.fetch_sub(1U, std::memory_order_acq_rel);
            if ((Previous & CountMask) == 1U)
            {
                NotifyDrainSignals();
            }
        }

        auto AccountRuntime::ReleaseStream() noexcept -> void { Admission_.fetch_sub(std::uint64_t{1U} << StreamShift, std::memory_order_acq_rel); }

        auto AccountRuntime::ReserveBytes(const std::uint64_t Amount, const std::uint64_t Limit) noexcept
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

        auto AccountRuntime::ReleaseBytes(const std::uint64_t Amount) noexcept -> void { Bytes_.fetch_sub(Amount, std::memory_order_acq_rel); }

        auto AccountRuntime::Acquire(const std::optional<std::uint32_t> Limit, const unsigned Shift) noexcept
            -> std::expected<Prism::Contract::AccountAdmissionPermit, Failure>
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
                if (Count == CountMask || (Limit && Count >= *Limit))
                {
                    auto Reason = FailureReason::ConnectionQuota;
                    if (Shift != 0U) { Reason = FailureReason::StreamQuota; }
                    return std::unexpected(MakeFailure(Reason));
                }
                if (Admission_.compare_exchange_weak(State, State + (std::uint64_t{1U} << Shift),
                    std::memory_order_acq_rel, std::memory_order_acquire)) { return std::move(*Permit); }
            }
        }
}
