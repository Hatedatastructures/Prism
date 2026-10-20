/** @file TransferBudget.cpp
 * @brief 单账户信用准入、带宽归还与持久 checkpoint。
 */
#include <Prism/Account/TransferBudget.hpp>
#include <Prism/Account/Detail/TransferRequestKey.hpp>
#include <Prism/Account/Detail/TransferSequence.hpp>

#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cmath>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace
{
    /** @brief 为持久预算owner分配不回绕的进程内ticket。 */
    [[nodiscard]] auto TakeTransferBudgetNamespace(const Prism::Account::TransferBudgetOptions& Options)
        noexcept -> std::uint64_t
    {
        if (!Options.Persistence || Options.Incarnation.empty()) { return 0U; }
        static std::atomic<std::uint64_t> NextNamespace{1U};
        const auto Namespace = Prism::Account::Detail::TryTakeRequestSequence(NextNamespace);
        return Namespace.value_or(0U);
    }
}

namespace Prism::Account::Detail
{
    /** @brief 单个已持久预约的无锁信用状态；成功量只转入实际用量。 */
    class UsageCredit final : public Contract::PayloadSettlement,
        public std::enable_shared_from_this<UsageCredit>
    {
        static constexpr unsigned Width{21};
        static constexpr std::uint64_t Mask{(std::uint64_t{1} << Width) - 1U};
        static constexpr std::uint64_t Closed{std::uint64_t{1} << 63U};

    public:
        explicit UsageCredit(UsageReservation Reservation)
            : Reservation_(std::move(Reservation)), State_(Reservation_.Bytes)
        {
        }

        [[nodiscard]] auto Reservation() const noexcept -> const UsageReservation&
        {
            return Reservation_;
        }

        [[nodiscard]] auto TryAcquire(const Contract::PayloadRequest& Request)
            -> std::expected<Contract::PayloadPermit, Fault::Failure>
        {
            auto State = State_.load(std::memory_order_acquire);
            for (;;)
            {
                const auto Count = (std::min)(Request.Bytes, State & Mask);
                if ((State & Closed) || Count == 0 || (Request.Datagram && Count < Request.Bytes))
                {
                    return std::unexpected(Fault::Failure{Fault::Code::WouldBlock});
                }
                const auto Next = State - Count + (Count << Width);
                if (State_.compare_exchange_weak(
                    State, Next, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return Contract::PayloadPermit{Count, shared_from_this()};
                }
            }
        }

        auto Complete(const std::uint64_t Granted, const std::uint64_t Transferred) noexcept -> void override
        {
            auto State = State_.load(std::memory_order_acquire);
            for (;;)
            {
                const auto Next = State - (Granted << Width) + (Granted - Transferred) +
                    (Transferred << (Width * 2));
                if (State_.compare_exchange_weak(
                    State, Next, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return;
                }
            }
        }

        auto Close() noexcept -> void
        {
            State_.fetch_or(Closed, std::memory_order_acq_rel);
        }

        [[nodiscard]] auto Idle() const noexcept -> bool
        {
            return ((State_.load(std::memory_order_acquire) >> Width) & Mask) == 0;
        }

        [[nodiscard]] auto Consumed() const noexcept -> std::uint64_t
        {
            return (State_.load(std::memory_order_acquire) >> (Width * 2)) & Mask;
        }

        [[nodiscard]] auto Available() const noexcept -> std::uint64_t
        {
            return State_.load(std::memory_order_acquire) & Mask;
        }

    private:
        const UsageReservation Reservation_;
        std::atomic<std::uint64_t> State_;
    };

    auto BandwidthBucket::TryTake(const std::optional<std::uint64_t> Limit,
        const Contract::PayloadRequest& Request) noexcept
        -> std::expected<BandwidthDecision, Fault::Failure>
    {
        if (Gate_.test_and_set(std::memory_order_acquire))
        {
            return std::unexpected(MakeFailure(FailureReason::Busy));
        }
        struct Release final
        {
            std::atomic_flag& Gate;
            ~Release() { Gate.clear(std::memory_order_release); }
        } Guard{Gate_};
        const auto Now = std::chrono::steady_clock::now();
        Refill(Now);
        if (Limit != Limit_ || !Initialized_)
        {
            const auto Capacity = static_cast<long double>((std::max)(Limit.value_or(0), std::uint64_t{65535}));
            if (!Initialized_) { Tokens_ = Capacity; }
            else { Tokens_ = (std::min)(Tokens_, Capacity); }
            Limit_ = Limit;
            Initialized_ = true;
        }
        if (!Limit) { return BandwidthDecision{Request.Bytes, std::chrono::milliseconds{0}}; }
        if (*Limit == 0) { return BandwidthDecision{0, std::chrono::milliseconds{1000}}; }
        const auto Available = static_cast<std::uint64_t>((std::min)(Tokens_,
            static_cast<long double>(Request.Bytes)));
        if (Available != 0 && (!Request.Datagram || Available == Request.Bytes))
        {
            Tokens_ -= static_cast<long double>(Available);
            return BandwidthDecision{Available, std::chrono::milliseconds{0}};
        }
        auto Needed = static_cast<long double>(Request.Datagram ? Request.Bytes : 1U) - Tokens_;
        const auto Milliseconds = std::ceil(Needed * 1000.0L / static_cast<long double>(*Limit));
        return BandwidthDecision{0, std::chrono::milliseconds{
            static_cast<std::int64_t>((std::clamp)(Milliseconds, 1.0L, 1000.0L))}};
    }

    auto BandwidthBucket::Refund(const std::uint64_t Bytes) noexcept -> void
    {
        if (Bytes == 0 || Gate_.test_and_set(std::memory_order_acquire)) { return; }
        if (Limit_)
        {
            Tokens_ = (std::min)(Tokens_ + static_cast<long double>(Bytes),
                static_cast<long double>((std::max)(*Limit_, std::uint64_t{65535})));
        }
        Gate_.clear(std::memory_order_release);
    }

    auto BandwidthBucket::Refill(const std::chrono::steady_clock::time_point Now) noexcept -> void
    {
        if (Initialized_ && Limit_)
        {
            const auto Elapsed = std::chrono::duration<long double>(Now - Updated_).count();
            const auto Capacity = static_cast<long double>((std::max)(*Limit_, std::uint64_t{65535}));
            Tokens_ = (std::min)(Capacity, Tokens_ + Elapsed * static_cast<long double>(*Limit_));
        }
        Updated_ = Now;
    }
}

namespace Prism::Account
{
    class TransferBudget::Gate final
    {
    public:
        explicit Gate(std::atomic_flag& Value) noexcept : Value_(&Value)
        {
            if (Value_->test_and_set(std::memory_order_acquire)) { Value_ = nullptr; }
        }

        ~Gate()
        {
            if (Value_) { Value_->clear(std::memory_order_release); }
        }

        [[nodiscard]] auto Acquired() const noexcept -> bool
        {
            return Value_ != nullptr;
        }

    private:
        std::atomic_flag* Value_;
    };

    class TransferBudget::DirectionSettlement final : public Contract::PayloadSettlement
    {
    public:
        DirectionSettlement(std::shared_ptr<TransferBudget> Owner, const std::size_t Direction,
            Permit Credit)
            : Owner_(std::move(Owner)), Direction_(Direction), Credit_(std::move(Credit))
        {
        }

        auto Complete(const std::uint64_t Granted, const std::uint64_t Transferred) noexcept -> void override;

    private:
        std::shared_ptr<TransferBudget> Owner_;
        const std::size_t Direction_;
        Permit Credit_;
    };

    TransferBudget::TransferBudget(TransferBudgetOptions Options)
        : Options_(std::move(Options)), RequestNamespace_(TakeTransferBudgetNamespace(Options_))
    {
    }

    TransferBudget::~TransferBudget() = default;

    auto TransferBudget::Acquire(Contract::PayloadRequest Request)
        -> Net::awaitable<std::expected<Permit, Failure>>
    {
        if (Request.Bytes == 0 || Request.Bytes > BlockBytes ||
            (Request.Datagram && Request.Bytes > 65535))
        {
            co_return std::unexpected(Failure{Fault::Code::InvalidArgument});
        }
        for (;;)
        {
            const auto Policy = CurrentPolicy();
            if (!Policy) { co_return std::unexpected(Failure{Fault::Code::Forbidden}); }
            const auto& Transfer = Policy->Settings().Transfer;
            const auto Direction = Request.Direction == Contract::PayloadDirection::Upload ? 0U : 1U;
            const auto Limit = Direction == 0 ? Transfer.UploadBytesPerSecond : Transfer.DownloadBytesPerSecond;
            const auto Decision = Bandwidth_[Direction].TryTake(Limit, Request);
            if (!Decision || Decision->Bytes == 0)
            {
                const auto Wait = Decision ? Decision->Wait : std::chrono::milliseconds{1};
                const auto Delayed = co_await Delay(Wait);
                if (!Delayed) { co_return std::unexpected(Delayed.error()); }
                continue;
            }
            auto Candidate = Request;
            Candidate.Bytes = Decision->Bytes;
            auto Granted = co_await AcquireCredit(Candidate, Policy);
            if (!Granted)
            {
                Bandwidth_[Direction].Refund(Candidate.Bytes);
                if (Granted.error().Code == Fault::Code::WouldBlock) { continue; }
                co_return std::unexpected(Granted.error());
            }
            Bandwidth_[Direction].Refund(Candidate.Bytes - Granted->Bytes());
            if (!Limit) { co_return std::move(*Granted); }
            const auto Bytes = Granted->Bytes();
            auto Settlement = std::make_shared<DirectionSettlement>(
                shared_from_this(), Direction, std::move(*Granted));
            co_return Permit{Bytes, std::move(Settlement)};
        }
    }

    auto TransferBudget::AdmissionAllowed() const noexcept -> bool
    {
        const auto Policy = CurrentPolicy();
        if (!Policy) { return false; }
        if (!Policy->Settings().Transfer.TrafficBytes) { return true; }
        if (*Policy->Settings().Transfer.TrafficBytes == 0) { return false; }
        const auto Credit = Credit_.load(std::memory_order_acquire);
        return (Credit && Credit->Available() != 0) || Available_.load(std::memory_order_acquire) != 0;
    }

    auto TransferBudget::Read() -> Net::awaitable<std::expected<UsageSnapshot, Failure>>
    {
        const auto Policy = CurrentPolicy();
        if (!Policy || !Options_.Persistence)
        {
            co_return std::unexpected(Failure{Fault::Code::ResourceUnavailable});
        }
        for (;;)
        {
            Gate Guard(Gate_);
            if (!Guard.Acquired())
            {
                const auto Waited = co_await Delay(std::chrono::milliseconds{1});
                if (!Waited) { co_return std::unexpected(Waited.error()); }
                continue;
            }
            const auto Prepared = co_await Resolve(Policy);
            if (!Prepared) { co_return std::unexpected(Prepared.error()); }
            const auto Checkpoint = co_await CheckpointCredit(false);
            if (!Checkpoint) { co_return std::unexpected(Checkpoint.error()); }
            auto Snapshot = co_await Options_.Persistence->Read(
                {Options_.AccountKey, *Prepared, Policy->Settings().Transfer.TrafficBytes});
            if (Snapshot) { Available_.store(Snapshot->RemainingBytes, std::memory_order_release); }
            co_return Snapshot;
        }
    }

    auto TransferBudget::Flush(const bool Final) -> Net::awaitable<std::expected<void, Failure>>
    {
        for (;;)
        {
            Gate Guard(Gate_);
            if (Guard.Acquired()) { co_return co_await CheckpointCredit(Final); }
            const auto Waited = co_await Delay(std::chrono::milliseconds{1});
            if (!Waited) { co_return std::unexpected(Waited.error()); }
        }
    }

    auto TransferBudget::AccountKey() const noexcept -> std::string_view
    {
        return Options_.AccountKey;
    }

    auto TransferBudget::CurrentPolicy() const noexcept -> std::shared_ptr<const PolicySnapshot>
    {
        return Options_.Policies ? Options_.Policies->Load(Options_.Id) : nullptr;
    }

    auto TransferBudget::Now() noexcept -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    auto TransferBudget::Delay(const std::chrono::milliseconds Duration)
        -> Net::awaitable<std::expected<void, Failure>>
    {
        Net::steady_timer Timer(co_await Net::this_coro::executor);
        Timer.expires_after(Duration);
        boost::system::error_code Error;
        co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (Error) { co_return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error))); }
        co_return std::expected<void, Failure>{};
    }

    auto TransferBudget::Resolve(const std::shared_ptr<const PolicySnapshot>& Policy)
        -> Net::awaitable<std::expected<UsageCycle, Failure>>
    {
        co_return co_await Options_.Persistence->ResolveCycle(
            {Options_.AccountKey, Policy->Settings().Transfer.Cycle, Now()});
    }

    auto TransferBudget::AcquireCredit(Contract::PayloadRequest Request,
        const std::shared_ptr<const PolicySnapshot>& Policy)
        -> Net::awaitable<std::expected<Permit, Failure>>
    {
        const auto Finite = Policy->Settings().Transfer.TrafficBytes;
        if (!Finite) { co_return Permit{Request.Bytes}; }
        if (*Finite == 0) { co_return std::unexpected(MakeFailure(FailureReason::ByteQuota)); }
        if (!Options_.Persistence) { co_return std::unexpected(Failure{Fault::Code::ResourceUnavailable}); }
        for (;;)
        {
            const auto Credit = Credit_.load(std::memory_order_acquire);
            if (Credit && Version_.load(std::memory_order_acquire) == Policy->Version().Value() &&
                (!Credit->Reservation().Cycle.End || Now() < *Credit->Reservation().Cycle.End))
            {
                auto Granted = Credit->TryAcquire(Request);
                if (Granted) { co_return std::move(*Granted); }
            }
            const auto Refilled = co_await Refill(Policy, Request);
            if (!Refilled) { co_return std::unexpected(Refilled.error()); }
            const auto Current = CurrentPolicy();
            if (!Current || Current->Version() != Policy->Version())
            {
                co_return std::unexpected(Failure{Fault::Code::WouldBlock});
            }
        }
    }

    auto TransferBudget::Refill(const std::shared_ptr<const PolicySnapshot>& Policy,
        const Contract::PayloadRequest& Request)
        -> Net::awaitable<std::expected<void, Failure>>
    {
        if (RequestNamespace_ == 0U)
        {
            co_return std::unexpected(Failure{Fault::Code::ResourceUnavailable});
        }
        Gate Guard(Gate_);
        if (!Guard.Acquired()) { co_return co_await Delay(std::chrono::milliseconds{1}); }
        const auto Credit = Credit_.load(std::memory_order_acquire);
        if (Credit)
        {
            const auto Enough = Request.Datagram ? Credit->Available() >= Request.Bytes : Credit->Available() != 0;
            if (Enough && Version_.load(std::memory_order_acquire) == Policy->Version().Value() &&
                (!Credit->Reservation().Cycle.End || Now() < *Credit->Reservation().Cycle.End))
            {
                co_return std::expected<void, Failure>{};
            }
            Credit->Close();
            if (!Credit->Idle()) { co_return co_await Delay(std::chrono::milliseconds{1}); }
            const auto Settled = co_await CheckpointCredit(true);
            if (!Settled) { co_return std::unexpected(Settled.error()); }
        }
        const auto Cycle = co_await Resolve(Policy);
        if (!Cycle) { co_return std::unexpected(Cycle.error()); }
        const auto Sequence = Detail::TryTakeRequestSequence(Sequence_);
        if (!Sequence) { co_return std::unexpected(Failure{Fault::Code::ResourceUnavailable}); }
        auto RequestKey = Detail::MakeTransferRequestKey({
            .Namespace = RequestNamespace_,
            .Incarnation = Options_.Incarnation,
            .AccountKey = Options_.AccountKey,
            .Sequence = *Sequence,
        });
        if (!RequestKey) { co_return std::unexpected(Failure{Fault::Code::ResourceUnavailable}); }
        auto Reserved = co_await Options_.Persistence->Reserve({
            {Options_.AccountKey, *Cycle, Policy->Settings().Transfer.TrafficBytes},
            std::move(*RequestKey),
            BlockBytes,
            BlockBytes * 2});
        if (!Reserved)
        {
            Available_.store(0, std::memory_order_release);
            co_return std::unexpected(Reserved.error());
        }
        if (Reserved->Bytes == 0 || Reserved->Bytes > BlockBytes)
        {
            co_return std::unexpected(Failure{Fault::Code::InvalidArgument});
        }
        Credit_.store(std::make_shared<Detail::UsageCredit>(std::move(*Reserved)), std::memory_order_release);
        Version_.store(Policy->Version().Value(), std::memory_order_release);
        co_return std::expected<void, Failure>{};
    }

    auto TransferBudget::CheckpointCredit(const bool Final)
        -> Net::awaitable<std::expected<void, Failure>>
    {
        const auto Credit = Credit_.load(std::memory_order_acquire);
        if (!Credit) { co_return std::expected<void, Failure>{}; }
        if (Final)
        {
            Credit->Close();
            if (!Credit->Idle()) { co_return std::unexpected(Failure{Fault::Code::WouldBlock}); }
        }
        const auto Settled = co_await Options_.Persistence->Settle(
            {Credit->Reservation().ReservationId, Credit->Consumed(), Final});
        if (!Settled) { co_return std::unexpected(Settled.error()); }
        Available_.store(Settled->RemainingBytes, std::memory_order_release);
        if (Final) { Credit_.store({}, std::memory_order_release); }
        co_return std::expected<void, Failure>{};
    }

    auto TransferBudget::DirectionSettlement::Complete(
        const std::uint64_t Granted, const std::uint64_t Transferred) noexcept -> void
    {
        Credit_.Finish(Transferred);
        Owner_->Bandwidth_[Direction_].Refund(Granted - Transferred);
    }
}
