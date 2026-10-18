/** @file TransferBudget.hpp
 * @brief 单账户跨 Worker 流量信用与双向带宽执行；数据库只通过异步端口调用。
 */
#pragma once
#include <Prism/Account/Detail/BandwidthBucket.hpp>
#include <Prism/Account/Detail/UsageCredit.hpp>
#include <Prism/Account/Policy.hpp>
#include <Prism/Account/UsagePersistence.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>

namespace Prism::Account
{
    namespace Net = boost::asio;

    /** @brief 应用装配输入持有正式存储和发布源，账户 Key 必须来自稳定配置身份。 */
    struct TransferBudgetOptions final
    {
        Prism::AccountId Id;
        std::string AccountKey;
        std::shared_ptr<PolicySource> Policies;
        std::shared_ptr<UsagePersistence> Persistence;
        std::string Incarnation;
    };

    /**
     * @brief 信用块只在慢路径分配；无带宽约束时每次 I/O 只操作共享原子信用。
     * @details 任何网络 executor 均可调用。只有补充/结清持久信用的慢路径互斥，
     *          gate 竞争通过可取消 timer 让出，不使用阻塞 mutex 或逐包 SQL。
     *          关闭网络仍由 relay；Application 停机须在数据面退休后调用 Flush(true)。
     */
    class TransferBudget final : public Contract::PayloadBudget,
        public std::enable_shared_from_this<TransferBudget>
    {
        using Failure = Fault::Failure;
        using Permit = Contract::PayloadPermit;
        static constexpr std::uint64_t BlockBytes{1024U * 1024U};
        class Gate final
        {
        public:
            explicit Gate(std::atomic_flag& Value) noexcept : Value_(&Value)
            { if (Value_->test_and_set(std::memory_order_acquire)) Value_ = nullptr; }
            ~Gate() { if (Value_) Value_->clear(std::memory_order_release); }
            [[nodiscard]] auto Acquired() const noexcept -> bool { return Value_ != nullptr; }
        private:
            std::atomic_flag* Value_;
        };
        class DirectionSettlement final : public Contract::PayloadSettlement
        {
        public:
            DirectionSettlement(std::shared_ptr<TransferBudget> Owner, const std::size_t Direction,
                Permit Credit) : Owner_(std::move(Owner)), Direction_(Direction), Credit_(std::move(Credit)) {}
            auto Complete(const std::uint64_t Granted, const std::uint64_t Transferred) noexcept -> void override
            {
                Credit_.Finish(Transferred);
                Owner_->Bandwidth_[Direction_].Refund(Granted - Transferred);
            }
        private:
            std::shared_ptr<TransferBudget> Owner_;
            const std::size_t Direction_;
            Permit Credit_;
        };
    public:
        explicit TransferBudget(TransferBudgetOptions Options) : Options_(std::move(Options)) {}

        [[nodiscard]] auto Acquire(Contract::PayloadRequest Request)
            -> Net::awaitable<std::expected<Permit, Failure>> override
        {
            if (Request.Bytes == 0 || Request.Bytes > BlockBytes ||
                (Request.Datagram && Request.Bytes > 65535))
                co_return std::unexpected(Failure{Fault::Code::InvalidArgument});
            for (;;)
            {
                const auto Policy = CurrentPolicy();
                if (!Policy) co_return std::unexpected(Failure{Fault::Code::Forbidden});
                const auto& Transfer = Policy->Settings().Transfer;
                const auto Direction = Request.Direction == Contract::PayloadDirection::Upload ? 0U : 1U;
                const auto Limit = Direction == 0 ? Transfer.UploadBytesPerSecond : Transfer.DownloadBytesPerSecond;
                const auto Decision = Bandwidth_[Direction].TryTake(Limit, Request);
                if (!Decision || Decision->Bytes == 0)
                {
                    const auto Wait = Decision ? Decision->Wait : std::chrono::milliseconds{1};
                    const auto Delayed = co_await Delay(Wait);
                    if (!Delayed) co_return std::unexpected(Delayed.error());
                    continue;
                }
                auto Candidate = Request;
                Candidate.Bytes = Decision->Bytes;
                auto Granted = co_await AcquireCredit(Candidate, Policy);
                if (!Granted)
                {
                    Bandwidth_[Direction].Refund(Candidate.Bytes);
                    if (Granted.error().Code == Fault::Code::WouldBlock) continue;
                    co_return std::unexpected(Granted.error());
                }
                Bandwidth_[Direction].Refund(Candidate.Bytes - Granted->Bytes());
                if (!Limit) co_return std::move(*Granted);
                const auto Bytes = Granted->Bytes();
                auto Settlement = std::make_shared<DirectionSettlement>(shared_from_this(), Direction, std::move(*Granted));
                co_return Permit{Bytes, std::move(Settlement)};
            }
        }

        /** @brief 准入只能使用已经查询过的账本；未知或存储失败不能退回不限额。 */
        [[nodiscard]] auto AdmissionAllowed() const noexcept -> bool
        {
            const auto Policy = CurrentPolicy();
            if (!Policy) return false;
            if (!Policy->Settings().Transfer.TrafficBytes) return true;
            if (*Policy->Settings().Transfer.TrafficBytes == 0) return false;
            const auto Credit = Credit_.load(std::memory_order_acquire);
            return (Credit && Credit->Available() != 0) || Available_.load(std::memory_order_acquire) != 0;
        }

        /** @brief 读取准确实时余额：持久快照与尚未 checkpoint 的实际信用消费只计算一次。 */
        [[nodiscard]] auto Read() -> Net::awaitable<std::expected<UsageSnapshot, Failure>>
        {
            const auto Policy = CurrentPolicy();
            if (!Policy || !Options_.Persistence) co_return std::unexpected(Failure{Fault::Code::ResourceUnavailable});
            for (;;)
            {
                Gate Guard(Gate_);
                if (!Guard.Acquired())
                {
                    const auto Waited = co_await Delay(std::chrono::milliseconds{1});
                    if (!Waited) co_return std::unexpected(Waited.error());
                    continue;
                }
                const auto Prepared = co_await Resolve(Policy);
                if (!Prepared) co_return std::unexpected(Prepared.error());
                const auto Checkpoint = co_await CheckpointCredit(false);
                if (!Checkpoint) co_return std::unexpected(Checkpoint.error());
                auto Snapshot = co_await Options_.Persistence->Read(
                    {Options_.AccountKey, *Prepared, Policy->Settings().Transfer.TrafficBytes});
                if (Snapshot) Available_.store(Snapshot->RemainingBytes, std::memory_order_release);
                co_return Snapshot;
            }
        }

        /** @brief 数据面退休后 Final=true 结清并释放；常规周期 checkpoint 不关闭仍在使用的信用。 */
        [[nodiscard]] auto Flush(const bool Final = false) -> Net::awaitable<std::expected<void, Failure>>
        {
            for (;;)
            {
                Gate Guard(Gate_);
                if (Guard.Acquired()) co_return co_await CheckpointCredit(Final);
                const auto Waited = co_await Delay(std::chrono::milliseconds{1});
                if (!Waited) co_return std::unexpected(Waited.error());
            }
        }

        [[nodiscard]] auto AccountKey() const noexcept -> std::string_view { return Options_.AccountKey; }
    private:
        [[nodiscard]] auto CurrentPolicy() const noexcept -> std::shared_ptr<const PolicySnapshot>
        { return Options_.Policies ? Options_.Policies->Load(Options_.Id) : nullptr; }

        [[nodiscard]] static auto Now() noexcept -> std::int64_t
        { return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }

        [[nodiscard]] static auto Delay(const std::chrono::milliseconds Duration)
            -> Net::awaitable<std::expected<void, Failure>>
        {
            Net::steady_timer Timer(co_await Net::this_coro::executor);
            Timer.expires_after(Duration);
            boost::system::error_code Error;
            co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
            if (Error) co_return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
            co_return std::expected<void, Failure>{};
        }

        [[nodiscard]] auto Resolve(const std::shared_ptr<const PolicySnapshot>& Policy)
            -> Net::awaitable<std::expected<UsageCycle, Failure>>
        {
            co_return co_await Options_.Persistence->ResolveCycle(
                {Options_.AccountKey, Policy->Settings().Transfer.Cycle, Now()});
        }

        [[nodiscard]] auto AcquireCredit(Contract::PayloadRequest Request,
            const std::shared_ptr<const PolicySnapshot>& Policy)
            -> Net::awaitable<std::expected<Permit, Failure>>
        {
            const auto Finite = Policy->Settings().Transfer.TrafficBytes;
            if (!Finite) co_return Permit{Request.Bytes};
            if (*Finite == 0) co_return std::unexpected(MakeFailure(FailureReason::ByteQuota));
            if (!Options_.Persistence) co_return std::unexpected(Failure{Fault::Code::ResourceUnavailable});
            for (;;)
            {
                const auto Credit = Credit_.load(std::memory_order_acquire);
                if (Credit && Version_.load(std::memory_order_acquire) == Policy->Version().Value() &&
                    (!Credit->Reservation().Cycle.End || Now() < *Credit->Reservation().Cycle.End))
                {
                    auto Granted = Credit->TryAcquire(Request);
                    if (Granted) co_return std::move(*Granted);
                }
                const auto Refilled = co_await Refill(Policy, Request);
                if (!Refilled) co_return std::unexpected(Refilled.error());
                const auto Current = CurrentPolicy();
                if (!Current || Current->Version() != Policy->Version())
                    co_return std::unexpected(Failure{Fault::Code::WouldBlock});
            }
        }

        [[nodiscard]] auto Refill(const std::shared_ptr<const PolicySnapshot>& Policy,
            const Contract::PayloadRequest& Request)
            -> Net::awaitable<std::expected<void, Failure>>
        {
            Gate Guard(Gate_);
            if (!Guard.Acquired()) co_return co_await Delay(std::chrono::milliseconds{1});
            const auto Credit = Credit_.load(std::memory_order_acquire);
            if (Credit)
            {
                const auto Enough = Request.Datagram ? Credit->Available() >= Request.Bytes : Credit->Available() != 0;
                if (Enough && Version_.load(std::memory_order_acquire) == Policy->Version().Value() &&
                    (!Credit->Reservation().Cycle.End || Now() < *Credit->Reservation().Cycle.End))
                    co_return std::expected<void, Failure>{};
                Credit->Close();
                if (!Credit->Idle()) co_return co_await Delay(std::chrono::milliseconds{1});
                const auto Settled = co_await CheckpointCredit(true);
                if (!Settled) co_return std::unexpected(Settled.error());
            }
            const auto Cycle = co_await Resolve(Policy);
            if (!Cycle) co_return std::unexpected(Cycle.error());
            const auto Sequence = Sequence_.fetch_add(1, std::memory_order_relaxed);
            if (Sequence == UINT64_MAX) co_return std::unexpected(Failure{Fault::Code::ResourceUnavailable});
            auto Reserved = co_await Options_.Persistence->Reserve({
                {Options_.AccountKey, *Cycle, Policy->Settings().Transfer.TrafficBytes},
                Options_.Incarnation + ":" + Options_.AccountKey + ":" + std::to_string(Sequence), BlockBytes, BlockBytes * 2});
            if (!Reserved) { Available_.store(0, std::memory_order_release); co_return std::unexpected(Reserved.error()); }
            if (Reserved->Bytes == 0 || Reserved->Bytes > BlockBytes)
                co_return std::unexpected(Failure{Fault::Code::InvalidArgument});
            Credit_.store(std::make_shared<Detail::UsageCredit>(std::move(*Reserved)), std::memory_order_release);
            Version_.store(Policy->Version().Value(), std::memory_order_release);
            co_return std::expected<void, Failure>{};
        }

        [[nodiscard]] auto CheckpointCredit(const bool Final)
            -> Net::awaitable<std::expected<void, Failure>>
        {
            const auto Credit = Credit_.load(std::memory_order_acquire);
            if (!Credit) co_return std::expected<void, Failure>{};
            if (Final)
            {
                Credit->Close();
                if (!Credit->Idle()) co_return std::unexpected(Failure{Fault::Code::WouldBlock});
            }
            const auto Settled = co_await Options_.Persistence->Settle(
                {Credit->Reservation().ReservationId, Credit->Consumed(), Final});
            if (!Settled) co_return std::unexpected(Settled.error());
            Available_.store(Settled->RemainingBytes, std::memory_order_release);
            if (Final) Credit_.store({}, std::memory_order_release);
            co_return std::expected<void, Failure>{};
        }

        const TransferBudgetOptions Options_;
        std::array<Detail::BandwidthBucket, 2> Bandwidth_;
        std::atomic<std::shared_ptr<Detail::UsageCredit>> Credit_;
        std::atomic<std::uint64_t> Version_{0};
        std::atomic<std::uint64_t> Available_{0};
        std::atomic<std::uint64_t> Sequence_{1};
        std::atomic_flag Gate_ = ATOMIC_FLAG_INIT;
    };
}
