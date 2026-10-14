/** @file QueryIds.hpp @brief DNS CSPRNG 在途 ID 的有界预约和无分配归还。 */
#pragma once

#include <Preview/Foundation/Exception/Deviant.hpp>
#include <Preview/Foundation/Utility/Crypto/Random.hpp>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <utility>

namespace Preview::Network::Dns
{
    namespace Detail
    {
        /** @brief 仅由冷路径构造抛出的 DNS 资源配置错误。 */
        class QueryIdConfigurationError final : public Exception::Deviant
        {
        public:
            QueryIdConfigurationError()
                : Exception::Deviant(Fault::make_error_code(Fault::Code::ConfigErr),
                                     "DNS 在途 ID 上限必须在 1 到 65536 之间") {}
        protected:
            [[nodiscard]] auto TypeName() const noexcept -> std::string_view override { return "DNS"; }
        };

        /** @brief 冷构造的单上游命名空间；预约保持状态真实存活。 */
        struct QueryIdState final
        {
            static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
            explicit QueryIdState(const std::size_t LimitValue) : Limit(LimitValue)
            {
                if (Limit == 0 || Limit > 65536) throw QueryIdConfigurationError();
            }
            std::array<std::atomic<std::uint64_t>, 1024> Words{};
            std::atomic<std::size_t> Active{0};
            const std::size_t Limit;

            [[nodiscard]] auto Enter() noexcept -> bool
            {
                auto Count = Active.load(std::memory_order_relaxed);
                for (std::size_t Attempt = 0; Attempt < 4 && Count < Limit; ++Attempt)
                    if (Active.compare_exchange_strong(Count, Count + 1, std::memory_order_acquire,
                                                       std::memory_order_relaxed)) return true;
                return false;
            }

            auto Release(const std::uint16_t Id) noexcept -> void
            {
                Words[Id / 64].fetch_and(~(std::uint64_t{1} << (Id % 64)), std::memory_order_release);
                Active.fetch_sub(1, std::memory_order_release);
            }
        };

        /** @brief Enter 前已成立的活动额度 owner；失败自动归还，成功才移交 ID 预约。 */
        class QuerySlot final
        {
        public:
            explicit QuerySlot(std::shared_ptr<QueryIdState> State) noexcept : State_(std::move(State)) {}
            ~QuerySlot() noexcept
            {
                if (Entered_) State_->Active.fetch_sub(1, std::memory_order_release);
            }
            QuerySlot(const QuerySlot&) = delete;
            auto operator=(const QuerySlot&) -> QuerySlot& = delete;
            [[nodiscard]] auto Enter() noexcept -> bool { Entered_ = State_->Enter(); return Entered_; }
            auto Transfer() noexcept -> void { Entered_ = false; }
        private:
            std::shared_ptr<QueryIdState> State_;
            bool Entered_{false};
        };
    }

    /**
     * @brief 独占在途 ID；移动转交真实 query owner，析构无分配归还一次。
     * @details 不能在取消命令发出时退休，须等所有关联 read/write/worker 实际退栈。
     *          没有 executor 或 socket 权限；不同预约可跨线程移动，本对象只串行访问。
     */
    class QueryIdReservation final
    {
    public:
        QueryIdReservation() noexcept = default;
        ~QueryIdReservation() noexcept { Release(); }
        QueryIdReservation(const QueryIdReservation&) = delete;
        auto operator=(const QueryIdReservation&) -> QueryIdReservation& = delete;
        QueryIdReservation(QueryIdReservation&& Other) noexcept
            : State_(std::move(Other.State_)), Id_(std::exchange(Other.Id_, 0)) {}
        auto operator=(QueryIdReservation&& Other) noexcept -> QueryIdReservation&
        {
            if (this != &Other)
            {
                Release();
                State_ = std::move(Other.State_);
                Id_ = std::exchange(Other.Id_, 0);
            }
            return *this;
        }
        [[nodiscard]] auto Id() const noexcept -> std::uint16_t { return Id_; }
        auto Release() noexcept -> void
        {
            if (State_) { State_->Release(Id_); State_.reset(); }
            Id_ = 0;
        }
    private:
        friend class QueryIds;
        QueryIdReservation(std::shared_ptr<Detail::QueryIdState> State, const std::uint16_t Id) noexcept
            : State_(std::move(State)), Id_(Id) {}
        std::shared_ptr<Detail::QueryIdState> State_;
        std::uint16_t Id_{0};
    };

    /** @brief 单真实上游 owner 的 ID 名字空间；不按进程全局猜测关联。 */
    class QueryIds final
    {
    public:
        /** @brief 冷分配固定 bitmap；非法上限抛项目配置异常，内存失败由启动边界处理。 */
        explicit QueryIds(const std::size_t MaxActive = 4096)
            : State_(std::make_shared<Detail::QueryIdState>(MaxActive)) {}
        QueryIds(const QueryIds&) = delete;
        auto operator=(const QueryIds&) -> QueryIds& = delete;

        /**
         * @brief 使用一次 CSPRNG 的十六个候选取得 ID，不扫描或等待无界历史。
         * @return 上限、冲突预算或并发额度不足为 ResourceUnavailable，随机失败保留 Crypto Failure。
         * @details 成功预约必须立即转交 query owner；所有失败均回滚活动额度，无动态分配。
         */
        [[nodiscard]] auto TryAcquire() -> std::expected<QueryIdReservation, Fault::Failure>
        {
            Detail::QuerySlot Slot(State_);
            if (!Slot.Enter())
                return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable, {}});
            std::array<std::uint8_t, 32> Random{};
            const auto Filled = Crypto::FillRandom(Random);
            if (!Filled)
            {
                return std::unexpected(Filled.error());
            }
            for (std::size_t Index = 0; Index < Random.size(); Index += 2)
            {
                const auto Id = static_cast<std::uint16_t>((Random[Index] << 8) | Random[Index + 1]);
                const auto Mask = std::uint64_t{1} << (Id % 64);
                const auto Before = State_->Words[Id / 64].fetch_or(Mask, std::memory_order_acq_rel);
                if ((Before & Mask) == 0)
                {
                    auto Reservation = QueryIdReservation(State_, Id);
                    Slot.Transfer();
                    return Reservation;
                }
            }
            return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable, {}});
        }

        [[nodiscard]] auto Active() const noexcept -> std::size_t
        { return State_->Active.load(std::memory_order_acquire); }
    private:
        std::shared_ptr<Detail::QueryIdState> State_;
    };
}
