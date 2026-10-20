/** @file QueryIds.cpp @brief DNS 在途 ID 预约与无分配归还实现。 */
#include <Prism/Net/Dns/Detail/QueryIds.hpp>

#include <Prism/Foundation/Exception/Deviant.hpp>
#include <Prism/Foundation/Utility/Crypto/Random.hpp>

#include <array>
#include <atomic>
#include <string_view>
#include <utility>

namespace Prism::Network::Dns::Detail
{
    class QueryIdConfigurationError final : public Exception::Deviant
    {
    public:
        QueryIdConfigurationError()
            : Exception::Deviant(Fault::make_error_code(Fault::Code::ConfigErr),
                  "DNS 在途 ID 上限必须在 1 到 65536 之间")
        {
        }

    protected:
        [[nodiscard]] auto TypeName() const noexcept -> std::string_view override
        {
            return "DNS";
        }
    };

    struct QueryIdState final
    {
        static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

        explicit QueryIdState(const std::size_t LimitValue) : Limit(LimitValue)
        {
            if (Limit == 0 || Limit > 65536)
            {
                throw QueryIdConfigurationError();
            }
        }

        [[nodiscard]] auto Enter() noexcept -> bool
        {
            auto Count = Active.load(std::memory_order_relaxed);
            for (std::size_t Attempt = 0; Attempt < 4 && Count < Limit; ++Attempt)
            {
                if (Active.compare_exchange_strong(Count, Count + 1,
                        std::memory_order_acquire, std::memory_order_relaxed))
                {
                    return true;
                }
            }
            return false;
        }

        auto Release(const std::uint16_t Id) noexcept -> void
        {
            Words[Id / 64].fetch_and(
                ~(std::uint64_t{1} << (Id % 64)), std::memory_order_release);
            Active.fetch_sub(1, std::memory_order_release);
        }

        std::array<std::atomic<std::uint64_t>, 1024> Words{};
        std::atomic<std::size_t> Active{0};
        const std::size_t Limit;
    };

    /** @brief Enter 前已成立的活动额度 owner；失败自动归还，成功才移交 ID 预约。 */
    class QuerySlot final
    {
    public:
        explicit QuerySlot(std::shared_ptr<QueryIdState> StateValue) noexcept
            : State_(std::move(StateValue))
        {
        }

        ~QuerySlot() noexcept
        {
            if (Entered_)
            {
                State_->Active.fetch_sub(1, std::memory_order_release);
            }
        }

        QuerySlot(const QuerySlot &) = delete;
        auto operator=(const QuerySlot &) -> QuerySlot & = delete;

        [[nodiscard]] auto Enter() noexcept -> bool
        {
            Entered_ = State_->Enter();
            return Entered_;
        }

        auto Transfer() noexcept -> void
        {
            Entered_ = false;
        }

    private:
        std::shared_ptr<QueryIdState> State_;
        bool Entered_{false};
    };
}

namespace Prism::Network::Dns
{
    QueryIdReservation::QueryIdReservation(
        std::shared_ptr<Detail::QueryIdState> State, const std::uint16_t Id) noexcept
        : State_(std::move(State)), Id_(Id)
    {
    }

    QueryIdReservation::~QueryIdReservation() noexcept
    {
        Release();
    }

    QueryIdReservation::QueryIdReservation(QueryIdReservation &&Other) noexcept
        : State_(std::move(Other.State_)), Id_(std::exchange(Other.Id_, 0))
    {
    }

    auto QueryIdReservation::operator=(QueryIdReservation &&Other) noexcept
        -> QueryIdReservation &
    {
        if (this != &Other)
        {
            Release();
            State_ = std::move(Other.State_);
            Id_ = std::exchange(Other.Id_, 0);
        }
        return *this;
    }

    auto QueryIdReservation::Id() const noexcept -> std::uint16_t
    {
        return Id_;
    }

    auto QueryIdReservation::Release() noexcept -> void
    {
        if (State_)
        {
            State_->Release(Id_);
            State_.reset();
        }
        Id_ = 0;
    }

    QueryIds::QueryIds(const std::size_t MaxActive)
        : State_(std::make_shared<Detail::QueryIdState>(MaxActive))
    {
    }

    auto QueryIds::TryAcquire() -> std::expected<QueryIdReservation, Fault::Failure>
    {
        Detail::QuerySlot Slot(State_);
        if (!Slot.Enter())
        {
            return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable, {}});
        }
        std::array<std::uint8_t, 32> Random{};
        const auto Filled = Crypto::FillRandom(Random);
        if (!Filled)
        {
            return std::unexpected(Filled.error());
        }
        for (std::size_t Index = 0; Index < Random.size(); Index += 2)
        {
            const auto Id = static_cast<std::uint16_t>(
                (Random[Index] << 8) | Random[Index + 1]);
            const auto Mask = std::uint64_t{1} << (Id % 64);
            const auto Before = State_->Words[Id / 64].fetch_or(
                Mask, std::memory_order_acq_rel);
            if ((Before & Mask) == 0)
            {
                auto Reservation = QueryIdReservation(State_, Id);
                Slot.Transfer();
                return Reservation;
            }
        }
        return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable, {}});
    }

    auto QueryIds::Active() const noexcept -> std::size_t
    {
        return State_->Active.load(std::memory_order_acquire);
    }
} // namespace Prism::Network::Dns
