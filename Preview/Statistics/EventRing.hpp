/**
 * @file EventRing.hpp
 * @brief 有界详细事件环及 terminal 保留配额。
 */

#pragma once

#include <Preview/Statistics/Redaction.hpp>
#include <Preview/Statistics/Types.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <utility>
#include <vector>

namespace Preview::Statistics
{

    enum class EventAppendStatus : std::uint8_t
    {
        Accepted,
        Dropped,
        TerminalDropped,
    };

    struct EventAppendResult final
    {
        EventAppendStatus Status{EventAppendStatus::Dropped};
        std::uint64_t Sequence{0};
        bool UsedReservation{false};

        [[nodiscard]] explicit operator bool() const noexcept
        {
            return Status == EventAppendStatus::Accepted;
        }
    };

    struct EventCounts final
    {
        std::size_t Size{0};
        std::size_t Capacity{0};
        std::size_t TerminalReservation{0};
        std::size_t TerminalReserved{0};
        std::uint64_t Dropped{0};
        std::uint64_t TerminalDropped{0};
    };

    struct EventPage final
    {
        std::vector<DetailedEvent> Items;
        std::uint64_t NextCursor{0};
        bool HasMore{false};
    };

    class EventRing final
    {
    public:
        struct Options final
        {
            std::size_t Capacity{1024};
            std::size_t TerminalReservation{16};
        };

        EventRing() noexcept : EventRing(Options{}) {}

        explicit EventRing(Options Value) noexcept
            : Capacity_(std::max<std::size_t>(Value.Capacity, 1)),
              TerminalReservation_(std::min(Value.TerminalReservation, Capacity_))
        {
        }

        [[nodiscard]] auto Append(DetailedEvent EventValue) -> EventAppendResult
        {
            if (Entries_.size() >= Capacity_)
            {
                if (EventValue.Terminal)
                {
                    ++TerminalDropped_;
                    return {EventAppendStatus::TerminalDropped, 0, false};
                }
                ++Dropped_;
                return {EventAppendStatus::Dropped, 0, false};
            }

            if (!EventValue.Terminal && Entries_.size() >= Capacity_ - TerminalReservation_)
            {
                ++Dropped_;
                return {EventAppendStatus::Dropped, 0, false};
            }

            EventValue.Sequence = ++NextSequence_;
            EventValue.Detail = RedactSensitiveText(EventValue.Detail);
            const bool UsedReservation = EventValue.Terminal &&
                                         TerminalReserved_ < TerminalReservation_;
            if (UsedReservation)
            {
                ++TerminalReserved_;
            }
            Entries_.push_back(std::move(EventValue));
            return {EventAppendStatus::Accepted, Entries_.back().Sequence, UsedReservation};
        }

        [[nodiscard]] auto Push(DetailedEvent EventValue) -> EventAppendResult
        {
            return Append(std::move(EventValue));
        }

        [[nodiscard]] auto Counts() const noexcept -> EventCounts
        {
            return EventCounts{Entries_.size(), Capacity_, TerminalReservation_, TerminalReserved_,
                               Dropped_, TerminalDropped_};
        }

        [[nodiscard]] auto Page(const std::uint64_t Cursor, std::size_t Limit) const -> EventPage
        {
            EventPage Result;
            if (Limit == 0)
            {
                Result.HasMore = std::any_of(Entries_.begin(), Entries_.end(),
                                             [Cursor](const DetailedEvent &EventValue)
                                             { return EventValue.Sequence > Cursor; });
                Result.NextCursor = Cursor;
                return Result;
            }

            for (const auto &EventValue : Entries_)
            {
                if (EventValue.Sequence <= Cursor)
                {
                    continue;
                }
                if (Result.Items.size() >= Limit)
                {
                    Result.HasMore = true;
                    break;
                }
                Result.Items.push_back(EventValue);
            }
            if (!Result.Items.empty())
            {
                Result.NextCursor = Result.Items.back().Sequence;
            }
            else
            {
                Result.NextCursor = Cursor;
            }
            return Result;
        }

        [[nodiscard]] auto Read(const std::uint64_t Cursor, const std::size_t Limit) const -> EventPage
        {
            return Page(Cursor, Limit);
        }

        [[nodiscard]] auto Snapshot() const -> std::vector<DetailedEvent>
        {
            return std::vector<DetailedEvent>(Entries_.begin(), Entries_.end());
        }

        auto Clear() noexcept -> void
        {
            Entries_.clear();
            TerminalReserved_ = 0;
            Dropped_ = 0;
            TerminalDropped_ = 0;
        }

    private:
        std::size_t Capacity_{1};
        std::size_t TerminalReservation_{0};
        std::size_t TerminalReserved_{0};
        std::uint64_t NextSequence_{0};
        std::uint64_t Dropped_{0};
        std::uint64_t TerminalDropped_{0};
        std::deque<DetailedEvent> Entries_;
    };

} // namespace Preview::Statistics
