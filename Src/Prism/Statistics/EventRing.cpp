/** @file EventRing.cpp @brief 有界事件环的保存、驱逐与查询实现。 */
#include <Prism/Statistics/EventRing.hpp>

#include <Prism/Foundation/Utility/Text/Redaction.hpp>
#include <Prism/Foundation/Utility/Text/Truncate.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Prism::Statistics
{
    EventRing::EventRing() : EventRing(Options{}) {}

    EventRing::EventRing(Options Value)
        : Capacity_((std::max)(Value.Capacity, std::size_t{1})),
          Reservation_((std::min)(Value.TerminalReservation, Capacity_)),
          Entries_(std::make_unique<Slot[]>(Capacity_))
    {
        for (std::size_t Index = 0; Index < Capacity_; ++Index) Entries_[Index].Next = Index + 1;
        Entries_[Capacity_ - 1].Next = None;
        Free_ = 0;
    }

    auto EventRing::Append(DetailedEvent Event) -> EventAppendResult
    {
        if (NextSequence_ == std::numeric_limits<std::uint64_t>::max() ||
            (!Event.Terminal && Capacity_ == Reservation_)) return Drop(Event.Terminal);
        LimitDetail(Event);
        if (!Event.Terminal && Ordinary_ >= Capacity_ - Reservation_)
            Evict(FindOrdinary());
        else if (Size_ == Capacity_)
        {
            auto Index = FindOrdinary();
            if (Index == None) Index = Oldest_;
            Evict(Index);
        }
        const auto Index = Free_;
        if (Index == None) return Drop(Event.Terminal);
        Free_ = Entries_[Index].Next;
        Event.Sequence = ++NextSequence_;
        const auto Used = Event.Terminal && Terminal_ < Reservation_;
        if (Event.Terminal) ++Terminal_;
        else ++Ordinary_;
        Entries_[Index].Event = std::move(Event);
        LinkNewest(Index);
        ++Size_;
        return {EventAppendStatus::Accepted, NextSequence_, Used};
    }

    auto EventRing::Counts() const noexcept -> EventCounts
    {
        return {Size_, Capacity_, Reservation_, (std::min)(Terminal_, Reservation_),
            Dropped_, TerminalDropped_, Overwritten_};
    }

    auto EventRing::Page(std::uint64_t Cursor, std::size_t Limit) const -> EventPage
    {
        EventPage Result;
        const auto PageCursor = (std::min)(Cursor, NextSequence_);
        Result.NextCursor = PageCursor;
        Result.Dropped = Dropped_;
        Result.TerminalDropped = TerminalDropped_;
        Result.Overwritten = Overwritten_;
        Result.EarliestCursor = NextSequence_;
        if (Oldest_ != None) Result.EarliestCursor = Entries_[Oldest_].Event.Sequence;
        else if (NextSequence_ != std::numeric_limits<std::uint64_t>::max()) ++Result.EarliestCursor;
        if (PageCursor < Result.EarliestCursor && Result.EarliestCursor - PageCursor > 1)
            AddLoss(Result, {PageCursor + 1, Result.EarliestCursor - 1});
        auto Previous = PageCursor;
        for (auto Index = Oldest_; Index != None; Index = Entries_[Index].Next)
        {
            const auto& Event = Entries_[Index].Event;
            if (Event.Sequence <= PageCursor) continue;
            if (Result.Items.size() == Limit)
            {
                Result.HasMore = true;
                break;
            }
            if (Previous >= Result.EarliestCursor && Event.Sequence - Previous > 1)
                AddLoss(Result, {Previous + 1, Event.Sequence - 1});
            Result.Items.push_back(Event);
            Result.NextCursor = Event.Sequence;
            Previous = Event.Sequence;
        }
        return Result;
    }

    auto EventRing::Snapshot() const -> std::vector<DetailedEvent>
    {
        std::vector<DetailedEvent> Result;
        Result.reserve(Size_);
        for (auto Index = Oldest_; Index != None; Index = Entries_[Index].Next)
            Result.push_back(Entries_[Index].Event);
        return Result;
    }

    auto EventRing::Clear() noexcept -> void
    {
        while (Oldest_ != None) Evict(Oldest_);
        Dropped_ = 0;
        TerminalDropped_ = 0;
        Overwritten_ = 0;
    }

    auto EventRing::Drop(bool Terminal) noexcept -> EventAppendResult
    {
        if (Terminal)
        {
            ++TerminalDropped_;
            return {EventAppendStatus::TerminalDropped, 0, false};
        }
        ++Dropped_;
        return {};
    }

    auto EventRing::AddLoss(EventPage& Page, EventLoss Range) -> void
    {
        Page.Lost = true;
        Page.LostRanges.push_back(Range);
    }

    auto EventRing::LimitDetail(DetailedEvent& Event) -> void
    {
        constexpr std::size_t Limit = 8 * 1024;
        if (Event.Detail.size() > Limit)
        {
            const auto Size = Prism::Text::FinishTruncatedUtf8(std::span<char>(Event.Detail.data(), Limit));
            Event.Detail.resize(Size);
            Event.Truncated = true;
        }
        Event.Detail = Prism::Text::RedactSensitiveText(Event.Detail);
        if (Event.Detail.size() > Limit)
        {
            const auto Size = Prism::Text::FinishTruncatedUtf8(std::span<char>(Event.Detail.data(), Limit));
            Event.Detail.resize(Size);
            Event.Truncated = true;
        }
    }

    auto EventRing::FindOrdinary() const noexcept -> std::size_t
    {
        for (auto Index = Oldest_; Index != None; Index = Entries_[Index].Next)
            if (!Entries_[Index].Event.Terminal) return Index;
        return None;
    }

    auto EventRing::LinkNewest(std::size_t Index) noexcept -> void
    {
        auto& Slot = Entries_[Index];
        Slot.Previous = Newest_;
        Slot.Next = None;
        if (Newest_ == None) Oldest_ = Index;
        else Entries_[Newest_].Next = Index;
        Newest_ = Index;
    }

    auto EventRing::Evict(std::size_t Index) noexcept -> void
    {
        if (Index == None) return;
        auto& Slot = Entries_[Index];
        if (Slot.Previous == None) Oldest_ = Slot.Next;
        else Entries_[Slot.Previous].Next = Slot.Next;
        if (Slot.Next == None) Newest_ = Slot.Previous;
        else Entries_[Slot.Next].Previous = Slot.Previous;
        if (Slot.Event.Terminal) --Terminal_;
        else --Ordinary_;
        Slot.Event = {};
        Slot.Previous = None;
        Slot.Next = Free_;
        Free_ = Index;
        --Size_;
        ++Overwritten_;
    }
}
