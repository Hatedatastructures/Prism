/** @file EventRing.hpp @brief 真实保留、终态配额与可检测丢失区间的有界事件环。 */
#pragma once
#include <Preview/Foundation/Utility/Text/Redaction.hpp>
#include <Preview/Foundation/Utility/Text/Truncate.hpp>
#include <Preview/Statistics/Types.hpp>
#include <algorithm>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

namespace Preview::Statistics
{
    enum class EventAppendStatus : std::uint8_t { Accepted, Dropped, TerminalDropped };
    struct EventAppendResult final
    {
        EventAppendStatus Status{EventAppendStatus::Dropped};
        std::uint64_t Sequence{0};
        bool UsedReservation{false};
        [[nodiscard]] explicit operator bool() const noexcept { return Status == EventAppendStatus::Accepted; }
    };
    struct EventCounts final
    {
        std::size_t Size{0}, Capacity{0}, TerminalReservation{0}, TerminalReserved{0};
        std::uint64_t Dropped{0}, TerminalDropped{0}, Overwritten{0};
    };
    /** @brief 已淘汰序号的闭区间，表示保留事实的缺口，不猜测事件内容。 */
    struct EventLoss final { std::uint64_t First{0}, Last{0}; };
    struct EventPage final
    {
        std::vector<DetailedEvent> Items;
        std::uint64_t NextCursor{0};
        bool HasMore{false};
        std::uint64_t EarliestCursor{0};
        bool Lost{false};
        std::vector<EventLoss> LostRanges;
        std::uint64_t Dropped{0};
        std::uint64_t TerminalDropped{0};
        std::uint64_t Overwritten{0};
    };
    /** @brief 控制 executor 独占；冷构造槽，Append 移交值，Page 返回不保活业务的拥有快照。 */
    class EventRing final
    {
    public:
        struct Options final { std::size_t Capacity{1024}; std::size_t TerminalReservation{16}; };
        EventRing() : EventRing(Options{}) {}
        explicit EventRing(Options Value)
            : Capacity_((std::max)(Value.Capacity, std::size_t{1})),
              Reservation_((std::min)(Value.TerminalReservation, Capacity_)),
              Entries_(std::make_unique<Slot[]>(Capacity_))
        {
            for (std::size_t Index = 0; Index < Capacity_; ++Index) Entries_[Index].Next = Index + 1;
            Entries_[Capacity_ - 1].Next = None;
            Free_ = 0;
        }
        /**
         * @brief 普通事件可复用最老普通槽；终态可淘汰旧事件，至少保留指定数量的最新终态。
         * @details 序号单调不回绕。拥有正文在入口限制为 8 KiB 后脱敏；关闭无额外资源申请。
         */
        [[nodiscard]] auto Append(DetailedEvent Event) -> EventAppendResult
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
        [[nodiscard]] auto Counts() const noexcept -> EventCounts
        { return {Size_, Capacity_, Reservation_, (std::min)(Terminal_, Reservation_), Dropped_, TerminalDropped_, Overwritten_}; }
        /** @brief 返回游标之后的真实事件、最早保留序号和缺口；查询分配仅发生在控制查询边界。 */
        [[nodiscard]] auto Page(std::uint64_t Cursor, std::size_t Limit) const -> EventPage
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
                if (Result.Items.size() == Limit) { Result.HasMore = true; break; }
                if (Previous >= Result.EarliestCursor && Event.Sequence - Previous > 1)
                    AddLoss(Result, {Previous + 1, Event.Sequence - 1});
                Result.Items.push_back(Event);
                Result.NextCursor = Event.Sequence;
                Previous = Event.Sequence;
            }
            return Result;
        }
        [[nodiscard]] auto Snapshot() const -> std::vector<DetailedEvent>
        {
            std::vector<DetailedEvent> Result;
            Result.reserve(Size_);
            for (auto Index = Oldest_; Index != None; Index = Entries_[Index].Next)
                Result.push_back(Entries_[Index].Event);
            return Result;
        }
        /** @brief 清除保留记录并释放正文，序号继续前进以让旧游标识别已清除区间。 */
        auto Clear() noexcept -> void
        {
            while (Oldest_ != None) Evict(Oldest_);
            Dropped_ = 0; TerminalDropped_ = 0; Overwritten_ = 0;
        }
    private:
        static constexpr auto None = std::numeric_limits<std::size_t>::max();
        struct Slot final { DetailedEvent Event; std::size_t Previous{None}, Next{None}; };
        [[nodiscard]] auto Drop(bool Terminal) noexcept -> EventAppendResult
        {
            if (Terminal) { ++TerminalDropped_; return {EventAppendStatus::TerminalDropped, 0, false}; }
            ++Dropped_; return {};
        }
        static auto AddLoss(EventPage& Page, EventLoss Range) -> void
        { Page.Lost = true; Page.LostRanges.push_back(Range); }
        static auto LimitDetail(DetailedEvent& Event) -> void
        {
            constexpr std::size_t Limit = 8 * 1024;
            if (Event.Detail.size() > Limit)
            {
                const auto Size = Preview::Text::FinishTruncatedUtf8(std::span<char>(Event.Detail.data(), Limit));
                Event.Detail.resize(Size);
                Event.Truncated = true;
            }
            Event.Detail = Preview::Text::RedactSensitiveText(Event.Detail);
            if (Event.Detail.size() > Limit)
            {
                const auto Size = Preview::Text::FinishTruncatedUtf8(std::span<char>(Event.Detail.data(), Limit));
                Event.Detail.resize(Size);
                Event.Truncated = true;
            }
        }
        [[nodiscard]] auto FindOrdinary() const noexcept -> std::size_t
        {
            for (auto Index = Oldest_; Index != None; Index = Entries_[Index].Next)
                if (!Entries_[Index].Event.Terminal) return Index;
            return None;
        }
        auto LinkNewest(std::size_t Index) noexcept -> void
        {
            auto& Slot = Entries_[Index];
            Slot.Previous = Newest_; Slot.Next = None;
            if (Newest_ == None) Oldest_ = Index;
            else Entries_[Newest_].Next = Index;
            Newest_ = Index;
        }
        auto Evict(std::size_t Index) noexcept -> void
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
            Slot.Previous = None; Slot.Next = Free_; Free_ = Index;
            --Size_; ++Overwritten_;
        }
        std::size_t Capacity_{1}, Reservation_{0}, Size_{0}, Ordinary_{0}, Terminal_{0};
        std::size_t Oldest_{None}, Newest_{None}, Free_{None};
        std::unique_ptr<Slot[]> Entries_;
        std::uint64_t NextSequence_{0}, Dropped_{0}, TerminalDropped_{0}, Overwritten_{0};
    };
}
