/** @file EventRing.hpp @brief 真实保留、终态配额与可检测丢失区间的有界事件环。 */
#pragma once
#include <Prism/Statistics/Types.hpp>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <vector>

namespace Prism::Statistics
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
        EventRing();
        explicit EventRing(Options Value);
        /**
         * @brief 普通事件可复用最老普通槽；终态可淘汰旧事件，至少保留指定数量的最新终态。
         * @details 序号单调不回绕。拥有正文在入口限制为 8 KiB 后脱敏；关闭无额外资源申请。
         */
        [[nodiscard]] auto Append(DetailedEvent Event) -> EventAppendResult;
        [[nodiscard]] auto Counts() const noexcept -> EventCounts;
        /** @brief 返回游标之后的真实事件、最早保留序号和缺口；查询分配仅发生在控制查询边界。 */
        [[nodiscard]] auto Page(std::uint64_t Cursor, std::size_t Limit) const -> EventPage;
        [[nodiscard]] auto Snapshot() const -> std::vector<DetailedEvent>;
        /** @brief 清除保留记录并释放正文，序号继续前进以让旧游标识别已清除区间。 */
        auto Clear() noexcept -> void;
    private:
        static constexpr auto None = std::numeric_limits<std::size_t>::max();
        struct Slot final { DetailedEvent Event; std::size_t Previous{None}, Next{None}; };
        [[nodiscard]] auto Drop(bool Terminal) noexcept -> EventAppendResult;
        static auto AddLoss(EventPage& Page, EventLoss Range) -> void;
        static auto LimitDetail(DetailedEvent& Event) -> void;
        [[nodiscard]] auto FindOrdinary() const noexcept -> std::size_t;
        auto LinkNewest(std::size_t Index) noexcept -> void;
        auto Evict(std::size_t Index) noexcept -> void;
        std::size_t Capacity_{1}, Reservation_{0}, Size_{0}, Ordinary_{0}, Terminal_{0};
        std::size_t Oldest_{None}, Newest_{None}, Free_{None};
        std::unique_ptr<Slot[]> Entries_;
        std::uint64_t NextSequence_{0}, Dropped_{0}, TerminalDropped_{0}, Overwritten_{0};
    };
}
