/**
 * @file DnsCacheVariants.hpp
 * @brief DNS 缓存对照实验的 A/B/C 实现。
 * @details A 包装生产 Cache；B/C 提供固定槽 intrusive LRU 与 CLOCK 候选。
 */

#pragma once

#include <Prism/Net/Dns/Cache.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace Prism::Network::Dns::Compare
{
    namespace Dns = Prism::Network::Dns;

    using CacheResult = std::optional<Dns::IpList>;
    using CacheClock = std::chrono::steady_clock;

    struct TransparentStringHash
    {
        using is_transparent = void;

        template <typename Value>
        auto operator()(const Value& Input) const noexcept -> std::size_t
        {
            return std::hash<std::string_view>{}(std::string_view{Input});
        }
    };

    struct TransparentStringEqual
    {
        using is_transparent = void;

        template <typename Left, typename Right>
        auto operator()(const Left& LeftValue, const Right& RightValue) const noexcept -> bool
        {
            return std::string_view{LeftValue} == std::string_view{RightValue};
        }
    };

    using CurrentCache = Dns::Cache;

    struct IntrusiveLru
    {
    };

    struct ClockSecondChance
    {
    };

    template <typename Policy>
    class FixedSlotCache
    {
    public:
        explicit FixedSlotCache(Dns::CacheOptions Options) : Options_(Options)
        {
            if (Options_.MaxEntries != 0)
            {
                Slots_.resize(Options_.MaxEntries);
                Free_.reserve(Options_.MaxEntries);
                Index_.reserve(Options_.MaxEntries);
                for (std::size_t Index = Options_.MaxEntries; Index > 0; --Index)
                {
                    Free_.push_back(Index - 1);
                }
            }
        }

        [[nodiscard]] auto Get(const std::string& Domain, const std::uint16_t QType) -> CacheResult
        {
            const auto It = FindByDomain(Domain, QType);
            if (It == Index_.end())
            {
                return std::nullopt;
            }

            const auto SlotIndex = It->second;
            auto& Slot = Slots_[SlotIndex];
            if (CacheClock::now() >= Slot.Expire)
            {
                if (Options_.Policy == Dns::StalePolicy::Discard)
                {
                    ReleaseSlot(SlotIndex);
                    return std::nullopt;
                }
                Touch(SlotIndex);
                return Slot.Failed ? Dns::IpList{} : Slot.Ips;
            }

            Touch(SlotIndex);
            return Slot.Failed ? Dns::IpList{} : Slot.Ips;
        }

        void Put(const Dns::PutInput& Input)
        {
            auto Ttl = Input.Ttl;
            if (Options_.TtlMax > std::chrono::seconds{0})
            {
                Ttl = std::min(Ttl, Options_.TtlMax);
            }
            Ttl = std::max(Ttl, Options_.TtlMin);
            Store(Input, Ttl);
        }

        void PutNegative(const std::string& Domain, const std::uint16_t QType)
        {
            Dns::PutInput Input;
            Input.Domain = Domain;
            Input.QType = QType;
            Input.Ttl = Options_.NegativeTtl;
            Input.Failed = true;
            Store(Input, Options_.NegativeTtl);
        }

        auto EvictExpired() -> std::size_t
        {
            const auto Now = CacheClock::now();
            std::size_t Evicted = 0;
            for (std::size_t Index = 0; Index < Slots_.size(); ++Index)
            {
                if (Slots_[Index].Occupied && Now >= Slots_[Index].Expire)
                {
                    ReleaseSlot(Index);
                    ++Evicted;
                }
            }
            return Evicted;
        }

        [[nodiscard]] auto Size() const -> std::size_t
        {
            return LiveCount_;
        }

    private:
        static constexpr auto NoSlot = std::numeric_limits<std::size_t>::max();

        struct Slot
        {
            std::string_view Key;
            Dns::IpList Ips;
            CacheClock::time_point Expire{};
            std::size_t Previous{NoSlot};
            std::size_t Next{NoSlot};
            bool Occupied{false};
            bool Failed{false};
            bool Referenced{false};
        };

        using Index =
            std::unordered_map<std::string, std::size_t, TransparentStringHash, TransparentStringEqual>;

        static auto MakeKeyView(const std::string_view Domain, const std::uint16_t QType,
            std::array<char, 260>& Buffer) -> std::string_view
        {
            auto* Cursor = Buffer.data();
            std::memcpy(Cursor, Domain.data(), Domain.size());
            Cursor += Domain.size();
            *Cursor++ = ':';
            const auto Result = std::to_chars(Cursor, Buffer.data() + Buffer.size(), QType);
            return {Buffer.data(), static_cast<std::size_t>(Result.ptr - Buffer.data())};
        }

        auto FindByDomain(const std::string& Domain, const std::uint16_t QType) -> Index::iterator
        {
            if (Domain.size() > 253)
            {
                const auto Key = Dns::Cache::MakeKey(Domain, QType);
                return Index_.find(Key);
            }
            std::array<char, 260> Buffer{};
            return Index_.find(MakeKeyView(Domain, QType, Buffer));
        }

        void Store(const Dns::PutInput& Input, const std::chrono::seconds Ttl)
        {
            const auto Now = CacheClock::now();
            if (const auto It = FindByDomain(Input.Domain, Input.QType); It != Index_.end())
            {
                const auto SlotIndex = It->second;
                auto& Slot = Slots_[SlotIndex];
                Slot.Ips = Input.Ips;
                Slot.Expire = Now + Ttl;
                Slot.Failed = Input.Failed;
                Touch(SlotIndex);
                return;
            }

            const auto SlotIndex = AcquireSlot();
            auto& Slot = Slots_[SlotIndex];
            auto [It, Inserted] = Index_.emplace(Dns::Cache::MakeKey(Input.Domain, Input.QType), SlotIndex);
            if (!Inserted)
            {
                throw std::logic_error("fixed-slot cache duplicate insert");
            }
            Slot.Key = It->first;
            Slot.Ips = Input.Ips;
            Slot.Expire = Now + Ttl;
            Slot.Occupied = true;
            Slot.Failed = Input.Failed;
            Slot.Referenced = true;
            ++LiveCount_;
            Touch(SlotIndex);
        }

        auto AcquireSlot() -> std::size_t
        {
            if (!Free_.empty())
            {
                const auto Slot = Free_.back();
                Free_.pop_back();
                return Slot;
            }
            if (Options_.MaxEntries == 0)
            {
                Slots_.emplace_back();
                return Slots_.size() - 1;
            }
            return EvictForInsert();
        }

        auto EvictForInsert() -> std::size_t
        {
            std::size_t Victim = NoSlot;
            if constexpr (std::is_same_v<Policy, IntrusiveLru>)
            {
                Victim = Head_;
            }
            else
            {
                while (Slots_[ClockHand_].Referenced)
                {
                    Slots_[ClockHand_].Referenced = false;
                    ClockHand_ = (ClockHand_ + 1) % Slots_.size();
                }
                Victim = ClockHand_;
                ClockHand_ = (ClockHand_ + 1) % Slots_.size();
            }
            if (Victim == NoSlot)
            {
                throw std::logic_error("fixed-slot cache has no eviction victim");
            }
            EraseSlot(Victim);
            return Victim;
        }

        void Touch(const std::size_t SlotIndex)
        {
            if constexpr (std::is_same_v<Policy, IntrusiveLru>)
            {
                Unlink(SlotIndex);
                LinkNewest(SlotIndex);
            }
            else
            {
                Slots_[SlotIndex].Referenced = true;
            }
        }

        void LinkNewest(const std::size_t SlotIndex)
        {
            auto& Slot = Slots_[SlotIndex];
            Slot.Previous = Tail_;
            Slot.Next = NoSlot;
            if (Tail_ == NoSlot)
            {
                Head_ = SlotIndex;
            }
            else
            {
                Slots_[Tail_].Next = SlotIndex;
            }
            Tail_ = SlotIndex;
        }

        void Unlink(const std::size_t SlotIndex)
        {
            auto& Slot = Slots_[SlotIndex];
            if (Slot.Previous == NoSlot && Slot.Next == NoSlot && Head_ != SlotIndex)
            {
                return;
            }
            if (Slot.Previous == NoSlot)
            {
                Head_ = Slot.Next;
            }
            else
            {
                Slots_[Slot.Previous].Next = Slot.Next;
            }
            if (Slot.Next == NoSlot)
            {
                Tail_ = Slot.Previous;
            }
            else
            {
                Slots_[Slot.Next].Previous = Slot.Previous;
            }
            Slot.Previous = NoSlot;
            Slot.Next = NoSlot;
        }

        void EraseSlot(const std::size_t SlotIndex)
        {
            auto& Slot = Slots_[SlotIndex];
            if (!Slot.Occupied)
            {
                return;
            }
            if constexpr (std::is_same_v<Policy, IntrusiveLru>)
            {
                Unlink(SlotIndex);
            }
            const auto It = Index_.find(Slot.Key);
            if (It != Index_.end())
            {
                Index_.erase(It);
            }
            Slot.Key = {};
            Slot.Ips.clear();
            Slot.Occupied = false;
            Slot.Failed = false;
            Slot.Referenced = false;
            Slot.Previous = NoSlot;
            Slot.Next = NoSlot;
            --LiveCount_;
        }

        void ReleaseSlot(const std::size_t SlotIndex)
        {
            EraseSlot(SlotIndex);
            Free_.push_back(SlotIndex);
        }

        Dns::CacheOptions Options_;
        std::vector<Slot> Slots_;
        std::vector<std::size_t> Free_;
        Index Index_;
        std::size_t LiveCount_{0};
        std::size_t Head_{NoSlot};
        std::size_t Tail_{NoSlot};
        std::size_t ClockHand_{0};
    };

    using IntrusiveCache = FixedSlotCache<IntrusiveLru>;
    using ClockCache = FixedSlotCache<ClockSecondChance>;
} // namespace Prism::Network::Dns::Compare
