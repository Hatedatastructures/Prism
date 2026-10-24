/** @file Cache.cpp @brief DNS 结果缓存与 LRU 实现。 */
#include <Prism/Net/Dns/Cache.hpp>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <iterator>
#include <utility>

namespace Prism::Network::Dns
{
    Cache::Cache(const CacheOptions Options)
        : Options_(Options), Unlimited_(Options.MaxEntries == 0)
    {
        if (!Unlimited_)
        {
            Slots_.reserve(Options.MaxEntries);
        }
    }

    auto Cache::Get(const std::string &Domain, const std::uint16_t QTypeValue)
        -> std::optional<IpList>
    {
        const auto Key = KeyView(Domain, QTypeValue);
        const auto It = Index_.find(Key);
        if (It == Index_.end())
        {
            return std::nullopt;
        }
        Entry &EntryValue = Slots_[It->second];
        if (std::chrono::steady_clock::now() >= EntryValue.Expire)
        {
            if (Options_.Policy == StalePolicy::Discard)
            {
                (void)Drop(It);
                return std::nullopt;
            }
            Promote(It->second);
            if (EntryValue.Failed)
            {
                return IpList{};
            }
            return EntryValue.Ips;
        }
        Promote(It->second);
        if (EntryValue.Failed)
        {
            return IpList{};
        }
        return EntryValue.Ips;
    }

    auto Cache::Put(const PutInput &Input) -> void
    {
        auto Ttl = Input.Ttl;
        if (Options_.TtlMax > std::chrono::seconds{0})
        {
            Ttl = std::min(Ttl, Options_.TtlMax);
        }
        Ttl = std::max(Ttl, Options_.TtlMin);
        if (!Input.Failed && Ttl <= std::chrono::seconds::zero())
        {
            return;
        }
        Store(Input, Ttl);
    }

    auto Cache::PutNegative(const std::string &Domain, const std::uint16_t QTypeValue) -> void
    {
        PutInput Input;
        Input.Domain = Domain;
        Input.QType = QTypeValue;
        Input.Ttl = Options_.NegativeTtl;
        Input.Failed = true;
        Store(Input, Options_.NegativeTtl);
    }

    auto Cache::EvictExpired() -> std::size_t
    {
        const auto Now = std::chrono::steady_clock::now();
        std::size_t Evicted = 0;
        for (auto It = Index_.begin(); It != Index_.end();)
        {
            const Entry &EntryValue = Slots_[It->second];
            if (Now >= EntryValue.Expire)
            {
                It = Drop(It);
                ++Evicted;
            }
            else
            {
                ++It;
            }
        }
        return Evicted;
    }

    auto Cache::Size() const -> std::size_t
    {
        return Index_.size();
    }

    auto Cache::Clear() -> void
    {
        Index_.clear();
        Oldest_ = NoSlot;
        Newest_ = NoSlot;
        Free_.clear();
        Slots_.clear();
        LiveCount_ = 0;
        if (!Unlimited_)
        {
            Slots_.reserve(Options_.MaxEntries);
        }
    }

    auto Cache::MakeKey(const std::string &Domain, const std::uint16_t QTypeValue)
        -> std::string
    {
        return Domain + ':' + std::to_string(QTypeValue);
    }

    auto Cache::KeyView(const std::string &Domain, const std::uint16_t QTypeValue)
        -> std::string_view
    {
        if (Domain.size() + 6 <= KeyBuf_.size())
        {
            auto *Cursor = KeyBuf_.data();
            std::memcpy(Cursor, Domain.data(), Domain.size());
            Cursor += Domain.size();
            *Cursor++ = ':';
            const auto End = std::to_chars(Cursor, KeyBuf_.data() + KeyBuf_.size(), QTypeValue);
            return {KeyBuf_.data(), static_cast<std::size_t>(End.ptr - KeyBuf_.data())};
        }
        HeapKey_ = MakeKey(Domain, QTypeValue);
        return HeapKey_;
    }

    auto Cache::Unlink(const std::size_t Slot) noexcept -> void
    {
        auto &EntryValue = Slots_[Slot];
        if (!EntryValue.Linked)
        {
            return;
        }
        if (EntryValue.Previous == NoSlot)
        {
            Oldest_ = EntryValue.Next;
        }
        else
        {
            Slots_[EntryValue.Previous].Next = EntryValue.Next;
        }
        if (EntryValue.Next == NoSlot)
        {
            Newest_ = EntryValue.Previous;
        }
        else
        {
            Slots_[EntryValue.Next].Previous = EntryValue.Previous;
        }
        EntryValue.Previous = NoSlot;
        EntryValue.Next = NoSlot;
        EntryValue.Linked = false;
    }

    auto Cache::Promote(const std::size_t Slot) noexcept -> void
    {
        Unlink(Slot);
        auto &EntryValue = Slots_[Slot];
        EntryValue.Previous = Newest_;
        EntryValue.Next = NoSlot;
        EntryValue.Linked = true;
        if (Newest_ == NoSlot)
        {
            Oldest_ = Slot;
        }
        else
        {
            Slots_[Newest_].Next = Slot;
        }
        Newest_ = Slot;
    }

    auto Cache::EvictOldest() -> void
    {
        if (Oldest_ == NoSlot)
        {
            return;
        }
        const auto Found = Index_.find(Slots_[Oldest_].Key);
        if (Found != Index_.end())
        {
            (void)Drop(Found);
        }
    }

    auto Cache::Drop(const Index::iterator EntryValue) -> Index::iterator
    {
        const auto Slot = EntryValue->second;
        Unlink(Slot);
        auto Next = std::next(EntryValue);
        Index_.erase(EntryValue);
        Slots_[Slot].Dead = true;
        --LiveCount_;
        Free_.push_back(Slot);
        return Next;
    }

    auto Cache::Store(const PutInput &Input, const std::chrono::seconds Ttl) -> void
    {
        const auto Key = MakeKey(Input.Domain, Input.QType);
        const auto Now = std::chrono::steady_clock::now();
        if (const auto It = Index_.find(Key); It != Index_.end())
        {
            (void)Drop(It);
        }
        if (!Unlimited_ && LiveCount_ >= Options_.MaxEntries)
        {
            EvictOldest();
        }

        std::size_t Slot;
        if (!Free_.empty())
        {
            Slot = Free_.back();
            Free_.pop_back();
        }
        else
        {
            Slot = Slots_.size();
            Slots_.resize(Slot + 1);
        }

        Entry Fresh;
        Fresh.Key = Key;
        Fresh.Ips = Input.Ips;
        Fresh.Expire = Now + Ttl;
        Fresh.Inserted = Now;
        Fresh.Failed = Input.Failed;
        Fresh.Dead = false;
        Slots_[Slot] = std::move(Fresh);
        Index_.emplace(Key, Slot);
        ++LiveCount_;
        Promote(Slot);
    }
} // namespace Prism::Network::Dns
