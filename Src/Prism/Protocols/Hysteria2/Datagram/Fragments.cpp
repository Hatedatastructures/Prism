/**
 * @file Fragments.cpp
 * @brief Hysteria2 UDP 数据报分片编解码与重组实现。
 */
#include <Prism/Protocols/Hysteria2/Datagram/Fragments.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Prism::Hysteria2::Detail
{
    auto VarintSize(const std::uint64_t Value) noexcept -> std::size_t
    {
        if (Value <= 63U) return 1U;
        if (Value <= 16383U) return 2U;
        if (Value <= 1073741823U) return 4U;
        if (Value <= 4611686018427387903ULL) return 8U;
        return 0U;
    }

    auto ReadVarint(
        const std::span<const std::uint8_t> Data,
        std::size_t &Offset,
        std::uint64_t &Value) noexcept -> bool
    {
        if (Offset >= Data.size()) return false;
        const auto First = Data[Offset];
        const auto Length = std::size_t{1U} << (First >> 6U);
        if (Data.size() - Offset < Length) return false;
        Value = First & 0x3FU;
        for (std::size_t Index = 1U; Index < Length; ++Index)
            Value = (Value << 8U) | Data[Offset + Index];
        Offset += Length;
        return true;
    }

    auto MaxReferenceUdpFragmentPayload(const std::size_t AddressSize) noexcept
        -> std::optional<std::size_t>
    {
        if (AddressSize == 0U || AddressSize > 2048U) return {};
        const auto HeaderSize = 8U + VarintSize(AddressSize) + AddressSize;
        if (HeaderSize >= MaxDatagramFrameSize) return {};
        return MaxDatagramFrameSize - HeaderSize;
    }

    auto ParseReferenceUdpFragment(const std::span<const std::uint8_t> Data)
        -> std::expected<ReferenceUdpFragmentView, Error>
    {
        if (Data.size() < 9U) return std::unexpected(Error::BadMessage);
        if (Data.size() > MaxDatagramFrameSize)
            return std::unexpected(Error::BadLength);
        ReferenceUdpFragmentView Result;
        Result.SessionId = static_cast<std::uint32_t>(Data[0]) << 24U |
            static_cast<std::uint32_t>(Data[1]) << 16U |
            static_cast<std::uint32_t>(Data[2]) << 8U |
            static_cast<std::uint32_t>(Data[3]);
        Result.PacketId = static_cast<std::uint16_t>(Data[4]) << 8U |
            static_cast<std::uint16_t>(Data[5]);
        Result.FragmentId = Data[6];
        Result.FragmentCount = Data[7];
        if (Result.FragmentCount == 0U || Result.FragmentId >= Result.FragmentCount)
        {
            return std::unexpected(Error::BadMessage);
        }
        std::size_t Offset = 8U;
        std::uint64_t AddressSize = 0;
        if (!ReadVarint(Data, Offset, AddressSize) || AddressSize == 0U ||
            AddressSize > 2048U || AddressSize > Data.size() - Offset)
        {
            return std::unexpected(Error::BadMessage);
        }
        Result.Address = std::string_view(
            reinterpret_cast<const char *>(Data.data() + Offset),
            static_cast<std::size_t>(AddressSize));
        Offset += static_cast<std::size_t>(AddressSize);
        Result.Payload = Data.subspan(Offset);
        return Result;
    }

    auto ReferenceUdpFragmentReassembler::KeyHash::operator()(
        const Key &Value) const noexcept -> std::size_t
    {
        return (static_cast<std::size_t>(Value.SessionId) << 16U) | Value.PacketId;
    }

    auto ReferenceUdpFragmentReassembler::Accept(const ReferenceUdpFragmentView &Fragment)
        -> std::expected<std::optional<ReferenceUdpPacket>, Error>
    {
        if (!Valid(Fragment)) return std::unexpected(Error::BadMessage);
        const auto Now = std::chrono::steady_clock::now();
        Expire(Now);
        if (Fragment.FragmentCount == 1U)
            return std::optional<ReferenceUdpPacket>{Complete(Fragment)};
        const Key Identity{Fragment.SessionId, Fragment.PacketId};
        auto Entry = Pending_.find(Identity);
        if (Entry == Pending_.end()) Entry = Create(Identity, Fragment, Now);
        if (Entry == Pending_.end()) return std::unexpected(Error::BadLength);
        return Add(Entry, Fragment, Now);
    }

    auto ReferenceUdpFragmentReassembler::Valid(
        const ReferenceUdpFragmentView &Fragment) noexcept -> bool
    {
        return Fragment.FragmentCount != 0U && !Fragment.Address.empty() &&
            Fragment.Address.size() <= 2048U &&
            (Fragment.FragmentCount == 1U || !Fragment.Payload.empty()) &&
            Fragment.Payload.size() <= MaxUdpPayloadSize &&
            Fragment.FragmentId < Fragment.FragmentCount;
    }

    auto ReferenceUdpFragmentReassembler::Complete(
        const ReferenceUdpFragmentView &Fragment) -> ReferenceUdpPacket
    {
        return {Fragment.SessionId, Fragment.PacketId, std::string(Fragment.Address),
            std::vector<std::uint8_t>(Fragment.Payload.begin(), Fragment.Payload.end())};
    }

    auto ReferenceUdpFragmentReassembler::Expire(
        const std::chrono::steady_clock::time_point Now) -> void
    {
        for (auto Entry = Pending_.begin(); Entry != Pending_.end();)
        {
            if (Now - Entry->second.LastSeen <= UdpFragmentLifetime)
            {
                ++Entry;
                continue;
            }
            PendingBytes_ -= Entry->second.PayloadSize;
            Entry = Pending_.erase(Entry);
        }
    }

    auto ReferenceUdpFragmentReassembler::EvictOldest() -> void
    {
        auto Oldest = Pending_.end();
        for (auto Entry = Pending_.begin(); Entry != Pending_.end(); ++Entry)
            if (Oldest == Pending_.end() || Entry->second.LastSeen < Oldest->second.LastSeen)
                Oldest = Entry;
        if (Oldest == Pending_.end()) return;
        PendingBytes_ -= Oldest->second.PayloadSize;
        Pending_.erase(Oldest);
    }

    auto ReferenceUdpFragmentReassembler::Create(
        const Key &Identity,
        const ReferenceUdpFragmentView &Fragment,
        const std::chrono::steady_clock::time_point Now) -> PendingMap::iterator
    {
        while (Pending_.size() >= MaxPendingUdpPackets) EvictOldest();
        PendingPacket Packet;
        Packet.Address.assign(Fragment.Address);
        Packet.Fragments.resize(Fragment.FragmentCount);
        Packet.Received.resize(Fragment.FragmentCount);
        Packet.LastSeen = Now;
        return Pending_.emplace(Identity, std::move(Packet)).first;
    }

    auto ReferenceUdpFragmentReassembler::Add(
        PendingMap::iterator Entry,
        const ReferenceUdpFragmentView &Fragment,
        const std::chrono::steady_clock::time_point Now)
        -> std::expected<std::optional<ReferenceUdpPacket>, Error>
    {
        auto &Packet = Entry->second;
        if (Packet.Fragments.size() != Fragment.FragmentCount ||
            Packet.Address != Fragment.Address)
        {
            Remove(Entry);
            return std::unexpected(Error::BadMessage);
        }
        const auto Index = static_cast<std::size_t>(Fragment.FragmentId);
        if (Packet.Received[Index] != 0U)
        {
            if (SamePayload(Packet.Fragments[Index], Fragment.Payload))
            {
                Packet.LastSeen = Now;
                return std::optional<ReferenceUdpPacket>{};
            }
            Remove(Entry);
            return std::unexpected(Error::BadMessage);
        }
        if (!CanStore(Packet.PayloadSize, Fragment.Payload.size()))
        {
            Remove(Entry);
            return std::unexpected(Error::BadLength);
        }
        Packet.Fragments[Index].assign(Fragment.Payload.begin(), Fragment.Payload.end());
        Packet.Received[Index] = 1U;
        ++Packet.ReceivedCount;
        Packet.PayloadSize += Fragment.Payload.size();
        Packet.LastSeen = Now;
        PendingBytes_ += Fragment.Payload.size();
        if (Packet.ReceivedCount != Packet.Fragments.size())
            return std::optional<ReferenceUdpPacket>{};
        auto Result = Assemble(Entry);
        return std::optional<ReferenceUdpPacket>{std::move(Result)};
    }

    auto ReferenceUdpFragmentReassembler::CanStore(
        const std::size_t CurrentSize,
        const std::size_t NewSize) const noexcept -> bool
    {
        return NewSize <= MaxUdpPayloadSize - (std::min)(CurrentSize, MaxUdpPayloadSize) &&
            NewSize <= MaxPendingUdpBytes - (std::min)(PendingBytes_, MaxPendingUdpBytes);
    }

    auto ReferenceUdpFragmentReassembler::SamePayload(
        const std::vector<std::uint8_t> &Stored,
        const std::span<const std::uint8_t> Incoming) noexcept -> bool
    {
        return Stored.size() == Incoming.size() &&
            std::equal(Stored.begin(), Stored.end(), Incoming.begin());
    }

    auto ReferenceUdpFragmentReassembler::Assemble(PendingMap::iterator Entry)
        -> ReferenceUdpPacket
    {
        ReferenceUdpPacket Result;
        Result.SessionId = Entry->first.SessionId;
        Result.PacketId = Entry->first.PacketId;
        Result.Address = Entry->second.Address;
        Result.Payload.reserve(Entry->second.PayloadSize);
        for (const auto &Fragment : Entry->second.Fragments)
            Result.Payload.insert(Result.Payload.end(), Fragment.begin(), Fragment.end());
        Remove(Entry);
        return Result;
    }

    auto ReferenceUdpFragmentReassembler::Remove(PendingMap::iterator Entry) -> void
    {
        PendingBytes_ -= Entry->second.PayloadSize;
        Pending_.erase(Entry);
    }
}
