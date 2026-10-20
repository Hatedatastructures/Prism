/**
 * @file DatagramPackets.cpp
 * @brief TUIC 数据报分片与有界重组实现。
 */
#include <Prism/Protocols/Tuic/Detail/DatagramPackets.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

namespace Prism::Tuic::Detail
{
    auto DatagramReassembler::KeyHash::operator()(const Key &Value) const noexcept -> std::size_t
    {
        const auto SequenceHash = std::hash<std::uint64_t>{}(Value.PacketSequence);
        return SequenceHash ^ (static_cast<std::size_t>(Value.AssocId) << 1U);
    }

    auto DatagramReassembler::Accept(Message Fragment)
        -> std::expected<std::optional<Message>, Error>
    {
        const auto Validation = Validate(Fragment);
        if (Validation != Error::None)
        {
            return std::unexpected(Validation);
        }
        const auto Now = std::chrono::steady_clock::now();
        Expire(Now);
        const auto PacketSequence = ExtendPacketId(
            Fragment.AssocId, Fragment.PktId, Fragment.FragTotal > 1U);
        const Key Identity{Fragment.AssocId, PacketSequence};
        if (Fragment.FragTotal == 1U)
        {
            if (auto Entry = Pending_.find(Identity); Entry != Pending_.end())
            {
                Remove(Entry);
                PruneSequences();
            }
            return std::optional<Message>{std::move(Fragment)};
        }

        auto Entry = Pending_.find(Identity);
        if (Entry == Pending_.end())
        {
            Entry = Create(Identity, Fragment, Now);
            PruneSequences();
        }
        if (Entry == Pending_.end())
        {
            return std::unexpected(Error::BadLength);
        }
        auto Result = Add(Entry, Fragment, Now);
        if (!Result || Result->has_value()) PruneSequences();
        return Result;
    }

    auto DatagramReassembler::Validate(const Message &Fragment) noexcept -> Error
    {
        if (Fragment.Cmd != CmdPacket || Fragment.FragTotal == 0U ||
            Fragment.FragId >= Fragment.FragTotal)
        {
            return Error::BadMessage;
        }
        if (Fragment.payload.size() > MaxUdpPayloadSize)
        {
            return Error::BadLength;
        }
        if (Fragment.FragTotal == 1U)
        {
            return Fragment.FragId == 0U &&
                   Fragment.dst.Type != AddressType::None
                ? Error::None
                : Error::BadMessage;
        }
        if (Fragment.payload.empty())
        {
            return Error::BadMessage;
        }
        if ((Fragment.FragId == 0U && Fragment.dst.Type == AddressType::None) ||
            (Fragment.FragId != 0U && Fragment.dst.Type != AddressType::None))
        {
            return Error::BadMessage;
        }
        return Error::None;
    }

    auto DatagramReassembler::ExtendPacketId(
        const std::uint16_t AssocId,
        const std::uint16_t PacketId,
        const bool Track) -> std::uint64_t
    {
        auto Entry = Sequences_.find(AssocId);
        if (Entry == Sequences_.end())
        {
            if (!Track) return PacketId;
            return Sequences_.emplace(
                AssocId, SequenceState{PacketId, PacketId}).first->second.LatestSequence;
        }

        auto &Sequence = Entry->second;
        const auto Forward = static_cast<std::uint16_t>(PacketId - Sequence.LatestPacketId);
        if (Forward == 0U)
        {
            return Sequence.LatestSequence;
        }
        if (Forward < 0x8000U)
        {
            Sequence.LatestPacketId = PacketId;
            Sequence.LatestSequence += Forward;
            return Sequence.LatestSequence;
        }

        const auto Backward = static_cast<std::uint16_t>(Sequence.LatestPacketId - PacketId);
        if (Backward <= Sequence.LatestSequence)
        {
            return Sequence.LatestSequence - Backward;
        }
        return PacketId;
    }

    auto DatagramReassembler::PruneSequences() -> void
    {
        for (auto Sequence = Sequences_.begin(); Sequence != Sequences_.end();)
        {
            const auto HasPending = std::ranges::any_of(
                Pending_, [AssocId = Sequence->first](const auto &Entry)
                {
                    return Entry.first.AssocId == AssocId;
                });
            if (HasPending)
            {
                ++Sequence;
            }
            else
            {
                Sequence = Sequences_.erase(Sequence);
            }
        }
    }

    auto DatagramReassembler::Create(
        const Key &Identity,
        const Message &Fragment,
        const std::chrono::steady_clock::time_point Now) -> PendingMap::iterator
    {
        while (Pending_.size() >= MaxPendingUdpPackets)
        {
            EvictOldest();
        }
        PendingPacket Packet;
        Packet.FragTotal = Fragment.FragTotal;
        Packet.Fragments.resize(Fragment.FragTotal);
        Packet.Received.resize(Fragment.FragTotal);
        Packet.LastSeen = Now;
        if (Fragment.FragId == 0U)
        {
            Packet.Destination = Fragment.dst;
        }
        return Pending_.emplace(Identity, std::move(Packet)).first;
    }

    auto DatagramReassembler::Add(
        PendingMap::iterator Entry,
        const Message &Fragment,
        const std::chrono::steady_clock::time_point Now)
        -> std::expected<std::optional<Message>, Error>
    {
        auto &Packet = Entry->second;
        if (Packet.FragTotal != Fragment.FragTotal)
        {
            Remove(Entry);
            return std::unexpected(Error::BadMessage);
        }
        if (Fragment.FragId == 0U)
        {
            if (Packet.Destination && !SameAddress(*Packet.Destination, Fragment.dst))
            {
                Remove(Entry);
                return std::unexpected(Error::BadMessage);
            }
            Packet.Destination = Fragment.dst;
        }

        const auto Index = static_cast<std::size_t>(Fragment.FragId);
        if (Packet.Received[Index] != 0U)
        {
            if (Packet.Fragments[Index] != Fragment.payload)
            {
                Remove(Entry);
                return std::unexpected(Error::BadMessage);
            }
            Packet.LastSeen = Now;
            return std::optional<Message>{};
        }
        if (!CanStore(Packet, Fragment.payload.size()))
        {
            Remove(Entry);
            return std::unexpected(Error::BadLength);
        }

        Packet.Fragments[Index] = Fragment.payload;
        Packet.Received[Index] = 1U;
        ++Packet.ReceivedCount;
        Packet.PayloadSize += Fragment.payload.size();
        Packet.LastSeen = Now;
        PendingBytes_ += Fragment.payload.size();
        if (Packet.ReceivedCount != Packet.Fragments.size())
        {
            return std::optional<Message>{};
        }
        if (!Packet.Destination)
        {
            Remove(Entry);
            return std::unexpected(Error::BadMessage);
        }
        return std::optional<Message>{Assemble(Entry)};
    }

    auto DatagramReassembler::CanStore(
        const PendingPacket &Packet,
        const std::size_t PayloadSize) const noexcept -> bool
    {
        return PayloadSize <= MaxUdpPayloadSize -
                   (std::min)(Packet.PayloadSize, MaxUdpPayloadSize) &&
               PayloadSize <= MaxPendingUdpBytes -
                   (std::min)(PendingBytes_, MaxPendingUdpBytes);
    }

    auto DatagramReassembler::SameAddress(
        const Address &Left,
        const Address &Right) noexcept -> bool
    {
        return Left.Type == Right.Type && Left.Host == Right.Host &&
               Left.Port == Right.Port;
    }

    auto DatagramReassembler::Expire(const std::chrono::steady_clock::time_point Now) -> void
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
        PruneSequences();
    }

    auto DatagramReassembler::EvictOldest() -> void
    {
        auto Oldest = Pending_.end();
        for (auto Entry = Pending_.begin(); Entry != Pending_.end(); ++Entry)
        {
            if (Oldest == Pending_.end() ||
                Entry->second.LastSeen < Oldest->second.LastSeen)
            {
                Oldest = Entry;
            }
        }
        if (Oldest != Pending_.end())
        {
            PendingBytes_ -= Oldest->second.PayloadSize;
            Pending_.erase(Oldest);
        }
    }

    auto DatagramReassembler::Assemble(PendingMap::iterator Entry) -> Message
    {
        Message Result;
        Result.Cmd = CmdPacket;
        Result.AssocId = Entry->first.AssocId;
        Result.PktId = static_cast<std::uint16_t>(Entry->first.PacketSequence);
        Result.FragTotal = 1;
        Result.FragId = 0;
        Result.Size = static_cast<std::uint16_t>(Entry->second.PayloadSize);
        Result.dst = *Entry->second.Destination;
        Result.payload.reserve(Entry->second.PayloadSize);
        for (const auto &Part : Entry->second.Fragments)
        {
            Result.payload.append(Part);
        }
        Remove(Entry);
        return Result;
    }

    auto DatagramReassembler::Remove(PendingMap::iterator Entry) -> void
    {
        PendingBytes_ -= Entry->second.PayloadSize;
        Pending_.erase(Entry);
    }
}
