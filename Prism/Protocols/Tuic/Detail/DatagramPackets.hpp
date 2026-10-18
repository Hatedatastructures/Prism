/**
 * @file DatagramPackets.hpp
 * @brief TUIC 数据报分片构造与有界重组。
 */
#pragma once

#include <Prism/Protocols/Tuic/Codec.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Prism::Tuic::Detail
{
    inline constexpr std::size_t MaxDatagramFrameSize{1200};
    inline constexpr std::size_t MaxUdpPayloadSize{65507};
    inline constexpr std::size_t MaxPendingUdpPackets{64};
    inline constexpr std::size_t MaxPendingUdpBytes{1024U * 1024U};
    inline constexpr std::chrono::seconds UdpFragmentLifetime{3};
    inline constexpr std::size_t PacketHeaderSize{2U + 8U};

    /** @brief 一次 TUIC packet 的分片计划；发送缓冲由调用方复用。 */
    struct DatagramFragmentPlan final
    {
        std::uint8_t FragTotal{1};
        std::size_t FirstPayloadSize{MaxUdpPayloadSize};
        std::size_t LaterPayloadSize{MaxUdpPayloadSize};
    };

    /** @brief 一次 TUIC packet 的发送输入；payload 在计划生成期间借用。 */
    struct DatagramBuildRequest final
    {
        std::uint16_t AssocId{0};
        std::uint16_t PacketId{0};
        const Address &Destination;
        std::size_t PayloadSize{0};
        bool LimitFrameSize{false};
    };

    /** @brief 按实际地址头长度规划至多 1200 字节的 TUIC QUIC datagram 分片。 */
    template <typename Alloc>
    [[nodiscard]] inline auto BuildDatagramPlan(
        const DatagramBuildRequest &Request,
        std::vector<std::uint8_t, Alloc> &Scratch)
        -> std::expected<DatagramFragmentPlan, Error>
    {
        if (Request.PayloadSize > MaxUdpPayloadSize)
        {
            return std::unexpected(Error::BadLength);
        }
        Scratch.clear();
        if (!EncodeAddress(Request.Destination, Scratch))
        {
            return std::unexpected(Error::BadAddress);
        }
        const auto FirstHeaderSize = PacketHeaderSize + Scratch.size();
        if (!Request.LimitFrameSize)
        {
            return DatagramFragmentPlan{};
        }
        if (FirstHeaderSize >= MaxDatagramFrameSize)
        {
            return std::unexpected(Error::BadAddress);
        }
        const auto FirstPayloadSize = MaxDatagramFrameSize - FirstHeaderSize;
        if (Request.PayloadSize <= FirstPayloadSize)
        {
            return DatagramFragmentPlan{1, FirstPayloadSize, FirstPayloadSize};
        }

        const auto FragmentZeroPayloadSize = FirstPayloadSize;
        const auto LaterHeaderSize = PacketHeaderSize + 1U;
        const auto LaterPayloadSize = MaxDatagramFrameSize - LaterHeaderSize;
        if (FragmentZeroPayloadSize == 0U || LaterPayloadSize == 0U ||
            Request.PayloadSize <= FragmentZeroPayloadSize)
        {
            return std::unexpected(Error::BadLength);
        }
        const auto Remaining = Request.PayloadSize - FragmentZeroPayloadSize;
        const auto LaterCount = (Remaining + LaterPayloadSize - 1U) / LaterPayloadSize;
        if (LaterCount + 1U > 0xFFU)
        {
            return std::unexpected(Error::BadLength);
        }
        return DatagramFragmentPlan{
            static_cast<std::uint8_t>(LaterCount + 1U),
            FragmentZeroPayloadSize,
            LaterPayloadSize};
    }

    /** @brief 单个 UDP 关联与 packet ID 下尚未完整的 TUIC packet。 */
    class DatagramReassembler final
    {
        struct Key final
        {
            std::uint16_t AssocId{0};
            std::uint64_t PacketSequence{0};
            [[nodiscard]] auto operator==(const Key &) const noexcept -> bool = default;
        };

        struct KeyHash final
        {
            [[nodiscard]] auto operator()(const Key &Value) const noexcept -> std::size_t
            {
                const auto SequenceHash = std::hash<std::uint64_t>{}(Value.PacketSequence);
                return SequenceHash ^ (static_cast<std::size_t>(Value.AssocId) << 1U);
            }
        };

        /** @brief 分片存活期间将 16 位 packet ID 扩展到单调序号空间。 */
        struct SequenceState final
        {
            std::uint16_t LatestPacketId{0};
            std::uint64_t LatestSequence{0};
        };

        struct PendingPacket final
        {
            std::uint8_t FragTotal{0};
            std::optional<Address> Destination;
            std::vector<std::string> Fragments;
            std::vector<std::uint8_t> Received;
            std::size_t ReceivedCount{0};
            std::size_t PayloadSize{0};
            std::chrono::steady_clock::time_point LastSeen{};
        };

        using PendingMap = std::unordered_map<Key, PendingPacket, KeyHash>;

    public:
        /** @brief 接受一个已解析分片；完成时返回拥有型完整 packet，未完成时返回空 optional。 */
        [[nodiscard]] auto Accept(Message Fragment)
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

    private:
        [[nodiscard]] static auto Validate(const Message &Fragment) noexcept -> Error
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

        /** @brief 按半序空间展开 ID，容纳回绕及窗口内乱序分片。 */
        [[nodiscard]] auto ExtendPacketId(
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

        auto PruneSequences() -> void
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

        [[nodiscard]] auto Create(
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

        [[nodiscard]] auto Add(
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

        [[nodiscard]] auto CanStore(
            const PendingPacket &Packet,
            const std::size_t PayloadSize) const noexcept -> bool
        {
            return PayloadSize <= MaxUdpPayloadSize -
                       (std::min)(Packet.PayloadSize, MaxUdpPayloadSize) &&
                   PayloadSize <= MaxPendingUdpBytes -
                       (std::min)(PendingBytes_, MaxPendingUdpBytes);
        }

        [[nodiscard]] static auto SameAddress(
            const Address &Left,
            const Address &Right) noexcept -> bool
        {
            return Left.Type == Right.Type && Left.Host == Right.Host &&
                   Left.Port == Right.Port;
        }

        auto Expire(const std::chrono::steady_clock::time_point Now) -> void
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

        auto EvictOldest() -> void
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

        [[nodiscard]] auto Assemble(PendingMap::iterator Entry) -> Message
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

        auto Remove(PendingMap::iterator Entry) -> void
        {
            PendingBytes_ -= Entry->second.PayloadSize;
            Pending_.erase(Entry);
        }

        PendingMap Pending_;
        std::unordered_map<std::uint16_t, SequenceState> Sequences_;
        std::size_t PendingBytes_{0};
    };
} // namespace Prism::Tuic::Detail
