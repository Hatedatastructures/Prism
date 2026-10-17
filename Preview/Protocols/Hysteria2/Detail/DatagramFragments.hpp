/** @file DatagramFragments.hpp @brief Hysteria2 UDP QUIC datagram 分片与有界重组。 */
#pragma once

#include <Preview/Protocols/Hysteria2/Codec.hpp>

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

namespace Preview::Hysteria2::Detail
{
    inline constexpr std::size_t MaxDatagramFrameSize{1200};
    inline constexpr std::size_t MaxUdpPayloadSize{65507};
    inline constexpr std::size_t MaxPendingUdpPackets{64};
    inline constexpr std::size_t MaxPendingUdpBytes{1024U * 1024U};
    inline constexpr std::chrono::seconds UdpFragmentLifetime{3};

    /** @brief 引用单个 QUIC UDPMessage 的已解析字段；Address/Payload 借用输入帧。 */
    struct ReferenceUdpFragmentView final
    {
        std::uint32_t SessionId{0};
        std::uint16_t PacketId{0};
        std::uint8_t FragmentId{0};
        std::uint8_t FragmentCount{0};
        std::string_view Address;
        std::span<const std::uint8_t> Payload;
    };

    /** @brief 单个 QUIC UDPMessage 的构造输入；Address/Payload 借用至构帧返回。 */
    struct ReferenceUdpBuildInput final
    {
        std::uint32_t SessionId{0};
        std::uint16_t PacketId{0};
        std::uint8_t FragmentId{0};
        std::uint8_t FragmentCount{1};
        std::string_view Address;
        std::span<const std::uint8_t> Payload;
    };

    /** @brief 已完整重组的拥有型 Hysteria2 UDP 包。 */
    struct ReferenceUdpPacket final
    {
        std::uint32_t SessionId{0};
        std::uint16_t PacketId{0};
        std::string Address;
        std::vector<std::uint8_t> Payload;
    };

    [[nodiscard]] inline auto VarintSize(const std::uint64_t Value) noexcept -> std::size_t
    {
        if (Value <= 63U) return 1U;
        if (Value <= 16383U) return 2U;
        if (Value <= 1073741823U) return 4U;
        if (Value <= 4611686018427387903ULL) return 8U;
        return 0U;
    }

    template<class Output>
    inline auto AppendVarint(Output &Data, const std::uint64_t Value) -> void
    {
        if (Value <= 63U)
        {
            Data.push_back(static_cast<std::uint8_t>(Value));
            return;
        }
        if (Value <= 16383U)
        {
            Data.push_back(static_cast<std::uint8_t>((Value >> 8U) | 0x40U));
            Data.push_back(static_cast<std::uint8_t>(Value));
            return;
        }
        if (Value <= 1073741823U)
        {
            Data.push_back(static_cast<std::uint8_t>((Value >> 24U) | 0x80U));
            Data.push_back(static_cast<std::uint8_t>(Value >> 16U));
            Data.push_back(static_cast<std::uint8_t>(Value >> 8U));
            Data.push_back(static_cast<std::uint8_t>(Value));
            return;
        }
        for (std::size_t Index = 0; Index < 8U; ++Index)
        {
            const auto Shift = static_cast<unsigned>((7U - Index) * 8U);
            const auto Prefix = Index == 0U ? 0xC0U : 0U;
            Data.push_back(static_cast<std::uint8_t>((Value >> Shift) | Prefix));
        }
    }

    [[nodiscard]] inline auto ReadVarint(
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

    /** @brief 计算固定 QUIC datagram 上限内能容纳的最大 UDP 分片载荷。 */
    [[nodiscard]] inline auto MaxReferenceUdpFragmentPayload(const std::size_t AddressSize) noexcept
        -> std::optional<std::size_t>
    {
        if (AddressSize == 0U || AddressSize > 2048U) return {};
        const auto HeaderSize = 8U + VarintSize(AddressSize) + AddressSize;
        if (HeaderSize >= MaxDatagramFrameSize) return {};
        return MaxDatagramFrameSize - HeaderSize;
    }

    /** @brief 解析单帧；成功视图只在输入 Datagram 缓冲有效期间借用。 */
    [[nodiscard]] inline auto ParseReferenceUdpFragment(
        const std::span<const std::uint8_t> Data)
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

    /** @brief 将一个拥有型输出缓冲复用为单个、受 datagram 上限约束的 wire 帧。 */
    template<class Output>
    [[nodiscard]] inline auto BuildReferenceUdpFragment(
        const ReferenceUdpBuildInput &Input,
        Output &Wire) -> bool
    {
        Wire.clear();
        if (Input.Address.empty() || Input.Address.size() > 2048U ||
            (Input.Payload.empty() && Input.FragmentCount != 1U) ||
            Input.FragmentCount == 0U ||
            Input.FragmentId >= Input.FragmentCount)
        {
            return false;
        }
        const auto Maximum = MaxReferenceUdpFragmentPayload(Input.Address.size());
        if (!Maximum || Input.Payload.size() > *Maximum) return false;
        Wire.reserve(8U + VarintSize(Input.Address.size()) + Input.Address.size() +
            Input.Payload.size());
        Wire.push_back(static_cast<std::uint8_t>(Input.SessionId >> 24U));
        Wire.push_back(static_cast<std::uint8_t>(Input.SessionId >> 16U));
        Wire.push_back(static_cast<std::uint8_t>(Input.SessionId >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(Input.SessionId));
        Wire.push_back(static_cast<std::uint8_t>(Input.PacketId >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(Input.PacketId));
        Wire.push_back(Input.FragmentId);
        Wire.push_back(Input.FragmentCount);
        AppendVarint(Wire, Input.Address.size());
        Wire.insert(Wire.end(), Input.Address.begin(), Input.Address.end());
        Wire.insert(Wire.end(), Input.Payload.begin(), Input.Payload.end());
        return Wire.size() <= MaxDatagramFrameSize;
    }

    /** @brief 单 datagram session 的有界 Hysteria2 UDP 分片状态。 */
    class ReferenceUdpFragmentReassembler final
    {
        struct Key final
        {
            std::uint32_t SessionId{0};
            std::uint16_t PacketId{0};
            [[nodiscard]] auto operator==(const Key &) const noexcept -> bool = default;
        };

        struct KeyHash final
        {
            [[nodiscard]] auto operator()(const Key &Value) const noexcept -> std::size_t
            {
                return (static_cast<std::size_t>(Value.SessionId) << 16U) | Value.PacketId;
            }
        };

        struct PendingPacket final
        {
            std::string Address;
            std::vector<std::vector<std::uint8_t>> Fragments;
            std::vector<std::uint8_t> Received;
            std::size_t ReceivedCount{0};
            std::size_t PayloadSize{0};
            std::chrono::steady_clock::time_point LastSeen{};
        };

        using PendingMap = std::unordered_map<Key, PendingPacket, KeyHash>;

    public:
        /**
         * @brief 接受借用片段并按 Session/Packet/Fragment ID 重组。
         * @param Fragment 从当前 QUIC datagram 解析出的短期借用视图。
         * @return 空 optional 表示还缺片；有值时返回完整拥有型包，错误表示坏帧或超限。
         * @details 调用期间复制所有需要跨 await 存活的字段。实例由单一 datagram session
         *          在其 executor 上顺序调用，不跨线程共享。
         */
        [[nodiscard]] auto Accept(const ReferenceUdpFragmentView &Fragment)
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

    private:
        [[nodiscard]] static auto Valid(const ReferenceUdpFragmentView &Fragment) noexcept -> bool
        {
            return Fragment.FragmentCount != 0U && !Fragment.Address.empty() &&
                Fragment.Address.size() <= 2048U &&
                (Fragment.FragmentCount == 1U || !Fragment.Payload.empty()) &&
                Fragment.Payload.size() <= MaxUdpPayloadSize &&
                Fragment.FragmentId < Fragment.FragmentCount;
        }

        [[nodiscard]] static auto Complete(const ReferenceUdpFragmentView &Fragment)
            -> ReferenceUdpPacket
        {
            return {Fragment.SessionId, Fragment.PacketId, std::string(Fragment.Address),
                std::vector<std::uint8_t>(Fragment.Payload.begin(), Fragment.Payload.end())};
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
        }

        auto EvictOldest() -> void
        {
            auto Oldest = Pending_.end();
            for (auto Entry = Pending_.begin(); Entry != Pending_.end(); ++Entry)
                if (Oldest == Pending_.end() || Entry->second.LastSeen < Oldest->second.LastSeen)
                    Oldest = Entry;
            if (Oldest == Pending_.end()) return;
            PendingBytes_ -= Oldest->second.PayloadSize;
            Pending_.erase(Oldest);
        }

        [[nodiscard]] auto Create(
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

        [[nodiscard]] auto Add(
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

        [[nodiscard]] auto CanStore(
            const std::size_t CurrentSize,
            const std::size_t NewSize) const noexcept -> bool
        {
            return NewSize <= MaxUdpPayloadSize - (std::min)(CurrentSize, MaxUdpPayloadSize) &&
                NewSize <= MaxPendingUdpBytes - (std::min)(PendingBytes_, MaxPendingUdpBytes);
        }

        [[nodiscard]] static auto SamePayload(
            const std::vector<std::uint8_t> &Stored,
            const std::span<const std::uint8_t> Incoming) noexcept -> bool
        {
            return Stored.size() == Incoming.size() &&
                std::equal(Stored.begin(), Stored.end(), Incoming.begin());
        }

        [[nodiscard]] auto Assemble(PendingMap::iterator Entry) -> ReferenceUdpPacket
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

        auto Remove(PendingMap::iterator Entry) -> void
        {
            PendingBytes_ -= Entry->second.PayloadSize;
            Pending_.erase(Entry);
        }

        PendingMap Pending_;
        std::size_t PendingBytes_{0};
    };
}
