/**
 * @file Packets.hpp
 * @brief TUIC 数据报分片构造与有界重组。
 */
#pragma once

#include <Prism/Protocols/Tuic/Codec.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
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
            [[nodiscard]] auto operator()(const Key &Value) const noexcept -> std::size_t;
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
            -> std::expected<std::optional<Message>, Error>;

    private:
        [[nodiscard]] static auto Validate(const Message &Fragment) noexcept -> Error;

        /** @brief 按半序空间展开 ID，容纳回绕及窗口内乱序分片。 */
        [[nodiscard]] auto ExtendPacketId(
            const std::uint16_t AssocId,
            const std::uint16_t PacketId,
            const bool Track) -> std::uint64_t;

        auto PruneSequences() -> void;

        [[nodiscard]] auto Create(
            const Key &Identity,
            const Message &Fragment,
            const std::chrono::steady_clock::time_point Now) -> PendingMap::iterator;

        [[nodiscard]] auto Add(
            PendingMap::iterator Entry,
            const Message &Fragment,
            const std::chrono::steady_clock::time_point Now)
            -> std::expected<std::optional<Message>, Error>;

        [[nodiscard]] auto CanStore(
            const PendingPacket &Packet,
            const std::size_t PayloadSize) const noexcept -> bool;

        [[nodiscard]] static auto SameAddress(
            const Address &Left,
            const Address &Right) noexcept -> bool;

        auto Expire(const std::chrono::steady_clock::time_point Now) -> void;

        auto EvictOldest() -> void;

        [[nodiscard]] auto Assemble(PendingMap::iterator Entry) -> Message;

        auto Remove(PendingMap::iterator Entry) -> void;

        PendingMap Pending_;
        std::unordered_map<std::uint16_t, SequenceState> Sequences_;
        std::size_t PendingBytes_{0};
    };
} // namespace Prism::Tuic::Detail
