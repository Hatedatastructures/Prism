/** @file Fragments.hpp @brief Hysteria2 UDP QUIC datagram 分片与有界重组。 */
#pragma once

#include <Prism/Protocols/Hysteria2/Codec.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace Prism::Hysteria2::Detail
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

    [[nodiscard]] auto VarintSize(const std::uint64_t Value) noexcept -> std::size_t;

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

    [[nodiscard]] auto ReadVarint(
        const std::span<const std::uint8_t> Data,
        std::size_t &Offset,
        std::uint64_t &Value) noexcept -> bool;

    /** @brief 计算固定 QUIC datagram 上限内能容纳的最大 UDP 分片载荷。 */
    [[nodiscard]] auto MaxReferenceUdpFragmentPayload(
        const std::size_t AddressSize) noexcept -> std::optional<std::size_t>;

    /** @brief 解析单帧；成功视图只在输入 Datagram 缓冲有效期间借用。 */
    [[nodiscard]] auto ParseReferenceUdpFragment(
        std::span<const std::uint8_t> Data)
        -> std::expected<ReferenceUdpFragmentView, Error>;

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
            [[nodiscard]] auto operator()(const Key &Value) const noexcept -> std::size_t;
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
            -> std::expected<std::optional<ReferenceUdpPacket>, Error>;

    private:
        [[nodiscard]] static auto Valid(const ReferenceUdpFragmentView &Fragment) noexcept -> bool;

        [[nodiscard]] static auto Complete(const ReferenceUdpFragmentView &Fragment)
            -> ReferenceUdpPacket;

        auto Expire(const std::chrono::steady_clock::time_point Now) -> void;

        auto EvictOldest() -> void;

        [[nodiscard]] auto Create(
            const Key &Identity,
            const ReferenceUdpFragmentView &Fragment,
            const std::chrono::steady_clock::time_point Now) -> PendingMap::iterator;

        [[nodiscard]] auto Add(
            PendingMap::iterator Entry,
            const ReferenceUdpFragmentView &Fragment,
            const std::chrono::steady_clock::time_point Now)
            -> std::expected<std::optional<ReferenceUdpPacket>, Error>;

        [[nodiscard]] auto CanStore(
            const std::size_t CurrentSize,
            const std::size_t NewSize) const noexcept -> bool;

        [[nodiscard]] static auto SamePayload(
            const std::vector<std::uint8_t> &Stored,
            const std::span<const std::uint8_t> Incoming) noexcept -> bool;

        [[nodiscard]] auto Assemble(PendingMap::iterator Entry) -> ReferenceUdpPacket;

        auto Remove(PendingMap::iterator Entry) -> void;

        PendingMap Pending_;
        std::size_t PendingBytes_{0};
    };
}
