/**
 * @file Classifier.hpp
 * @brief Prism UDP 数据报分类与 QUIC connection id 提取。
 * @details 该模块只做入口层 framing 判断，不解析任何应用协议。长头
 *          QUIC 包先进入 QuicPacketGateway；已登记的短头 CID 也保持同一归属，
 *          其余数据报交给普通 UDP association 路径。
 */
#pragma once

#include <boost/asio/ip/udp.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_set>
#include <vector>

namespace Prism::Boundary
{

    enum class DatagramKind : std::uint8_t
    {
        Ordinary,
        Quic,
        Invalid,
    };

    /**
     * @brief 入口层路由结果。
     * @details Kind::Quic 表示通过 QUIC framing 分类；Route 区分已经登记的 CID
     *          与格式正确但尚未登记的 CID。malformed QUIC-like 数据报仍回到
     *          普通 UDP，并保留 Error 供诊断和计数使用。
     */
    enum class DatagramRoute : std::uint8_t
    {
        Ordinary,
        RegisteredCid,
        UnknownCid,
        Malformed,
    };

    enum class QuicHeaderError : std::uint8_t
    {
        None,
        Empty,
        TooShort,
        FixedBit,
        UnsupportedVersion,
        PacketType,
        ReservedBits,
        ConnectionIdLength,
        Truncated,
    };

    struct DatagramClassification final
    {
        DatagramKind Kind{DatagramKind::Invalid};
        std::uint64_t ConnectionId{0};
        DatagramRoute Route{DatagramRoute::Ordinary};
        QuicHeaderError Error{QuicHeaderError::None};
        std::uint32_t Version{0};
        std::vector<std::byte> ConnectionIdBytes;
    };

    class DatagramClassifier final
    {
    public:
        [[nodiscard]] auto Classify(std::span<const std::byte> Payload) const
            -> DatagramClassification;

        auto RegisterQuicCid(std::span<const std::byte> ConnectionId) -> bool;

        auto RemoveQuicCid(std::span<const std::byte> ConnectionId) -> void;

        [[nodiscard]] auto QuicCidCount() const noexcept -> std::size_t;

    private:
        static constexpr std::size_t MaxConnectionIdLength = 20U;

        struct CidKey final
        {
            std::vector<std::byte> Bytes;

            [[nodiscard]] auto operator==(const CidKey& Other) const noexcept -> bool;
        };

        struct CidHash final
        {
            [[nodiscard]] auto operator()(const CidKey& Key) const noexcept -> std::size_t;
        };

        struct LongHeader final
        {
            std::uint32_t Version{0};
            std::uint8_t PacketType{0};
            std::span<const std::byte> DestinationCid;
        };

        [[nodiscard]] static auto MakeOrdinary(const QuicHeaderError Error) noexcept
            -> DatagramClassification;

        [[nodiscard]] auto ClassifyLongHeader(std::span<const std::byte> Payload) const
            -> DatagramClassification;

        [[nodiscard]] auto ClassifyShortHeader(std::span<const std::byte> Payload) const
            -> DatagramClassification;

        [[nodiscard]] static auto ParseLongHeader(
            std::span<const std::byte> Payload,
            LongHeader& Header) noexcept -> QuicHeaderError;

        [[nodiscard]] static auto HashPrefix(std::span<const std::byte> Payload) noexcept
            -> std::uint64_t;

        [[nodiscard]] auto IsRegistered(std::span<const std::byte> ConnectionId) const
            -> bool;

        [[nodiscard]] auto FindExactShortCid(std::span<const std::byte> Payload) const noexcept
            -> std::span<const std::byte>;

        [[nodiscard]] static auto MakeQuic(
            const std::uint32_t Version,
            std::span<const std::byte> ConnectionId,
            const bool Registered) -> DatagramClassification;

        std::unordered_set<CidKey, CidHash> RegisteredCids_;
    };

    struct BoundaryPacket final
    {
        std::vector<std::byte> Payload;
        boost::asio::ip::udp::endpoint Peer;
        DatagramClassification Classification{};
        std::uint64_t Sequence{0};
    };

} // namespace Prism::Boundary
