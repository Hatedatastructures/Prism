/**
 * @file UdpDemux.hpp
 * @brief Preview UDP 数据报分类与 QUIC connection id 提取。
 * @details 该模块只做入口层 framing 判断，不解析任何应用协议。长头
 *          QUIC 包先进入 QuicGateway；已登记的短头 CID 也保持同一归属，
 *          其余数据报交给普通 UDP association 路径。
 */
#pragma once

#include <boost/asio/ip/udp.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Preview::Ingress
{

    enum class DatagramKind : std::uint8_t
    {
        Ordinary,
        Quic,
        Invalid,
    };

    /**
     * @brief 入口层路由结果。
     * @details Kind::Quic 保持旧 API 兼容；Route 才区分已经登记的 CID
     *          与格式正确但尚未登记的 CID。malformed QUIC-like 数据报
     *          仍回到普通 UDP，并保留 Error 供诊断和计数使用。
     */
    enum class DatagramRoute : std::uint8_t
    {
        Legacy,
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
        DatagramRoute Route{DatagramRoute::Legacy};
        QuicHeaderError Error{QuicHeaderError::None};
        std::uint32_t Version{0};
        std::vector<std::byte> ConnectionIdBytes;
    };

    class UdpDemux final
    {
    public:
        [[nodiscard]] auto Classify(std::span<const std::byte> Payload) const
            -> DatagramClassification
        {
            if (Payload.empty())
            {
                return DatagramClassification{DatagramKind::Invalid,
                                              0,
                                              DatagramRoute::Malformed,
                                              QuicHeaderError::Empty,
                                              0,
                                              {}};
            }

            const auto First = std::to_integer<std::uint8_t>(Payload.front());
            if ((First & 0x80U) != 0U)
            {
                return ClassifyLongHeader(Payload);
            }
            return ClassifyShortHeader(Payload);
        }

        auto RegisterQuicCid(const std::uint64_t ConnectionId) -> bool
        {
            return ConnectionId != 0U && LegacyCids_.insert(ConnectionId).second;
        }

        auto RegisterQuicCid(std::span<const std::byte> ConnectionId) -> bool
        {
            if (ConnectionId.empty() || ConnectionId.size() > MaxConnectionIdLength)
            {
                return false;
            }
            CidKey Key;
            Key.Bytes.assign(ConnectionId.begin(), ConnectionId.end());
            return RegisteredCids_.insert(std::move(Key)).second;
        }

        auto RemoveQuicCid(const std::uint64_t ConnectionId) noexcept -> void
        {
            if (ConnectionId != 0U)
            {
                LegacyCids_.erase(ConnectionId);
            }
        }

        auto RemoveQuicCid(std::span<const std::byte> ConnectionId) -> void
        {
            if (!ConnectionId.empty())
            {
                CidKey Key;
                Key.Bytes.assign(ConnectionId.begin(), ConnectionId.end());
                RegisteredCids_.erase(Key);
            }
        }

        [[nodiscard]] auto QuicCidCount() const noexcept -> std::size_t
        {
            return RegisteredCids_.size() + LegacyCids_.size();
        }

    private:
        static constexpr std::size_t MaxConnectionIdLength = 20U;

        struct CidKey final
        {
            std::vector<std::byte> Bytes;

            [[nodiscard]] auto operator==(const CidKey &Other) const noexcept -> bool
            {
                return Bytes == Other.Bytes;
            }
        };

        struct CidHash final
        {
            [[nodiscard]] auto operator()(const CidKey &Key) const noexcept -> std::size_t
            {
                constexpr std::uint64_t Offset = 14695981039346656037ULL;
                constexpr std::uint64_t Prime = 1099511628211ULL;
                std::uint64_t Hash = Offset;
                for (const auto Byte : Key.Bytes)
                {
                    Hash ^= std::to_integer<std::uint8_t>(Byte);
                    Hash *= Prime;
                }
                Hash ^= static_cast<std::uint64_t>(Key.Bytes.size());
                return static_cast<std::size_t>(Hash);
            }
        };

        struct LongHeader final
        {
            std::uint32_t Version{0};
            std::uint8_t PacketType{0};
            std::span<const std::byte> DestinationCid;
        };

        [[nodiscard]] static auto MakeOrdinary(const QuicHeaderError Error) noexcept
            -> DatagramClassification
        {
            return DatagramClassification{DatagramKind::Ordinary,
                                          0,
                                          Error == QuicHeaderError::None ? DatagramRoute::Ordinary
                                                                          : DatagramRoute::Malformed,
                                          Error,
                                          0,
                                          {}};
        }

        [[nodiscard]] auto ClassifyLongHeader(std::span<const std::byte> Payload) const
            -> DatagramClassification
        {
            LongHeader Header;
            const auto Error = ParseLongHeader(Payload, Header);
            if (Error != QuicHeaderError::None)
            {
                return MakeOrdinary(Error);
            }

            return MakeQuic(Header.Version, Header.DestinationCid, IsRegistered(Header.DestinationCid));
        }

        [[nodiscard]] auto ClassifyShortHeader(std::span<const std::byte> Payload) const
            -> DatagramClassification
        {
            const auto First = std::to_integer<std::uint8_t>(Payload.front());
            if ((First & 0x40U) == 0U)
            {
                return MakeOrdinary(QuicHeaderError::None);
            }
            if ((First & 0x18U) != 0U)
            {
                return MakeOrdinary(QuicHeaderError::ReservedBits);
            }
            if (Payload.size() < 2U)
            {
                return MakeOrdinary(QuicHeaderError::Truncated);
            }

            std::span<const std::byte> MatchedCid;
            if (const auto Exact = FindExactShortCid(Payload); !Exact.empty())
            {
                MatchedCid = Exact;
            }
            else if (const auto Legacy = FindLegacyShortCid(Payload); !Legacy.empty())
            {
                MatchedCid = Legacy;
            }

            if (!MatchedCid.empty())
            {
                return MakeQuic(0, MatchedCid, true);
            }

            auto Result = MakeQuic(0, {}, false);
            Result.ConnectionId = HashPrefix(Payload);
            return Result;
        }

        [[nodiscard]] static auto ParseLongHeader(
            std::span<const std::byte> Payload,
            LongHeader &Header) noexcept -> QuicHeaderError
        {
            if (Payload.size() < 6U)
            {
                return QuicHeaderError::TooShort;
            }

            const auto First = std::to_integer<std::uint8_t>(Payload[0]);
            if ((First & 0x40U) == 0U)
            {
                return QuicHeaderError::FixedBit;
            }
            if ((First & 0x0cU) != 0U)
            {
                return QuicHeaderError::ReservedBits;
            }

            const auto Version = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Payload[1])) << 24U) |
                                 (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Payload[2])) << 16U) |
                                 (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Payload[3])) << 8U) |
                                 static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Payload[4]));
            if (Version != 1U)
            {
                return QuicHeaderError::UnsupportedVersion;
            }

            const auto PacketType = static_cast<std::uint8_t>((First >> 4U) & 0x03U);
            if (PacketType == 3U && (First & 0x03U) != 0U)
            {
                return QuicHeaderError::PacketType;
            }

            const auto DestinationLength = std::to_integer<std::uint8_t>(Payload[5]);
            if (DestinationLength == 0U || DestinationLength > MaxConnectionIdLength)
            {
                return QuicHeaderError::ConnectionIdLength;
            }
            const auto DestinationEnd = 6U + static_cast<std::size_t>(DestinationLength);
            if (Payload.size() <= DestinationEnd)
            {
                return QuicHeaderError::Truncated;
            }
            const auto SourceLength = std::to_integer<std::uint8_t>(Payload[DestinationEnd]);
            if (SourceLength > MaxConnectionIdLength)
            {
                return QuicHeaderError::ConnectionIdLength;
            }
            const auto HeaderEnd = DestinationEnd + 1U + static_cast<std::size_t>(SourceLength);
            if (Payload.size() < HeaderEnd)
            {
                return QuicHeaderError::Truncated;
            }

            Header.Version = Version;
            Header.PacketType = PacketType;
            Header.DestinationCid = Payload.subspan(6U, DestinationLength);
            return QuicHeaderError::None;
        }

        [[nodiscard]] static auto HashPrefix(std::span<const std::byte> Payload) noexcept
            -> std::uint64_t
        {
            constexpr std::uint64_t Offset = 14695981039346656037ULL;
            constexpr std::uint64_t Prime = 1099511628211ULL;
            std::uint64_t Hash = Offset;
            const auto Count = Payload.size() < 8U ? Payload.size() : 8U;
            for (std::size_t Index = 0; Index < Count; ++Index)
            {
                Hash ^= std::to_integer<std::uint8_t>(Payload[Index]);
                Hash *= Prime;
            }
            return Hash == 0U ? 1U : Hash;
        }

        [[nodiscard]] auto IsRegistered(std::span<const std::byte> ConnectionId) const
            -> bool
        {
            CidKey Key;
            Key.Bytes.assign(ConnectionId.begin(), ConnectionId.end());
            if (RegisteredCids_.contains(Key))
            {
                return true;
            }
            return LegacyCids_.contains(HashPrefix(ConnectionId));
        }

        [[nodiscard]] auto FindExactShortCid(std::span<const std::byte> Payload) const noexcept
            -> std::span<const std::byte>
        {
            std::span<const std::byte> Match;
            for (const auto &Registered : RegisteredCids_)
            {
                const auto Length = Registered.Bytes.size();
                if (Length <= Match.size() || Payload.size() < 1U + Length)
                {
                    continue;
                }
                const auto Candidate = Payload.subspan(1U, Length);
                if (std::equal(Registered.Bytes.begin(), Registered.Bytes.end(), Candidate.begin()))
                {
                    Match = Candidate;
                }
            }
            return Match;
        }

        [[nodiscard]] auto FindLegacyShortCid(std::span<const std::byte> Payload) const noexcept
            -> std::span<const std::byte>
        {
            const auto Maximum = std::min(MaxConnectionIdLength, Payload.size() - 1U);
            for (std::size_t Length = Maximum; Length != 0U; --Length)
            {
                const auto Candidate = Payload.subspan(1U, Length);
                if (LegacyCids_.contains(HashPrefix(Candidate)))
                {
                    return Candidate;
                }
            }
            return {};
        }

        [[nodiscard]] static auto MakeQuic(
            const std::uint32_t Version,
            std::span<const std::byte> ConnectionId,
            const bool Registered) -> DatagramClassification
        {
            DatagramClassification Result;
            Result.Kind = DatagramKind::Quic;
            Result.Route = Registered ? DatagramRoute::RegisteredCid : DatagramRoute::UnknownCid;
            Result.Version = Version;
            Result.ConnectionIdBytes.assign(ConnectionId.begin(), ConnectionId.end());
            Result.ConnectionId = ConnectionId.empty() ? 0U : HashPrefix(ConnectionId);
            return Result;
        }

        std::unordered_set<CidKey, CidHash> RegisteredCids_;
        std::unordered_set<std::uint64_t> LegacyCids_;
    };

    struct UdpPacket final
    {
        std::vector<std::byte> Payload;
        boost::asio::ip::udp::endpoint Peer;
        DatagramClassification Classification{};
        std::uint64_t Sequence{0};
    };

} // namespace Preview::Ingress
