/** @file Classifier.cpp @brief QUIC framing 与 CID 分类实现。 */
#include <Prism/Boundary/Datagram/Classifier.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace Prism::Boundary
{
    auto DatagramClassifier::Classify(std::span<const std::byte> Payload) const
        -> DatagramClassification
    {
        if (Payload.empty())
        {
            return DatagramClassification{DatagramKind::Invalid, 0, DatagramRoute::Malformed,
                QuicHeaderError::Empty, 0, {}};
        }

        const auto First = std::to_integer<std::uint8_t>(Payload.front());
        if ((First & 0x80U) != 0U)
        {
            return ClassifyLongHeader(Payload);
        }
        return ClassifyShortHeader(Payload);
    }

    auto DatagramClassifier::RegisterQuicCid(std::span<const std::byte> ConnectionId) -> bool
    {
        if (ConnectionId.empty() || ConnectionId.size() > MaxConnectionIdLength)
        {
            return false;
        }
        CidKey Key;
        Key.Bytes.assign(ConnectionId.begin(), ConnectionId.end());
        return RegisteredCids_.insert(std::move(Key)).second;
    }

    auto DatagramClassifier::RemoveQuicCid(std::span<const std::byte> ConnectionId) -> void
    {
        if (!ConnectionId.empty())
        {
            CidKey Key;
            Key.Bytes.assign(ConnectionId.begin(), ConnectionId.end());
            RegisteredCids_.erase(Key);
        }
    }

    auto DatagramClassifier::QuicCidCount() const noexcept -> std::size_t
    {
        return RegisteredCids_.size();
    }

    auto DatagramClassifier::CidKey::operator==(const CidKey& Other) const noexcept -> bool
    {
        return Bytes == Other.Bytes;
    }

    auto DatagramClassifier::CidHash::operator()(const CidKey& Key) const noexcept -> std::size_t
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

    auto DatagramClassifier::MakeOrdinary(const QuicHeaderError Error) noexcept
        -> DatagramClassification
    {
        return DatagramClassification{DatagramKind::Ordinary, 0,
            Error == QuicHeaderError::None ? DatagramRoute::Ordinary : DatagramRoute::Malformed,
            Error, 0, {}};
    }

    auto DatagramClassifier::ClassifyLongHeader(std::span<const std::byte> Payload) const
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

    auto DatagramClassifier::ClassifyShortHeader(std::span<const std::byte> Payload) const
        -> DatagramClassification
    {
        const auto First = std::to_integer<std::uint8_t>(Payload.front());
        if ((First & 0x40U) == 0U)
        {
            return MakeOrdinary(QuicHeaderError::None);
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

        if (!MatchedCid.empty())
        {
            return MakeQuic(0, MatchedCid, true);
        }

        auto Result = MakeQuic(0, {}, false);
        Result.ConnectionId = HashPrefix(Payload);
        return Result;
    }

    auto DatagramClassifier::ParseLongHeader(std::span<const std::byte> Payload,
        LongHeader& Header) noexcept -> QuicHeaderError
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
        const auto Version = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Payload[1])) << 24U) |
                             (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Payload[2])) << 16U) |
                             (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Payload[3])) << 8U) |
                             static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Payload[4]));
        if (Version != 1U)
        {
            return QuicHeaderError::UnsupportedVersion;
        }

        // 长头的保留位与包号长度位受头保护；Native QUIC 解开保护前，
        // 入口分类器不能校验这些位的明文值。
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
        Header.PacketType = static_cast<std::uint8_t>((First >> 4U) & 0x03U);
        Header.DestinationCid = Payload.subspan(6U, DestinationLength);
        return QuicHeaderError::None;
    }

    auto DatagramClassifier::HashPrefix(std::span<const std::byte> Payload) noexcept
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

    auto DatagramClassifier::IsRegistered(std::span<const std::byte> ConnectionId) const
        -> bool
    {
        CidKey Key;
        Key.Bytes.assign(ConnectionId.begin(), ConnectionId.end());
        return RegisteredCids_.contains(Key);
    }

    auto DatagramClassifier::FindExactShortCid(std::span<const std::byte> Payload) const noexcept
        -> std::span<const std::byte>
    {
        std::span<const std::byte> Match;
        for (const auto& Registered : RegisteredCids_)
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

    auto DatagramClassifier::MakeQuic(const std::uint32_t Version,
        std::span<const std::byte> ConnectionId, const bool Registered) -> DatagramClassification
    {
        DatagramClassification Result;
        Result.Kind = DatagramKind::Quic;
        Result.Route = Registered ? DatagramRoute::RegisteredCid : DatagramRoute::UnknownCid;
        Result.Version = Version;
        Result.ConnectionIdBytes.assign(ConnectionId.begin(), ConnectionId.end());
        Result.ConnectionId = ConnectionId.empty() ? 0U : HashPrefix(ConnectionId);
        return Result;
    }
}
