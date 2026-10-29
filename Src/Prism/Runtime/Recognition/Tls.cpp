/** @file Tls.cpp @brief TLS ClientHello 记录解析实现。 */
#include <Prism/Runtime/Recognition/Tls.hpp>

#include <algorithm>
#include <array>
#include <span>
#include <utility>
#include <vector>

namespace Prism::Recognition::detail
{
    namespace
    {
        auto AppendHandshake(
            std::vector<std::uint8_t>& Handshake,
            const std::span<const std::uint8_t> Bytes) -> void
        {
            Handshake.reserve(Handshake.size() + Bytes.size());
            for (const auto Byte : Bytes)
            {
                Handshake.push_back(Byte);
            }
        }
    }

    auto ReadU16(const std::span<const std::uint8_t> Data,
                 const std::size_t Offset,
                 std::uint16_t& Value) noexcept -> bool
    {
        if (Offset > Data.size() || Data.size() - Offset < 2)
        {
            return false;
        }
        Value = static_cast<std::uint16_t>(Data[Offset]) << 8 |
            static_cast<std::uint16_t>(Data[Offset + 1]);
        return true;
    }

    auto ReadU24(const std::span<const std::uint8_t> Data,
                 const std::size_t Offset,
                 std::size_t& Value) noexcept -> bool
    {
        if (Offset > Data.size() || Data.size() - Offset < 3)
        {
            return false;
        }
        Value = static_cast<std::size_t>(Data[Offset]) << 16 |
            static_cast<std::size_t>(Data[Offset + 1]) << 8 |
            static_cast<std::size_t>(Data[Offset + 2]);
        return true;
    }

    auto ParseServerName(
        const std::span<const std::uint8_t> Data,
        std::string& ServerName) -> bool
    {
        std::uint16_t ListLength = 0;
        if (Data.size() < 2 || !ReadU16(Data, 0, ListLength) || ListLength != Data.size() - 2)
        {
            return false;
        }
        std::size_t Offset = 2;
        const auto End = Offset + ListLength;
        while (Offset < End)
        {
            if (End - Offset < 3)
            {
                return false;
            }
            const auto NameType = Data[Offset++];
            std::uint16_t NameLength = 0;
            if (!ReadU16(Data, Offset, NameLength))
            {
                return false;
            }
            Offset += 2;
            if (NameLength > End - Offset)
            {
                return false;
            }
            if (NameType == 0 && ServerName.empty())
            {
                ServerName.assign(reinterpret_cast<const char*>(Data.data() + Offset), NameLength);
            }
            Offset += NameLength;
        }
        return true;
    }

    auto ParseAlpn(
        const std::span<const std::uint8_t> Data,
        std::vector<std::string>& Protocols) -> bool
    {
        std::uint16_t ListLength = 0;
        if (Data.size() < 2 || !ReadU16(Data, 0, ListLength) || ListLength != Data.size() - 2)
        {
            return false;
        }
        std::size_t Offset = 2;
        const auto End = Offset + ListLength;
        while (Offset < End)
        {
            const auto Length = static_cast<std::size_t>(Data[Offset++]);
            if (Length == 0 || Length > End - Offset)
            {
                return false;
            }
            Protocols.emplace_back(reinterpret_cast<const char*>(Data.data() + Offset), Length);
            Offset += Length;
        }
        return Offset == End && !Protocols.empty();
    }

    auto ParseVersions(
        const std::span<const std::uint8_t> Data,
        std::vector<std::uint16_t>& Versions) -> bool
    {
        if (Data.empty())
        {
            return false;
        }
        const auto ListLength = static_cast<std::size_t>(Data.front());
        if (ListLength != Data.size() - 1 || (ListLength % 2) != 0)
        {
            return false;
        }
        for (std::size_t Offset = 1; Offset < Data.size(); Offset += 2)
        {
            std::uint16_t Version = 0;
            if (!ReadU16(Data, Offset, Version))
            {
                return false;
            }
            Versions.push_back(Version);
        }
        return true;
    }

    auto ParseKeyShare(
        const std::span<const std::uint8_t> Data,
        ClientHelloFeatures& Features) -> bool
    {
        constexpr std::uint16_t X25519Group = 0x001D;
        constexpr std::uint16_t X25519MLKEM768Group = 0x11EC;
        constexpr std::size_t X25519KeySize = 32;
        constexpr std::size_t MLKEM768EncapsulationKeySize = 1184;

        std::uint16_t ListLength = 0;
        if (Data.size() < 2 || !ReadU16(Data, 0, ListLength) || ListLength != Data.size() - 2)
        {
            return false;
        }

        std::array<std::uint8_t, X25519KeySize> HybridX25519Key{};
        bool HasHybridX25519Key = false;
        std::size_t Offset = 2;
        const auto End = Offset + ListLength;
        while (Offset < End)
        {
            if (End - Offset < 4)
            {
                return false;
            }
            std::uint16_t Group = 0;
            std::uint16_t KeyLength = 0;
            if (!ReadU16(Data, Offset, Group) || !ReadU16(Data, Offset + 2, KeyLength))
            {
                return false;
            }
            Offset += 4;
            if (KeyLength > End - Offset)
            {
                return false;
            }

            Features.KeyShareGroups.push_back(Group);
            if (Group == X25519MLKEM768Group)
            {
                Features.HasX25519MLKEM768 = true;
                if (!HasHybridX25519Key &&
                    KeyLength == MLKEM768EncapsulationKeySize + X25519KeySize)
                {
                    std::copy_n(Data.data() + Offset + MLKEM768EncapsulationKeySize,
                        X25519KeySize, HybridX25519Key.data());
                    HasHybridX25519Key = true;
                }
            }
            else if (Group == X25519Group && KeyLength == Features.X25519Key.size())
            {
                std::copy_n(Data.data() + Offset,
                    Features.X25519Key.size(), Features.X25519Key.data());
                Features.HasX25519 = true;
            }
            Offset += KeyLength;
        }

        if (!Features.HasX25519 && HasHybridX25519Key)
        {
            Features.X25519Key = HybridX25519Key;
            Features.HasX25519 = true;
        }
        return true;
    }

    auto ScanClientHello(const std::span<const std::uint8_t> Data) -> ClientHelloScan
    {
        ClientHelloScan Result;
        std::size_t Offset = 0;
        bool HeaderKnown = false;
        while (true)
        {
            if (Offset > Data.size() || Data.size() - Offset < TlsRecordHeaderSize)
            {
                Result.Required = Offset + TlsRecordHeaderSize;
                return Result;
            }
            if (Data[Offset] != 0x16 || Data[Offset + 1] != 0x03)
            {
                Result.Status = Error::BadMessage;
                return Result;
            }
            const auto PayloadLength = static_cast<std::size_t>(Data[Offset + 3]) << 8 |
                static_cast<std::size_t>(Data[Offset + 4]);
            if (PayloadLength > MaxTlsRecordPayload)
            {
                Result.Status = Error::BadLength;
                return Result;
            }
            const auto Total = TlsRecordHeaderSize + PayloadLength;
            if (Offset > MaxTlsClientHelloBytes || Total > MaxTlsClientHelloBytes - Offset)
            {
                Result.Status = Error::BadLength;
                return Result;
            }
            const auto RecordEnd = Offset + Total;
            const auto PayloadStart = Offset + TlsRecordHeaderSize;
            std::size_t Available = 0;
            if (Data.size() > PayloadStart)
            {
                Available = (std::min)(Data.size() - PayloadStart, PayloadLength);
            }
            const auto Before = Result.Handshake.size();
            std::size_t Copied = 0;
            if (Result.Handshake.size() < 4 && Available > 0)
            {
                const auto CopyCount = (std::min)(Available, 4 - Result.Handshake.size());
                AppendHandshake(Result.Handshake, Data.subspan(PayloadStart, CopyCount));
                Copied += CopyCount;
            }
            if (!Result.Handshake.empty() && Result.Handshake.front() != 0x01)
            {
                Result.Status = Error::BadMessage;
                return Result;
            }
            if (!HeaderKnown && Result.Handshake.size() >= 4)
            {
                const auto HandshakeLength =
                    (static_cast<std::size_t>(Result.Handshake[1]) << 16) |
                    (static_cast<std::size_t>(Result.Handshake[2]) << 8) |
                    static_cast<std::size_t>(Result.Handshake[3]);
                if (HandshakeLength > MaxTlsClientHelloBytes - 4)
                {
                    Result.Status = Error::BadLength;
                    return Result;
                }
                Result.MessageSize = 4 + HandshakeLength;
                HeaderKnown = true;
            }
            if (HeaderKnown && Result.Handshake.size() < Result.MessageSize && Available > Copied)
            {
                const auto CopyCount = (std::min)(Available - Copied,
                    Result.MessageSize - Result.Handshake.size());
                AppendHandshake(Result.Handshake,
                    Data.subspan(PayloadStart + Copied, CopyCount));
            }
            if (HeaderKnown && Result.Handshake.size() >= Result.MessageSize)
            {
                Result.Status = Error::None;
                Result.RecordEnd = PayloadStart + (Result.MessageSize - Before);
                return Result;
            }
            std::size_t Need = 4;
            if (HeaderKnown)
            {
                Need = Result.MessageSize;
            }
            std::size_t InRecordNeed = 0;
            if (Need > Before)
            {
                InRecordNeed = Need - Before;
            }
            if (InRecordNeed <= PayloadLength)
            {
                Result.Required = PayloadStart + InRecordNeed;
            }
            else
            {
                Result.Required = RecordEnd;
            }
            if (Data.size() < Result.Required)
            {
                return Result;
            }
            Offset = RecordEnd;
        }
    }

    auto MapProbeFill(const ProbeFillResult& Fill) noexcept -> Error
    {
        if (Fill.Status == RecognitionStatus::EndOfStream ||
            Prism::Fault::ToCode(Fill.Error) == Prism::Fault::Code::Eof)
        {
            return Error::UnexpectedEof;
        }
        if (Fill.Status == RecognitionStatus::BudgetExceeded)
        {
            return Error::BadLength;
        }
        if (Fill.Status == RecognitionStatus::IoError || Fill.Status == RecognitionStatus::Polluted)
        {
            return Error::IoError;
        }
        return Error::NeedMore;
    }

    auto ParseExtensions(
        const std::span<const std::uint8_t> Message,
        std::size_t& Offset,
        ClientHelloFeatures& Features) -> bool
    {
        std::uint16_t ExtensionsLength = 0;
        if (!ReadU16(Message, Offset, ExtensionsLength))
        {
            return false;
        }
        Offset += 2;
        if (ExtensionsLength != Message.size() - Offset)
        {
            return false;
        }
        const auto ExtensionsEnd = Offset + ExtensionsLength;
        std::vector<std::uint16_t> SeenTypes;
        SeenTypes.reserve(8);
        while (Offset < ExtensionsEnd)
        {
            std::uint16_t Type = 0;
            std::uint16_t Length = 0;
            if (ExtensionsEnd - Offset < 4 || !ReadU16(Message, Offset, Type) ||
                !ReadU16(Message, Offset + 2, Length))
            {
                return false;
            }
            Offset += 4;
            if (Length > ExtensionsEnd - Offset)
            {
                return false;
            }
            if (std::find(SeenTypes.begin(), SeenTypes.end(), Type) != SeenTypes.end())
            {
                return false;
            }
            SeenTypes.push_back(Type);
            const auto Payload = Message.subspan(Offset, Length);
            switch (Type)
            {
            case 0x0000:
                if (!ParseServerName(Payload, Features.ServerName)) return false;
                break;
            case 0x0010:
                if (!ParseAlpn(Payload, Features.AlpnProtocols)) return false;
                Features.HasAlpn = true;
                break;
            case 0x002B:
                if (!ParseVersions(Payload, Features.Versions)) return false;
                break;
            case 0x0033:
                if (!ParseKeyShare(Payload, Features)) return false;
                break;
            case 0x0029: Features.HasPsk = true; break;
            case 0xFE0D: Features.HasEch = true; break;
            default: break;
            }
            Offset += Length;
        }
        return Offset == ExtensionsEnd;
    }

    auto ParseClientHelloMessage(
        const std::span<const std::uint8_t> Message,
        ClientHelloFeatures& Features) -> Error
    {
        if (Message.size() < 4 || Message[0] != 0x01)
        {
            return Error::BadMessage;
        }
        std::size_t HandshakeLength = 0;
        if (!ReadU24(Message, 1, HandshakeLength) || HandshakeLength != Message.size() - 4 ||
            HandshakeLength < 34)
        {
            return Error::BadMessage;
        }
        Features.RawMessage.assign(Message.begin(), Message.end());

        std::size_t Offset = 4;
        if (!ReadU16(Message, Offset, Features.LegacyVersion))
        {
            return Error::BadMessage;
        }
        Offset += 2;
        if (Message.size() - Offset < Features.Random.size())
        {
            return Error::BadMessage;
        }
        std::copy_n(Message.data() + Offset, Features.Random.size(), Features.Random.data());
        Offset += Features.Random.size();
        if (Offset >= Message.size())
        {
            return Error::BadMessage;
        }
        const auto SessionLength = static_cast<std::size_t>(Message[Offset++]);
        if (SessionLength > MaxTlsSessionIdBytes || SessionLength > Message.size() - Offset)
        {
            return Error::BadMessage;
        }
        Features.SessionId.assign(Message.begin() + Offset, Message.begin() + Offset + SessionLength);
        Offset += SessionLength;

        std::uint16_t CipherLength = 0;
        if (!ReadU16(Message, Offset, CipherLength))
        {
            return Error::BadMessage;
        }
        Offset += 2;
        if ((CipherLength % 2) != 0 || CipherLength > Message.size() - Offset)
        {
            return Error::BadMessage;
        }
        Offset += CipherLength;
        if (Offset >= Message.size())
        {
            return Error::BadMessage;
        }
        const auto CompressionLength = static_cast<std::size_t>(Message[Offset++]);
        if (CompressionLength > Message.size() - Offset)
        {
            return Error::BadMessage;
        }
        Offset += CompressionLength;
        if (Offset == Message.size() || !ParseExtensions(Message, Offset, Features))
        {
            if (Offset == Message.size())
            {
                return Error::None;
            }
            return Error::BadMessage;
        }
        return Error::None;
    }
}

namespace Prism::Recognition
{
    auto ParseClientHelloProgress(const std::span<const std::uint8_t> RecordSequence)
        -> std::pair<Error, ClientHelloFeatures>
    {
        const auto Scan = detail::ScanClientHello(RecordSequence);
        ClientHelloFeatures Features;
        if (Scan.Status != Error::None)
        {
            return {Scan.Status, std::move(Features)};
        }
        Features.RawRecord.assign(RecordSequence.begin(), RecordSequence.begin() + Scan.RecordEnd);
        Features.ConsumedBytes = Scan.RecordEnd;
        const auto Message = std::span<const std::uint8_t>(Scan.Handshake.data(), Scan.MessageSize);
        const auto ErrorCode = detail::ParseClientHelloMessage(Message, Features);
        if (ErrorCode != Error::None)
        {
            return {ErrorCode, std::move(Features)};
        }
        return {Error::None, std::move(Features)};
    }

    auto ParseClientHello(const std::span<const std::uint8_t> RecordSequence)
        -> std::pair<Error, ClientHelloFeatures>
    {
        auto Result = ParseClientHelloProgress(RecordSequence);
        if (Result.first == Error::NeedMore)
        {
            Result.first = Error::BadMessage;
        }
        return Result;
    }

    auto ReadClientHello(Prism::Transmission& Transport, ProbeBuffer& Buffer)
        -> Net::awaitable<std::pair<Error, ClientHelloFeatures>>
    {
        while (true)
        {
            const auto Data = Buffer.Data();
            const auto Bytes = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(Data.data()), Data.size());
            const auto Scan = detail::ScanClientHello(Bytes);
            if (Scan.Status != Error::NeedMore)
            {
                co_return ParseClientHello(Bytes);
            }
            if (Scan.Required <= Buffer.Size() || Scan.Required > MaxTlsClientHelloBytes)
            {
                co_return std::pair{Error::BadLength, ClientHelloFeatures{}};
            }
            const auto Fill = co_await Buffer.Ensure(Transport, Scan.Required);
            if (Fill.Status != RecognitionStatus::Accepted)
            {
                const auto UpdatedData = Buffer.Data();
                const auto UpdatedBytes = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t*>(UpdatedData.data()), UpdatedData.size());
                const auto UpdatedScan = detail::ScanClientHello(UpdatedBytes);
                if (UpdatedScan.Status != Error::NeedMore)
                {
                    co_return ParseClientHello(UpdatedBytes);
                }
                co_return std::pair{detail::MapProbeFill(Fill), ClientHelloFeatures{}};
            }
        }
    }

    auto ReadClientHello(ProbeBuffer& Buffer, Prism::Transmission& Transport)
        -> Net::awaitable<std::pair<Error, ClientHelloFeatures>>
    {
        co_return co_await ReadClientHello(Transport, Buffer);
    }
}
