/**
 * @file RequestState.cpp
 * @brief Shadowsocks 2022 请求握手状态机实现。
 */

#include <Prism/Foundation/Utility/Crypto/Random.hpp>
#include <Prism/Protocols/Shadowsocks2022/ChunkCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestState.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestWire.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <random>
#include <span>
#include <utility>

namespace Prism::Shadowsocks2022
{
    Serializer::Serializer(const std::array<std::uint8_t, 16>& Psk, RandomSource Source)
        : Psk_(Psk), Source_(std::move(Source))
    {
    }

    auto Serializer::Reset(const Message& MessageValue, std::uint64_t TimeSec) -> void
    {
        Wire_.clear();
        Offset_ = 0;
        Ready_ = false;
        Failed_ = false;
        std::array<std::uint8_t, 16> Salt{};
        bool Filled;
        if (Source_)
        {
            Filled = Prism::Crypto::FillRandom(std::span<std::uint8_t>(Salt), Source_).has_value();
        }
        else
        {
            Filled = Prism::Crypto::FillRandom(std::span<std::uint8_t>(Salt)).has_value();
        }
        if (!Filled)
        {
            Failed_ = true;
            return;
        }
        const auto SessionKeyValue = SessionKey(Psk_, Salt, 16);

        std::random_device RandomDevice;
        const auto PaddingLength = static_cast<std::uint16_t>(1 + RandomDevice() % 16);
        std::vector<std::uint8_t> VariableHeader;
        const auto AddressBytes = EncodeAddress(MessageValue.dst);
        if (AddressBytes.empty())
        {
            Failed_ = true;
            return;
        }
        VariableHeader.insert(VariableHeader.end(), AddressBytes.begin(), AddressBytes.end());
        VariableHeader.push_back(static_cast<std::uint8_t>((PaddingLength >> 8) & 0xFF));
        VariableHeader.push_back(static_cast<std::uint8_t>(PaddingLength & 0xFF));
        for (std::uint16_t I = 0; I < PaddingLength; ++I)
        {
            VariableHeader.push_back(static_cast<std::uint8_t>(RandomDevice() & 0xFF));
        }
        VariableHeader.insert(VariableHeader.end(), MessageValue.InitialPayload.begin(),
            MessageValue.InitialPayload.end());
        if (VariableHeader.size() > (std::numeric_limits<std::uint16_t>::max)())
        {
            Failed_ = true;
            return;
        }

        const auto Fixed =
            ParseFixedHeader(HeaderTypeClient, TimeSec, static_cast<std::uint16_t>(VariableHeader.size()));
        ChunkCodec Codec(SessionKeyValue);
        const auto FixedEncrypted = Codec.SealRaw(Fixed);
        const auto VariableEncrypted = Codec.SealRaw(VariableHeader);
        if (FixedEncrypted.empty() || VariableEncrypted.empty())
        {
            Failed_ = true;
            return;
        }

        Wire_.clear();
        Wire_.reserve(Salt.size() + FixedEncrypted.size() + VariableEncrypted.size());
        Wire_.insert(Wire_.end(), Salt.begin(), Salt.end());
        Wire_.insert(Wire_.end(), FixedEncrypted.begin(), FixedEncrypted.end());
        Wire_.insert(Wire_.end(), VariableEncrypted.begin(), VariableEncrypted.end());
        Ready_ = !Wire_.empty();
    }

    auto Serializer::Get(boost::asio::mutable_buffer Buffer, std::error_code& ErrorCode) -> std::size_t
    {
        ErrorCode.clear();
        if (!Ready_)
        {
            ErrorCode = make_error_code(Error::IoError);
            return 0;
        }
        const auto N = std::min(Buffer.size(), Wire_.size() - Offset_);
        std::memcpy(Buffer.data(), Wire_.data() + Offset_, N);
        Offset_ += N;
        return N;
    }

    Parser::Parser(const std::array<std::uint8_t, 16>& Psk) : Psk_(Psk)
    {
    }

    auto Parser::Put(boost::asio::const_buffer Buffer, std::error_code& ErrorCode) -> std::size_t
    {
        ErrorCode.clear();
        if (Done_)
        {
            return 0;
        }
        const auto Data =
            std::span<const std::uint8_t>(static_cast<const std::uint8_t*>(Buffer.data()), Buffer.size());
        Buf_.insert(Buf_.end(), Data.begin(), Data.end());
        if (Buf_.size() < 16 + FixedHdrPlain + AeadTagLen)
        {
            ErrorCode = make_error_code(Error::NeedMore);
            return 0;
        }

        const auto Salt = std::span<const std::uint8_t>(Buf_).first(16);
        const auto SessionKeyValue = SessionKey(Psk_, Salt, 16);
        ChunkCodec Codec(SessionKeyValue);
        auto FixedPlain =
            Codec.OpenRaw(std::span<const std::uint8_t>(Buf_).subspan(16, FixedHdrPlain + AeadTagLen));
        if (FixedPlain.size() != FixedHdrPlain || FixedPlain[0] != HeaderTypeClient)
        {
            ErrorCode = make_error_code(Error::BadAuth);
            return 0;
        }
        FixedHeader FixedHeaderValue;
        if (ParseFixedHeader(FixedPlain, FixedHeaderValue) != Error::None)
        {
            ErrorCode = make_error_code(Error::BadMessage);
            return 0;
        }
        TimeSec_ = FixedHeaderValue.TimeSec;
        const auto VariableLength = static_cast<std::size_t>(FixedHeaderValue.VarLen);
        if (Buf_.size() < 16 + FixedHdrPlain + AeadTagLen + VariableLength + AeadTagLen)
        {
            ErrorCode = make_error_code(Error::NeedMore);
            return 0;
        }
        auto VariablePlain = Codec.OpenRaw(std::span<const std::uint8_t>(Buf_).subspan(
            16 + FixedHdrPlain + AeadTagLen, VariableLength + AeadTagLen));
        if (VariablePlain.empty())
        {
            ErrorCode = make_error_code(Error::BadAuth);
            return 0;
        }

        std::size_t Offset = 0;
        const auto AddressError =
            ParseAddress(std::span<const std::uint8_t>(VariablePlain).subspan(Offset), Msg_.dst, Offset);
        if (AddressError != Error::None)
        {
            ErrorCode = make_error_code(AddressError);
            return 0;
        }
        if (VariablePlain.size() - Offset < 2)
        {
            ErrorCode = make_error_code(Error::BadMessage);
            return 0;
        }
        const auto PaddingLength =
            static_cast<std::size_t>(VariablePlain[Offset]) << 8 | VariablePlain[Offset + 1];
        Offset += 2;
        if (VariablePlain.size() - Offset < PaddingLength)
        {
            ErrorCode = make_error_code(Error::BadMessage);
            return 0;
        }
        Offset += PaddingLength;
        Msg_.InitialPayload.assign(reinterpret_cast<const char*>(VariablePlain.data() + Offset),
            VariablePlain.size() - Offset);
        Done_ = true;
        return Buf_.size();
    }

    [[nodiscard]] auto Parser::IsTimestampFresh(std::uint64_t TimeWindow) const noexcept -> bool
    {
        const auto Now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
                .count());
        std::uint64_t Difference;
        if (Now >= TimeSec_)
        {
            Difference = Now - TimeSec_;
        }
        else
        {
            Difference = TimeSec_ - Now;
        }
        return Difference <= TimeWindow;
    }

    auto Parser::Reset() -> void
    {
        Buf_.clear();
        Msg_ = Message{};
        TimeSec_ = 0;
        Done_ = false;
    }

} // namespace Prism::Shadowsocks2022
