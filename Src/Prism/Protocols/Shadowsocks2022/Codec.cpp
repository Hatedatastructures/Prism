/**
 * @file Codec.cpp
 * @brief Shadowsocks 2022 分块与 UDP 编解码实现。
 */

#include <Prism/Protocols/Shadowsocks2022/ChunkCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestWire.hpp>
#include <Prism/Protocols/Shadowsocks2022/ResponseCodec.hpp>

#include <openssl/evp.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <utility>

namespace Prism::Shadowsocks2022
{
    namespace detail
    {
        [[nodiscard]] auto ValidAeadInput(const AeadInput& Input) noexcept -> bool
        {
            constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
            return Input.Key.size() == AesKeyLen && Input.Nonce.size() == AesNonceLen &&
                Input.Data.size() <= MaxInt;
        }

        auto IncNonce(std::span<std::uint8_t> Nonce) -> void
        {
            for (std::size_t Index = 0; Index < Nonce.size(); ++Index)
            {
                ++Nonce[Index];
                if (Nonce[Index] != 0)
                {
                    break;
                }
            }
        }

        [[nodiscard]] auto AeadSeal(const AeadInput Input) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> Out;
            (void)AeadSeal(Input, Out);
            return Out;
        }

        [[nodiscard]] auto AeadOpen(const AeadInput Input) -> std::vector<std::uint8_t>
        {
            if (Input.Data.size() < AeadTagLen ||
                !ValidAeadInput(AeadInput{Input.Key, Input.Nonce,
                    std::span<const std::uint8_t>(Input.Data).subspan(0, Input.Data.size() - AeadTagLen)}))
            {
                return {};
            }
            const auto CipherLen = Input.Data.size() - AeadTagLen;
            std::vector<std::uint8_t> Out(CipherLen);
            EVP_CIPHER_CTX* Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return {};
            }
            int Len = 0;
            bool Ok = EVP_DecryptInit_ex(Ctx, EVP_aes_128_gcm(), nullptr, Input.Key.data(),
                          Input.Nonce.data()) == 1;
            if (Ok && CipherLen > 0)
            {
                Ok = EVP_DecryptUpdate(Ctx, Out.data(), &Len, Input.Data.data(),
                         static_cast<int>(CipherLen)) == 1;
            }
            int OutLen = 0;
            if (CipherLen > 0)
            {
                OutLen = Len;
            }
            if (Ok)
            {
                Ok = EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(AeadTagLen),
                         const_cast<std::uint8_t*>(Input.Data.data()) + CipherLen) == 1;
            }
            if (Ok)
            {
                Ok = EVP_DecryptFinal_ex(Ctx, Out.data() + OutLen, &Len) == 1;
                OutLen += Len;
            }
            EVP_CIPHER_CTX_free(Ctx);
            if (!Ok || OutLen != static_cast<int>(CipherLen))
            {
                return {};
            }
            Out.resize(static_cast<std::size_t>(OutLen));
            return Out;
        }

        [[nodiscard]] auto CryptSeparate(std::span<const std::uint8_t> Key,
            std::span<const std::uint8_t, SeparateHdrLen> Input, bool Encrypt)
            -> std::optional<std::array<std::uint8_t, SeparateHdrLen>>
        {
            if (Key.size() != AeadKeyLen)
            {
                return std::nullopt;
            }
            EVP_CIPHER_CTX* Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return std::nullopt;
            }
            const auto* Cipher = EVP_aes_128_ecb();
            int InitOk = 0;
            if (Encrypt)
            {
                InitOk = EVP_EncryptInit_ex(Ctx, Cipher, nullptr, Key.data(), nullptr);
            }
            else
            {
                InitOk = EVP_DecryptInit_ex(Ctx, Cipher, nullptr, Key.data(), nullptr);
            }
            if (InitOk != 1 || EVP_CIPHER_CTX_set_padding(Ctx, 0) != 1)
            {
                EVP_CIPHER_CTX_free(Ctx);
                return std::nullopt;
            }
            std::array<std::uint8_t, SeparateHdrLen> Output{};
            int PartLen = 0;
            int UpdateOk = 0;
            if (Encrypt)
            {
                UpdateOk = EVP_EncryptUpdate(Ctx, Output.data(), &PartLen, Input.data(), Input.size());
            }
            else
            {
                UpdateOk = EVP_DecryptUpdate(Ctx, Output.data(), &PartLen, Input.data(), Input.size());
            }
            int FinalLen = 0;
            int FinalOk = 0;
            if (Encrypt)
            {
                FinalOk = EVP_EncryptFinal_ex(Ctx, Output.data() + PartLen, &FinalLen);
            }
            else
            {
                FinalOk = EVP_DecryptFinal_ex(Ctx, Output.data() + PartLen, &FinalLen);
            }
            EVP_CIPHER_CTX_free(Ctx);
            if (UpdateOk != 1 || FinalOk != 1 || PartLen + FinalLen != SeparateHdrLen)
            {
                return std::nullopt;
            }
            return Output;
        }

        [[nodiscard]] auto UdpSeal(const UdpSealInput& Input) -> std::vector<std::uint8_t>
        {
            constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
            if (Input.key.size() != AeadKeyLen || Input.Nonce.size() != 12 || Input.plain.size() > MaxInt ||
                Input.aad.size() > MaxInt ||
                Input.plain.size() > (std::numeric_limits<std::size_t>::max)() - AeadTagLen)
            {
                return {};
            }
            std::vector<std::uint8_t> Output(Input.plain.size() + AeadTagLen);
            EVP_CIPHER_CTX* Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return {};
            }
            int Len = 0;
            bool Ok = EVP_EncryptInit_ex(Ctx, EVP_aes_128_gcm(), nullptr, Input.key.data(),
                          Input.Nonce.data()) == 1;
            if (Ok && !Input.aad.empty())
            {
                Ok = EVP_EncryptUpdate(Ctx, nullptr, &Len, Input.aad.data(),
                         static_cast<int>(Input.aad.size())) == 1;
            }
            int OutputLength = 0;
            if (Ok && !Input.plain.empty())
            {
                Ok = EVP_EncryptUpdate(Ctx, Output.data(), &Len, Input.plain.data(),
                         static_cast<int>(Input.plain.size())) == 1;
                OutputLength = Len;
            }
            if (Ok)
            {
                Ok = EVP_EncryptFinal_ex(Ctx, Output.data() + OutputLength, &Len) == 1;
                OutputLength += Len;
            }
            if (Ok)
            {
                Ok = EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_GET_TAG, 16, Output.data() + OutputLength) == 1;
            }
            EVP_CIPHER_CTX_free(Ctx);
            if (!Ok || OutputLength != static_cast<int>(Input.plain.size()))
            {
                return {};
            }
            Output.resize(static_cast<std::size_t>(OutputLength) + AeadTagLen);
            return Output;
        }

        [[nodiscard]] auto UdpOpen(const UdpOpenInput& Input) -> std::optional<std::vector<std::uint8_t>>
        {
            constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
            if (Input.key.size() != AeadKeyLen || Input.Nonce.size() != 12 ||
                Input.cipher.size() < AeadTagLen || Input.cipher.size() - AeadTagLen > MaxInt ||
                Input.aad.size() > MaxInt)
            {
                return std::nullopt;
            }
            const auto CipherLength = Input.cipher.size() - AeadTagLen;
            std::vector<std::uint8_t> Output(CipherLength);
            EVP_CIPHER_CTX* Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return std::nullopt;
            }
            int Len = 0;
            bool Ok = EVP_DecryptInit_ex(Ctx, EVP_aes_128_gcm(), nullptr, Input.key.data(),
                          Input.Nonce.data()) == 1;
            if (Ok && !Input.aad.empty())
            {
                Ok = EVP_DecryptUpdate(Ctx, nullptr, &Len, Input.aad.data(),
                         static_cast<int>(Input.aad.size())) == 1;
            }
            int OutputLength = 0;
            if (Ok && CipherLength > 0)
            {
                Ok = EVP_DecryptUpdate(Ctx, Output.data(), &Len, Input.cipher.data(),
                         static_cast<int>(CipherLength)) == 1;
                OutputLength = Len;
            }
            if (Ok)
            {
                Ok = EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(AeadTagLen),
                         const_cast<std::uint8_t*>(Input.cipher.data()) + CipherLength) == 1;
            }
            if (Ok)
            {
                Ok = EVP_DecryptFinal_ex(Ctx, Output.data() + OutputLength, &Len) == 1;
                OutputLength += Len;
            }
            EVP_CIPHER_CTX_free(Ctx);
            if (!Ok || OutputLength != static_cast<int>(CipherLength))
            {
                return std::nullopt;
            }
            Output.resize(static_cast<std::size_t>(OutputLength));
            return Output;
        }

        [[nodiscard]] auto DecodeSeparateHeader(std::span<const std::uint8_t> SessionKey,
            std::span<const std::uint8_t> Packet, UdpParseState& State) -> Error
        {
            if (SessionKey.size() != AeadKeyLen ||
                Packet.size() < SeparateHdrLen + 1 + UdpTsLen + 1 + 2 + AeadTagLen)
                return Error::BadLength;
            const auto Separate = Packet.first(SeparateHdrLen);
            const auto SeparatePlain = detail::CryptSeparate(SessionKey,
                std::span<const std::uint8_t, SeparateHdrLen>(Separate), false);
            if (!SeparatePlain)
                return Error::BadAuth;
            std::memcpy(State.SessionId.data(), SeparatePlain->data(), SessionIdLen);
            for (std::size_t I = 0; I < PacketIdLen; ++I)
                State.PacketId = (State.PacketId << 8) | SeparatePlain->at(SessionIdLen + I);
            std::memcpy(State.Nonce.data(), SeparatePlain->data() + SessionIdLen / 2, SessionIdLen / 2);
            std::memcpy(State.Nonce.data() + SessionIdLen / 2, SeparatePlain->data() + SessionIdLen,
                PacketIdLen);
            return Error::None;
        }

        [[nodiscard]] auto OpenUdpBody(std::span<const std::uint8_t> SessionKey,
            std::span<const std::uint8_t> Packet, UdpParseState& State) -> Error
        {
            const auto Subkey = Prism::Shadowsocks2022::SessionKey(SessionKey,
                std::span<const std::uint8_t>(State.SessionId), AeadKeyLen);
            auto Body = detail::UdpOpen(
                detail::UdpOpenInput{Subkey, State.Nonce, Packet.subspan(SeparateHdrLen), {}});
            if (!Body)
                return Error::BadAuth;
            State.Body = std::move(*Body);
            return Error::None;
        }

        [[nodiscard]] auto ValidateUdpBody(const UdpParseInput& Input, UdpParseState& State) -> Error
        {
            if (State.Body.size() < 1 + UdpTsLen + 2)
                return Error::BadLength;
            State.Type = State.Body[0];
            if (State.Type != HeaderTypeClient && State.Type != HeaderTypeServer)
                return Error::BadMessage;
            for (std::size_t I = 0; I < UdpTsLen; ++I)
                State.Timestamp = (State.Timestamp << 8) | State.Body[1 + I];
            const auto Now = Input.Now != 0
                ? Input.Now
                : static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                          .count());
            const auto Difference = Now >= State.Timestamp ? Now - State.Timestamp : State.Timestamp - Now;
            if (Difference > Input.TimeWindow)
                return Error::BadMessage;

            // SIP022 / sing-shadowsocks 的权威顺序：server 帧先携带 client session id。
            State.Offset = 1 + UdpTsLen;
            if (State.Type == HeaderTypeServer)
            {
                if (State.Body.size() - State.Offset < SessionIdLen)
                    return Error::BadLength;
                if (Input.RemoteSessionId)
                    std::memcpy(Input.RemoteSessionId->data(), State.Body.data() + State.Offset,
                        SessionIdLen);
                State.Offset += SessionIdLen;
            }
            if (State.Body.size() - State.Offset < 2)
                return Error::BadLength;
            const auto PaddingLength =
                (static_cast<std::size_t>(State.Body[State.Offset]) << 8) | State.Body[State.Offset + 1];
            State.Offset += 2;
            if (State.Body.size() - State.Offset < PaddingLength)
                return Error::BadLength;
            State.Offset += PaddingLength;
            return Error::None;
        }

        [[nodiscard]] auto ParseUdpAddressPayload(const UdpParseInput& Input, UdpParseState& State) -> Error
        {
            std::size_t Consumed = 0;
            const auto AddressError = ParseAddress(
                std::span<const std::uint8_t>(State.Body).subspan(State.Offset), *Input.Target, Consumed);
            if (AddressError != Error::None)
                return AddressError;
            State.Offset += Consumed;
            const auto PayloadLength = State.Body.size() - State.Offset;
            if (PayloadLength > MaxUdpPayload)
                return Error::BadLength;
            Input.payload->assign(State.Body.begin() + static_cast<std::ptrdiff_t>(State.Offset),
                State.Body.end());
            return Error::None;
        }

    } // namespace detail

    ChunkCodec::ChunkCodec(std::span<const std::uint8_t> Key, std::size_t StartNonce)
        : Key_(Key.begin(), Key.end())
    {
        for (std::size_t I = 0; I < StartNonce; ++I)
        {
            detail::IncNonce(Nonce_);
        }
    }

    [[nodiscard]] auto ChunkCodec::Seal(std::span<const std::uint8_t> Plain) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Out;
        (void)Seal(Plain, Out);
        return Out;
    }

    [[nodiscard]] auto ChunkCodec::OpenLen(std::span<const std::uint8_t> Head) -> std::optional<std::size_t>
    {
        const auto StartNonce = Nonce_;
        if (Head.size() < LenBlockSize)
        {
            return std::nullopt;
        }
        const auto LenPlain = detail::AeadOpen(detail::AeadInput{Key_, Nonce_, Head.first(LenBlockSize)});
        if (LenPlain.size() != 2)
        {
            return std::nullopt;
        }
        detail::IncNonce(Nonce_);
        const auto N = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];
        if (N > MaxChunkSize)
        {
            Nonce_ = StartNonce;
            return std::nullopt;
        }
        return N;
    }

    [[nodiscard]] auto ChunkCodec::OpenPayload(std::span<const std::uint8_t> Data)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Out;
        (void)OpenPayload(Data, Out);
        return Out;
    }

    [[nodiscard]] auto ChunkCodec::Open(std::span<const std::uint8_t> Data, std::size_t& Consumed)
        -> std::vector<std::uint8_t>
    {
        Consumed = 0;
        const auto StartNonce = Nonce_;
        auto Len = OpenLen(Data);
        if (!Len)
        {
            Nonce_ = StartNonce;
            return {};
        }
        if (*Len == 0)
        {
            Consumed = LenBlockSize;
            return {};
        }
        if (Data.size() < LenBlockSize + *Len + AeadTagLen)
        {
            Nonce_ = StartNonce;
            return {};
        }
        auto Body = OpenPayload(Data.subspan(LenBlockSize, *Len + AeadTagLen));
        if (Body.empty())
        {
            Nonce_ = StartNonce;
            return {};
        }
        Consumed = LenBlockSize + *Len + AeadTagLen;
        return Body;
    }

    [[nodiscard]] auto ChunkCodec::SealRaw(std::span<const std::uint8_t> Plain) -> std::vector<std::uint8_t>
    {
        auto Out = detail::AeadSeal(detail::AeadInput{Key_, Nonce_, Plain});
        if (!Out.empty())
        {
            detail::IncNonce(Nonce_);
        }
        return Out;
    }

    [[nodiscard]] auto ChunkCodec::OpenRaw(std::span<const std::uint8_t> Data) -> std::vector<std::uint8_t>
    {
        auto Out = detail::AeadOpen(detail::AeadInput{Key_, Nonce_, Data});
        if (!Out.empty())
        {
            detail::IncNonce(Nonce_);
        }
        return Out;
    }

    [[nodiscard]] auto ChunkCodec::Finish() -> std::vector<std::uint8_t>
    {
        return Seal({});
    }

    [[nodiscard]] auto ParseFixedHeader(std::uint8_t Type, std::uint64_t TimeSec, std::uint16_t VarLen)
        -> std::array<std::uint8_t, FixedHdrPlain>
    {
        std::array<std::uint8_t, FixedHdrPlain> Output{};
        Output[0] = Type;
        for (std::size_t I = 0; I < 8; ++I)
        {
            Output[1 + I] = static_cast<std::uint8_t>((TimeSec >> (56 - I * 8)) & 0xFF);
        }
        Output[9] = static_cast<std::uint8_t>((VarLen >> 8) & 0xFF);
        Output[10] = static_cast<std::uint8_t>(VarLen & 0xFF);
        return Output;
    }

    [[nodiscard]] auto ParseFixedHeader(std::span<const std::uint8_t> Data, FixedHeader& Output) -> Error
    {
        if (Data.size() < FixedHdrPlain)
        {
            return Error::NeedMore;
        }
        Output.Type = Data[0];
        Output.TimeSec = 0;
        for (std::size_t I = 0; I < 8; ++I)
        {
            Output.TimeSec = (Output.TimeSec << 8) | Data[1 + I];
        }
        Output.VarLen = static_cast<std::uint16_t>(Data[9]) << 8 | Data[10];
        return Error::None;
    }

    [[nodiscard]] auto EncodeAddress(const Address& AddressValue) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        if (!EncodeAddress(AddressValue, Output))
        {
            return {};
        }
        return Output;
    }

    [[nodiscard]] auto ParseAddress(std::span<const std::uint8_t> Data, Address& Output, std::size_t& Offset)
        -> Error
    {
        if (Offset >= Data.size())
        {
            return Error::NeedMore;
        }
        Output.Type = static_cast<AddressType>(Data[Offset++]);
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Offset < 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> Buffer{};
            std::snprintf(Buffer.data(), Buffer.size(), "%u.%u.%u.%u",
                static_cast<unsigned int>(Data[Offset]), static_cast<unsigned int>(Data[Offset + 1]),
                static_cast<unsigned int>(Data[Offset + 2]), static_cast<unsigned int>(Data[Offset + 3]));
            Output.Host = Buffer.data();
            Offset += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() - Offset < 16)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char*>(Data.data() + Offset), 16);
            Offset += 16;
            break;
        }
        case AddressType::Domain: {
            if (Offset >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Length = Data[Offset++];
            if (Length == 0)
            {
                return Error::BadAddress;
            }
            if (Data.size() - Offset < Length)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char*>(Data.data() + Offset), Length);
            Offset += Length;
            break;
        }
        default:
            return Error::BadAddress;
        }
        if (Data.size() - Offset < 2)
        {
            return Error::NeedMore;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Offset]) << 8 | Data[Offset + 1];
        Offset += 2;
        return Error::None;
    }

    [[nodiscard]] auto BuildVarHeader(const Address& AddressValue, std::uint16_t PaddingLength,
        std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        auto Output = EncodeAddress(AddressValue);
        if (Output.empty())
        {
            return {};
        }
        constexpr auto MaxVarHeaderLength = (std::numeric_limits<std::uint16_t>::max)();
        if (PaddingLength > MaxVarHeaderLength - 2 ||
            Output.size() > MaxVarHeaderLength - 2 - PaddingLength ||
            Payload.size() > MaxVarHeaderLength - 2 - PaddingLength - Output.size())
        {
            return {};
        }
        Output.push_back(static_cast<std::uint8_t>((PaddingLength >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(PaddingLength & 0xFF));
        for (std::uint16_t I = 0; I < PaddingLength; ++I)
        {
            Output.push_back(0);
        }
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    [[nodiscard]] auto ParseVarHeader(std::span<const std::uint8_t> Data, Address& Output,
        std::span<const std::uint8_t>& Payload) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::NeedMore;
        }
        Output.Type = static_cast<AddressType>(Data[0]);
        std::size_t Off = 1;
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Off < 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> Buffer{};
            std::snprintf(Buffer.data(), Buffer.size(), "%u.%u.%u.%u", static_cast<unsigned int>(Data[Off]),
                static_cast<unsigned int>(Data[Off + 1]), static_cast<unsigned int>(Data[Off + 2]),
                static_cast<unsigned int>(Data[Off + 3]));
            Output.Host = Buffer.data();
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() - Off < 16)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char*>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain: {
            if (Off >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Length = Data[Off++];
            if (Length == 0)
            {
                return Error::BadAddress;
            }
            if (Data.size() - Off < Length)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char*>(Data.data() + Off), Length);
            Off += Length;
            break;
        }
        default:
            return Error::BadAddress;
        }
        if (Data.size() - Off < 2)
        {
            return Error::NeedMore;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        if (Data.size() - Off < 2)
        {
            return Error::NeedMore;
        }
        const auto PaddingLength = static_cast<std::size_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        if (Data.size() - Off < PaddingLength)
        {
            return Error::NeedMore;
        }
        Off += PaddingLength;
        Payload = Data.subspan(Off);
        return Error::None;
    }

    [[nodiscard]] auto BuildUdpPacket(const UdpBuildInput& Input) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        if (!BuildUdpPacket(Input, Output))
        {
            return {};
        }
        return Output;
    }

    [[nodiscard]] auto ParseUdpPacket(const UdpParseInput& Input) -> Error
    {
        if (!Input.Target || !Input.payload)
            return Error::BadLength;
        Input.payload->clear();
        if (Input.packet.size() < MinUdpPacketSize ||
            Input.packet.size() > MaxUdpPacketSize)
        {
            return Error::BadLength;
        }
        detail::UdpParseState State;
        auto ErrorValue = detail::DecodeSeparateHeader(Input.SessionKey, Input.packet, State);
        if (ErrorValue != Error::None)
            return ErrorValue;
        ErrorValue = detail::OpenUdpBody(Input.SessionKey, Input.packet, State);
        if (ErrorValue != Error::None)
            return ErrorValue;
        ErrorValue = detail::ValidateUdpBody(Input, State);
        if (ErrorValue != Error::None)
            return ErrorValue;
        ErrorValue = detail::ParseUdpAddressPayload(Input, State);
        if (ErrorValue != Error::None)
            return ErrorValue;
        if (Input.SessionId)
            std::memcpy(Input.SessionId->data(), State.SessionId.data(), SessionIdLen);
        if (Input.PacketId)
            *Input.PacketId = State.PacketId;
        if (Input.HeaderType)
            *Input.HeaderType = State.Type;
        if (Input.Timestamp)
            *Input.Timestamp = State.Timestamp;
        return Error::None;
    }

} // namespace Prism::Shadowsocks2022
