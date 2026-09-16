/**
 * @file ResponseCodec.hpp
 * @brief Shadowsocks 2022 响应/数据报编解码
 * @details 负责无状态 UDP 数据报的 SeparateHeader、目标地址和
 *          AEAD 载荷组装/解析。会话密钥、分块数据面和请求握手分别
 *          位于 KeyDerivation.hpp、ChunkCodec.hpp 与 RequestCodec.hpp。
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Shadowsocks2022/RequestCodec.hpp>
#include <Preview/Protocols/Shadowsocks2022/Types.hpp>

namespace Preview::Shadowsocks2022
{

    /// UDP 数据报填充类型（客户端/服务端）
    inline constexpr std::uint8_t UdpType = HeaderTypeClient;
    /// UDP 数据报 AEAD 使用 AES-128-GCM，密钥固定 16 字节
    inline constexpr std::size_t AeadKeyLen = 16;
    /// SeparateHeader 总长度
    inline constexpr std::size_t SeparateHdrLen = SessionIdLen + PacketIdLen;
    /// 时间戳长度
    inline constexpr std::size_t UdpTsLen = 8;
    /// 单个 UDP 数据报载荷上限
    inline constexpr std::size_t MaxUdpPayload = 65535;

    namespace detail
    {

        /**
         * @brief UDP 数据报 AEAD 加密输入
         */
        struct UdpSealInput
        {
            std::span<const std::uint8_t> key;
            std::span<const std::uint8_t> Nonce;
            std::span<const std::uint8_t> plain;
            std::span<const std::uint8_t> aad;
        };

        /**
         * @brief UDP 数据报 AEAD 解密输入
         */
        struct UdpOpenInput
        {
            std::span<const std::uint8_t> key;
            std::span<const std::uint8_t> Nonce;
            std::span<const std::uint8_t> cipher;
            std::span<const std::uint8_t> aad;
        };

        /**
         * @brief 对 UDP SeparateHeader 执行无填充 AES-128-ECB
         * @param Key 预共享密钥
         * @param Input 16 字节明文或密文
         * @param Encrypt true = 加密，false = 解密
         * @return 转换后的 16 字节；参数或 OpenSSL 失败返回空值
         */
        [[nodiscard]] inline auto CryptSeparate(
            std::span<const std::uint8_t> Key,
            std::span<const std::uint8_t, SeparateHdrLen> Input,
            bool Encrypt)
            -> std::optional<std::array<std::uint8_t, SeparateHdrLen>>
        {
            if (Key.size() != AeadKeyLen)
            {
                return std::nullopt;
            }
            EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return std::nullopt;
            }
            const auto *Cipher = EVP_aes_128_ecb();
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
                UpdateOk = EVP_EncryptUpdate(
                    Ctx,
                    Output.data(),
                    &PartLen,
                    Input.data(),
                    Input.size());
            }
            else
            {
                UpdateOk = EVP_DecryptUpdate(
                    Ctx,
                    Output.data(),
                    &PartLen,
                    Input.data(),
                    Input.size());
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

        /**
         * @brief UDP 数据报单次 AES-128-GCM 加密
         * @param Input 加密输入
         * @return 密文 + 16B tag；失败返回空
         */
        [[nodiscard]] inline auto UdpSeal(const UdpSealInput &Input)
            -> std::vector<std::uint8_t>
        {
            constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
            if (Input.key.size() != AeadKeyLen || Input.Nonce.size() != 12 ||
                Input.plain.size() > MaxInt || Input.aad.size() > MaxInt ||
                Input.plain.size() > (std::numeric_limits<std::size_t>::max)() - AeadTagLen)
            {
                return {};
            }
            std::vector<std::uint8_t> Output(Input.plain.size() + AeadTagLen);
            EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return {};
            }
            int Len = 0;
            bool Ok = EVP_EncryptInit_ex(
                          Ctx,
                          EVP_aes_128_gcm(),
                          nullptr,
                          Input.key.data(),
                          Input.Nonce.data()) == 1;
            if (Ok && !Input.aad.empty())
            {
                Ok = EVP_EncryptUpdate(
                    Ctx,
                    nullptr,
                    &Len,
                    Input.aad.data(),
                    static_cast<int>(Input.aad.size())) == 1;
            }
            int OutputLength = 0;
            if (Ok && !Input.plain.empty())
            {
                Ok = EVP_EncryptUpdate(
                    Ctx,
                    Output.data(),
                    &Len,
                    Input.plain.data(),
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
                Ok = EVP_CIPHER_CTX_ctrl(
                    Ctx,
                    EVP_CTRL_GCM_GET_TAG,
                    16,
                    Output.data() + OutputLength) == 1;
            }
            EVP_CIPHER_CTX_free(Ctx);
            if (!Ok || OutputLength != static_cast<int>(Input.plain.size()))
            {
                return {};
            }
            Output.resize(static_cast<std::size_t>(OutputLength) + AeadTagLen);
            return Output;
        }

        /**
         * @brief UDP 数据报单次 AES-128-GCM 解密
         * @param Input 解密输入
         * @return 明文；nullopt = 校验失败或参数非法，空 vector = 合法空载荷
         */
        [[nodiscard]] inline auto UdpOpen(const UdpOpenInput &Input)
            -> std::optional<std::vector<std::uint8_t>>
        {
            constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
            if (Input.key.size() != AeadKeyLen || Input.Nonce.size() != 12 ||
                Input.cipher.size() < AeadTagLen ||
                Input.cipher.size() - AeadTagLen > MaxInt || Input.aad.size() > MaxInt)
            {
                return std::nullopt;
            }
            const auto CipherLength = Input.cipher.size() - AeadTagLen;
            std::vector<std::uint8_t> Output(CipherLength);
            EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return std::nullopt;
            }
            int Len = 0;
            bool Ok = EVP_DecryptInit_ex(
                          Ctx,
                          EVP_aes_128_gcm(),
                          nullptr,
                          Input.key.data(),
                          Input.Nonce.data()) == 1;
            if (Ok && !Input.aad.empty())
            {
                Ok = EVP_DecryptUpdate(
                    Ctx,
                    nullptr,
                    &Len,
                    Input.aad.data(),
                    static_cast<int>(Input.aad.size())) == 1;
            }
            int OutputLength = 0;
            if (Ok && CipherLength > 0)
            {
                Ok = EVP_DecryptUpdate(
                    Ctx,
                    Output.data(),
                    &Len,
                    Input.cipher.data(),
                    static_cast<int>(CipherLength)) == 1;
                OutputLength = Len;
            }
            if (Ok)
            {
                Ok = EVP_CIPHER_CTX_ctrl(
                    Ctx,
                    EVP_CTRL_GCM_SET_TAG,
                    static_cast<int>(AeadTagLen),
                    const_cast<std::uint8_t *>(Input.cipher.data()) + CipherLength) == 1;
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

    } // namespace detail

    /**
     * @brief UDP 数据报构造输入
     */
    struct UdpBuildInput
    {
        std::span<const std::uint8_t> SessionKey;
        std::uint64_t PacketId{0};
        const Address *Target{nullptr};
        std::span<const std::uint8_t> payload;
        std::span<const std::uint8_t> SessionId{};
        std::uint64_t Timestamp{0};
        std::span<const std::uint8_t> RemoteSessionId{};
        std::uint8_t HeaderType{HeaderTypeClient};
    };

    /**
     * @brief UDP 数据报解析输入
     */
    struct UdpParseInput
    {
        std::span<const std::uint8_t> SessionKey;
        std::span<const std::uint8_t> packet;
        Address *Target{nullptr};
        std::vector<std::uint8_t> *payload{nullptr};
        std::array<std::uint8_t, SessionIdLen> *SessionId{nullptr};
        std::uint64_t *PacketId{nullptr};
        std::uint64_t *Timestamp{nullptr};
        std::uint8_t *HeaderType{nullptr};
        std::array<std::uint8_t, SessionIdLen> *RemoteSessionId{nullptr};
        std::uint64_t Now{0}; ///< 校验时间基准（0 = 当前系统时间）
        std::uint64_t TimeWindow{30}; ///< 时间戳容忍窗口（秒）
    };

    /**
     * @brief 构造 UDP 数据报（写入复用缓冲）
     * @param Input 构造输入
     * @param Output 输出缓冲
     * @return false = 参数非法
     */
    template <typename Alloc>
    [[nodiscard]] inline auto BuildUdpPacket(
        const UdpBuildInput &Input,
        std::vector<std::uint8_t, Alloc> &Output) -> bool
    {
        Output.clear();
        if (!Input.Target || Input.SessionKey.size() != AeadKeyLen ||
            Input.payload.size() > MaxUdpPayload ||
            (Input.HeaderType != HeaderTypeClient && Input.HeaderType != HeaderTypeServer))
        {
            return false;
        }

        std::array<std::uint8_t, SessionIdLen> SessionId{};
        if (Input.SessionId.empty())
        {
            if (RAND_bytes(SessionId.data(), static_cast<int>(SessionId.size())) != 1)
            {
                return false;
            }
        }
        else if (Input.SessionId.size() != SessionIdLen)
        {
            return false;
        }
        else
        {
            std::memcpy(SessionId.data(), Input.SessionId.data(), SessionIdLen);
        }
        if (Input.HeaderType == HeaderTypeServer && Input.RemoteSessionId.size() != SessionIdLen)
        {
            return false;
        }

        std::array<std::uint8_t, SeparateHdrLen> SeparatePlain{};
        std::memcpy(SeparatePlain.data(), SessionId.data(), SessionIdLen);
        for (std::size_t I = 0; I < PacketIdLen; ++I)
        {
            SeparatePlain[SessionIdLen + I] =
                static_cast<std::uint8_t>((Input.PacketId >> (56 - I * 8)) & 0xFF);
        }
        const auto Separate = detail::CryptSeparate(
            Input.SessionKey,
            std::span<const std::uint8_t, SeparateHdrLen>(SeparatePlain),
            true);
        if (!Separate)
        {
            return false;
        }

        const auto Subkey = Preview::Shadowsocks2022::SessionKey(
            Input.SessionKey,
            std::span<const std::uint8_t>(SessionId),
            AeadKeyLen);
        std::vector<std::uint8_t> Plain;
        Plain.reserve(1 + UdpTsLen + 32 + 2 + Input.payload.size());
        Plain.push_back(Input.HeaderType);
        std::uint64_t Timestamp;
        if (Input.Timestamp != 0)
        {
            Timestamp = Input.Timestamp;
        }
        else
        {
            Timestamp = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
        }
        for (std::size_t I = 0; I < UdpTsLen; ++I)
        {
            Plain.push_back(static_cast<std::uint8_t>((Timestamp >> (56 - I * 8)) & 0xFF));
        }
        if (Input.HeaderType == HeaderTypeServer)
        {
            Plain.insert(Plain.end(), Input.RemoteSessionId.begin(), Input.RemoteSessionId.end());
            Plain.push_back(0);
            Plain.push_back(0);
        }
        else
        {
            // SIP022 request body places the destination before padding.
            if (!EncodeAddress(*Input.Target, Plain))
            {
                return false;
            }
            Plain.push_back(0);
            Plain.push_back(0);
        }
        Plain.insert(Plain.end(), Input.payload.begin(), Input.payload.end());

        std::array<std::uint8_t, 12> Nonce{};
        std::memcpy(Nonce.data(), SeparatePlain.data() + SessionIdLen / 2, SessionIdLen / 2);
        std::memcpy(Nonce.data() + SessionIdLen / 2,
                    SeparatePlain.data() + SessionIdLen, PacketIdLen);

        const auto BodyEnc = detail::UdpSeal(detail::UdpSealInput{Subkey, Nonce, Plain, {}});
        if (BodyEnc.empty())
        {
            return false;
        }
        Output.reserve(Separate->size() + BodyEnc.size());
        Output.insert(Output.end(), Separate->begin(), Separate->end());
        Output.insert(Output.end(), BodyEnc.begin(), BodyEnc.end());
        return true;
    }

    /**
     * @brief 构造 UDP 数据报（逐包 AEAD 无状态加密）
     * @param Input 构造输入
     * @return 完整数据报字节；参数非法返回空
     */
    [[nodiscard]] inline auto BuildUdpPacket(const UdpBuildInput &Input)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        if (!BuildUdpPacket(Input, Output))
        {
            return {};
        }
        return Output;
    }

    /**
     * @brief 解析 UDP 数据报（逐包 AEAD 无状态解密）
     * @param Input 解析输入
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseUdpPacket(const UdpParseInput &Input) -> Error
    {
        if (!Input.Target || !Input.payload)
        {
            return Error::BadLength;
        }
        const auto &SessionKey16 = Input.SessionKey;
        const auto &Packet = Input.packet;
        auto &Target = *Input.Target;
        auto &Payload = *Input.payload;
        Payload.clear();
        if (SessionKey16.size() != AeadKeyLen ||
            Packet.size() < SeparateHdrLen + 1 + UdpTsLen + 1 + 2 + AeadTagLen)
        {
            return Error::BadLength;
        }
        const auto Separate = Packet.first(SeparateHdrLen);
        const auto SeparatePlain = detail::CryptSeparate(
            SessionKey16,
            std::span<const std::uint8_t, SeparateHdrLen>(Separate),
            false);
        if (!SeparatePlain)
        {
            return Error::BadAuth;
        }

        const auto SessionId = std::span<const std::uint8_t>(
            SeparatePlain->data(), SessionIdLen);
        std::uint64_t PacketId = 0;
        for (std::size_t I = 0; I < PacketIdLen; ++I)
        {
            PacketId = (PacketId << 8) | SeparatePlain->at(SessionIdLen + I);
        }
        const auto Subkey = Preview::Shadowsocks2022::SessionKey(
            SessionKey16,
            SessionId,
            AeadKeyLen);
        std::array<std::uint8_t, 12> Nonce{};
        std::memcpy(Nonce.data(), SeparatePlain->data() + SessionIdLen / 2, SessionIdLen / 2);
        std::memcpy(Nonce.data() + SessionIdLen / 2,
                    SeparatePlain->data() + SessionIdLen, PacketIdLen);
        const auto Body = detail::UdpOpen(detail::UdpOpenInput{
            Subkey,
            Nonce,
            Packet.subspan(SeparateHdrLen),
            {}});
        if (!Body)
        {
            return Error::BadAuth;
        }
        if (Body->size() < 1 + UdpTsLen + 2)
        {
            return Error::BadLength;
        }
        const auto Type = (*Body)[0];
        if (Type != HeaderTypeClient && Type != HeaderTypeServer)
        {
            return Error::BadMessage;
        }
        std::uint64_t Timestamp = 0;
        for (std::size_t I = 0; I < UdpTsLen; ++I)
        {
            Timestamp = (Timestamp << 8) | (*Body)[1 + I];
        }
        std::uint64_t Now;
        if (Input.Now != 0)
        {
            Now = Input.Now;
        }
        else
        {
            Now = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
        }
        std::uint64_t Difference;
        if (Now >= Timestamp)
        {
            Difference = Now - Timestamp;
        }
        else
        {
            Difference = Timestamp - Now;
        }
        if (Difference > Input.TimeWindow)
        {
            return Error::BadMessage;
        }

        std::size_t Off = 1 + UdpTsLen;
        if (Type == HeaderTypeServer)
        {
            if (Body->size() - Off < SessionIdLen + 2)
            {
                return Error::BadLength;
            }
            if (Input.RemoteSessionId)
            {
                std::memcpy(Input.RemoteSessionId->data(), Body->data() + Off, SessionIdLen);
            }
            Off += SessionIdLen;
        }
        std::size_t Consumed = 0;
        if (Type == HeaderTypeClient)
        {
            const auto AddressError = ParseAddress(
                std::span<const std::uint8_t>(*Body).subspan(Off),
                Target,
                Consumed);
            if (AddressError != Error::None)
            {
                return AddressError;
            }
            Off += Consumed;
        }
        if (Body->size() - Off < 2)
        {
            return Error::BadLength;
        }
        const auto PaddingLength = static_cast<std::size_t>((*Body)[Off]) << 8 | (*Body)[Off + 1];
        Off += 2;
        if (Body->size() - Off < PaddingLength)
        {
            return Error::BadLength;
        }
        Off += PaddingLength;
        Payload.assign(Body->begin() + static_cast<std::ptrdiff_t>(Off), Body->end());
        if (Input.SessionId)
        {
            std::memcpy(Input.SessionId->data(), SessionId.data(), SessionIdLen);
        }
        if (Input.PacketId)
        {
            *Input.PacketId = PacketId;
        }
        if (Input.HeaderType)
        {
            *Input.HeaderType = Type;
        }
        if (Input.Timestamp)
        {
            *Input.Timestamp = Timestamp;
        }
        return Error::None;
    }

} // namespace Preview::Shadowsocks2022
