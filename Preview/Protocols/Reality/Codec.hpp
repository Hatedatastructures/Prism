/**
 * @file Codec.hpp
 * @brief Reality 密钥工具与认证编解码（纯函数）
 * @details 对齐 mihomo component/tls/reality.go 与
 * C++ src/prism/handshake/reality/util/：
 *          - base64url 编解码（RFC 4648 无填充）
 *          - X25519 密钥对生成/派生
 *          - AuthKey 派生：HKDF-Extract(random[:20], shared) +
 *            HKDF-Expand("REALITY", 32)
 *          - SessionId Seal/Open：AES-256-GCM（Nonce = random[20:32]，
 *            AAD = ClientHello raw 且 SessionId 区清零）
 *          - 短 ID 解析
 * @note 参考 Reality 协议规范。
 */

#pragma once

#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Utility/Crypto/Hkdf.hpp>
#include <Preview/Protocols/Reality/Types.hpp>

namespace Preview::Reality
{

    /**
     * @brief base64url 编码（RFC 4648，无填充）
     * @param Data 输入
     * @return base64url 字符串
     */
    [[nodiscard]] inline auto Base64urlEncode(std::span<const std::uint8_t> Data) -> std::string
    {
        static constexpr char Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string Output;
        Output.reserve((Data.size() + 2) / 3 * 4);
        std::size_t I = 0;
        for (; I + 2 < Data.size(); I += 3)
        {
            const auto N = static_cast<std::uint32_t>(Data[I]) << 16 |
                           static_cast<std::uint32_t>(Data[I + 1]) << 8 | Data[I + 2];
            Output.push_back(Table[(N >> 18) & 0x3F]);
            Output.push_back(Table[(N >> 12) & 0x3F]);
            Output.push_back(Table[(N >> 6) & 0x3F]);
            Output.push_back(Table[N & 0x3F]);
        }
        if (I + 1 == Data.size())
        {
            const auto N = static_cast<std::uint32_t>(Data[I]) << 16;
            Output.push_back(Table[(N >> 18) & 0x3F]);
            Output.push_back(Table[(N >> 12) & 0x3F]);
        }
        else if (I + 2 == Data.size())
        {
            const auto N = static_cast<std::uint32_t>(Data[I]) << 16 | static_cast<std::uint32_t>(Data[I + 1])
                                                                           << 8;
            Output.push_back(Table[(N >> 18) & 0x3F]);
            Output.push_back(Table[(N >> 12) & 0x3F]);
            Output.push_back(Table[(N >> 6) & 0x3F]);
        }
        return Output;
    }

    /**
     * @brief base64url 解码（无填充，失败返回空）
     * @param Input 输入
     * @return 解码字节
     */
    [[nodiscard]] inline auto Base64urlDecode(std::string_view Input) -> std::vector<std::uint8_t>
    {
        auto ValueOf = [](const char Character) -> int
        {
            if (Character >= 'A' && Character <= 'Z')
            {
                return Character - 'A';
            }
            if (Character >= 'a' && Character <= 'z')
            {
                return Character - 'a' + 26;
            }
            if (Character >= '0' && Character <= '9')
            {
                return Character - '0' + 52;
            }
            if (Character == '-')
            {
                return 62;
            }
            if (Character == '_')
            {
                return 63;
            }
            return -1;
        };
        if (Input.size() % 4 == 1)
        {
            return {};
        }
        std::vector<std::uint8_t> Output;
        std::uint32_t Acc = 0;
        int Bits = 0;
        for (const char Character : Input)
        {
            const int Value = ValueOf(Character);
            if (Value < 0)
            {
                return {};
            }
            Acc = (Acc << 6) | static_cast<std::uint32_t>(Value);
            Bits += 6;
            if (Bits >= 8)
            {
                Bits -= 8;
                Output.push_back(static_cast<std::uint8_t>((Acc >> Bits) & 0xFF));
                if (Bits == 0)
                {
                    Acc = 0;
                }
                else
                {
                    Acc &= (std::uint32_t{1} << Bits) - 1;
                }
            }
        }
        if (Bits != 0 && (Acc & ((std::uint32_t{1} << Bits) - 1)) != 0)
        {
            return {};
        }
        return Output;
    }

    /**
     * @brief 生成 X25519 密钥对（BoringSSL 原生 API）
     * @param PrivateKey 输出私钥（32 字节）
     * @param PublicKey 输出公钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto GenerateKeypair(
        std::array<std::uint8_t, KeyLen> &PrivateKey,
        std::array<std::uint8_t, KeyLen> &PublicKey) -> bool
    {
        PrivateKey.fill(0);
        PublicKey.fill(0);
        if (RAND_bytes(PrivateKey.data(), static_cast<int>(KeyLen)) != 1)
        {
            return true;
        }
        X25519_public_from_private(PublicKey.data(), PrivateKey.data());
        return false;
    }

    /**
     * @brief 由私钥派生公钥（BoringSSL 原生 API）
     * @param PrivateKey 私钥（32 字节）
     * @param PublicKey 输出公钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto DerivePublicKey(
        std::span<const std::uint8_t> PrivateKey,
        std::array<std::uint8_t, KeyLen> &PublicKey) -> bool
    {
        if (PrivateKey.size() != KeyLen)
        {
            return true;
        }
        X25519_public_from_private(PublicKey.data(), PrivateKey.data());
        return false;
    }

    /**
     * @brief X25519 共享密钥（BoringSSL 原生 API）
     * @param PrivateKey 私钥（32 字节）
     * @param PublicKey 公钥（32 字节）
     * @param Output 输出共享密钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto X25519Shared(
        std::span<const std::uint8_t> PrivateKey,
        std::span<const std::uint8_t> PublicKey,
        std::array<std::uint8_t, KeyLen> &Output) -> bool
    {
        Output.fill(0);
        if (PrivateKey.size() != KeyLen || PublicKey.size() != KeyLen)
        {
            return true;
        }
        if (X25519(Output.data(), PrivateKey.data(), PublicKey.data()) != 1)
        {
            return true;
        }
        bool AllZero = true;
        for (const auto Byte : Output)
        {
            if (Byte != 0)
            {
                AllZero = false;
                break;
            }
        }
        return AllZero;
    }

    /**
     * @brief 派生认证密钥（对齐 mihomo reality.go，HMAC 实现 HKDF）
     * @param SharedSecret X25519 共享密钥（32 字节）
     * @param ClientRandom TLS ClientRandom（32 字节：前 20 salt，后 12 Nonce）
     * @param Output 输出 32 字节 AuthKey
     * @return 成功返回 false
     * @details HKDF-Extract(salt=random[:20], ikm=shared) +
     * HKDF-Expand(Info="REALITY", 32)，用 HMAC-SHA256 实现
     * （BoringSSL 无 EVP_PKEY HKDF 上下文）。
     */
    [[nodiscard]] inline auto DeriveAuthKey(std::span<const std::uint8_t> SharedSecret,
                                              std::span<const std::uint8_t> ClientRandom,
                                              std::array<std::uint8_t, KeyLen> &Output) -> bool
    {
        Output.fill(0);
        if (SharedSecret.size() != KeyLen || ClientRandom.size() != 32)
        {
            return true;
        }
        auto HmacSha256 = [](std::span<const std::uint8_t> Key,
                              std::span<const std::uint8_t> Data,
                              std::array<std::uint8_t, 32> &Digest) -> bool
        {
            unsigned int Len = 0;
            const auto *Result = HMAC(
                EVP_sha256(),
                Key.data(),
                static_cast<int>(Key.size()),
                Data.data(),
                Data.size(),
                Digest.data(),
                &Len);
            return Result != nullptr && Len == Digest.size();
        };

        // HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
        std::array<std::uint8_t, 32> Prk{};
        if (!HmacSha256(ClientRandom.first(20), SharedSecret, Prk))
        {
            return true;
        }

        // HKDF-Expand: OKM = HMAC-SHA256(PRK, Info || 0x01)，32 字节单块
        std::vector<std::uint8_t> Info(sizeof(RealityInfo) - 1 + 1);
        std::memcpy(Info.data(), RealityInfo, sizeof(RealityInfo) - 1);
        Info.back() = 0x01;
        std::array<std::uint8_t, 32> Okm{};
        if (!HmacSha256(Prk, Info, Okm))
        {
            return true;
        }
        std::memcpy(Output.data(), Okm.data(), KeyLen);
        return false;
    }

    /// TLS 1.3 AES-128-GCM traffic secrets used by the Reality wire carrier.
    struct Tls13Keys final
    {
        std::array<std::uint8_t, 32> MasterSecret{};
        std::array<std::uint8_t, 16> ClientHandshakeKey{};
        std::array<std::uint8_t, 12> ClientHandshakeIv{};
        std::array<std::uint8_t, 16> ServerHandshakeKey{};
        std::array<std::uint8_t, 12> ServerHandshakeIv{};
        std::array<std::uint8_t, 32> ClientFinishedKey{};
        std::array<std::uint8_t, 16> ClientApplicationKey{};
        std::array<std::uint8_t, 12> ClientApplicationIv{};
        std::array<std::uint8_t, 16> ServerApplicationKey{};
        std::array<std::uint8_t, 12> ServerApplicationIv{};
    };

    /// Decrypted TLS 1.3 record content and its inner content type.
    struct Tls13Plaintext final
    {
        std::uint8_t ContentType{0};
        std::vector<std::uint8_t> Data;
    };

    namespace Detail
    {

        [[nodiscard]] inline auto ExpandTls13Label(
            std::span<const std::uint8_t> Secret,
            const std::string_view Label,
            std::span<const std::uint8_t> Context,
            std::span<std::uint8_t> Output) -> bool
        {
            const auto [ErrorCode, Expanded] = Preview::Crypto::ExpandLabel(
                Preview::Crypto::ExpandParams{Secret, Label, Context, Output.size()});
            if (ErrorCode != Preview::Fault::Code::Success || Expanded.size() != Output.size())
            {
                return true;
            }
            std::copy(Expanded.begin(), Expanded.end(), Output.begin());
            return false;
        }

        [[nodiscard]] inline auto Tls13Nonce(const std::array<std::uint8_t, 12> &Iv,
                                             const std::uint64_t Sequence) -> std::array<std::uint8_t, 12>
        {
            auto Nonce = Iv;
            for (std::size_t Index = 0; Index < sizeof(Sequence); ++Index)
            {
                Nonce[Nonce.size() - 1 - Index] ^=
                    static_cast<std::uint8_t>(Sequence >> (Index * 8));
            }
            return Nonce;
        }

        [[nodiscard]] inline auto Aes128GcmSeal(
            std::span<const std::uint8_t> Key,
            const std::array<std::uint8_t, 12> &Nonce,
            std::span<const std::uint8_t> AdditionalData,
            std::span<const std::uint8_t> Plaintext,
            std::vector<std::uint8_t> &Ciphertext) -> bool
        {
            if (Key.size() != 16 || Plaintext.size() >
                static_cast<std::size_t>((std::numeric_limits<int>::max)()))
            {
                return true;
            }
            Ciphertext.assign(Plaintext.size() + 16, 0);
            auto *Context = EVP_CIPHER_CTX_new();
            if (!Context)
            {
                return true;
            }
            int Length = 0;
            int Written = 0;
            bool Ok = EVP_EncryptInit_ex(Context, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1;
            if (Ok)
            {
                Ok = EVP_CIPHER_CTX_ctrl(Context, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1;
            }
            if (Ok)
            {
                Ok = EVP_EncryptInit_ex(Context, nullptr, nullptr, Key.data(), Nonce.data()) == 1;
            }
            if (Ok && !AdditionalData.empty())
            {
                Ok = EVP_EncryptUpdate(Context, nullptr, &Length, AdditionalData.data(),
                                       static_cast<int>(AdditionalData.size())) == 1;
            }
            if (Ok && !Plaintext.empty())
            {
                Ok = EVP_EncryptUpdate(Context, Ciphertext.data(), &Written, Plaintext.data(),
                                       static_cast<int>(Plaintext.size())) == 1;
            }
            if (Ok)
            {
                Ok = EVP_EncryptFinal_ex(Context, Ciphertext.data() + Written, &Length) == 1;
                Written += Length;
            }
            if (Ok && Written == static_cast<int>(Plaintext.size()))
            {
                Ok = EVP_CIPHER_CTX_ctrl(Context, EVP_CTRL_GCM_GET_TAG, 16,
                                         Ciphertext.data() + Plaintext.size()) == 1;
            }
            EVP_CIPHER_CTX_free(Context);
            if (!Ok)
            {
                Ciphertext.clear();
            }
            return !Ok;
        }

        [[nodiscard]] inline auto Aes128GcmOpen(
            std::span<const std::uint8_t> Key,
            const std::array<std::uint8_t, 12> &Nonce,
            std::span<const std::uint8_t> AdditionalData,
            std::span<const std::uint8_t> Ciphertext,
            std::vector<std::uint8_t> &Plaintext) -> bool
        {
            if (Key.size() != 16 || Ciphertext.size() < 16 ||
                Ciphertext.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
            {
                return true;
            }
            const auto PlaintextSize = Ciphertext.size() - 16;
            Plaintext.assign(PlaintextSize, 0);
            auto *Context = EVP_CIPHER_CTX_new();
            if (!Context)
            {
                return true;
            }
            int Length = 0;
            int Written = 0;
            bool Ok = EVP_DecryptInit_ex(Context, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1;
            if (Ok)
            {
                Ok = EVP_CIPHER_CTX_ctrl(Context, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1;
            }
            if (Ok)
            {
                Ok = EVP_DecryptInit_ex(Context, nullptr, nullptr, Key.data(), Nonce.data()) == 1;
            }
            if (Ok && !AdditionalData.empty())
            {
                Ok = EVP_DecryptUpdate(Context, nullptr, &Length, AdditionalData.data(),
                                       static_cast<int>(AdditionalData.size())) == 1;
            }
            if (Ok && PlaintextSize != 0)
            {
                Ok = EVP_DecryptUpdate(Context, Plaintext.data(), &Written, Ciphertext.data(),
                                       static_cast<int>(PlaintextSize)) == 1;
            }
            if (Ok)
            {
                Ok = EVP_CIPHER_CTX_ctrl(
                         Context, EVP_CTRL_GCM_SET_TAG, 16,
                         const_cast<std::uint8_t *>(Ciphertext.data() + PlaintextSize)) == 1;
            }
            if (Ok)
            {
                Ok = EVP_DecryptFinal_ex(Context, Plaintext.data() + Written, &Length) == 1;
                Written += Length;
            }
            EVP_CIPHER_CTX_free(Context);
            if (!Ok || Written != static_cast<int>(PlaintextSize))
            {
                Plaintext.clear();
                return true;
            }
            return false;
        }

    } // namespace Detail

    /**
     * @brief Derive the TLS 1.3 AES-128-GCM handshake traffic keys.
     * @param SharedSecret X25519 ECDHE shared secret
     * @param ClientHello Handshake message bytes, including its 4-byte header
     * @param ServerHello Handshake message bytes, including its 4-byte header
     */
    [[nodiscard]] inline auto DeriveTls13Keys(
        std::span<const std::uint8_t> SharedSecret,
        std::span<const std::uint8_t> ClientHello,
        std::span<const std::uint8_t> ServerHello) -> std::pair<Error, Tls13Keys>
    {
        Tls13Keys Result;
        if (SharedSecret.size() != 32)
        {
            return {Error::KdfError, Result};
        }

        const std::array<std::uint8_t, 32> Zeros{};
        const auto EmptyHash = Preview::Crypto::Sha256(std::span<const std::uint8_t>{});
        const auto EarlySecret = Preview::Crypto::HkdfExtract({}, Zeros);
        std::array<std::uint8_t, 32> DerivedSecret{};
        if (Detail::ExpandTls13Label(EarlySecret, "derived", EmptyHash, DerivedSecret))
        {
            return {Error::KdfError, Result};
        }
        const auto HandshakeSecret = Preview::Crypto::HkdfExtract(DerivedSecret, SharedSecret);
        const auto TranscriptHash = Preview::Crypto::Sha256(ClientHello, ServerHello);
        std::array<std::uint8_t, 32> ClientHandshakeSecret{};
        std::array<std::uint8_t, 32> ServerHandshakeSecret{};
        if (Detail::ExpandTls13Label(HandshakeSecret, "c hs traffic", TranscriptHash,
                                      ClientHandshakeSecret) ||
            Detail::ExpandTls13Label(HandshakeSecret, "s hs traffic", TranscriptHash,
                                     ServerHandshakeSecret) ||
            Detail::ExpandTls13Label(ClientHandshakeSecret, "key", {}, Result.ClientHandshakeKey) ||
            Detail::ExpandTls13Label(ClientHandshakeSecret, "iv", {}, Result.ClientHandshakeIv) ||
            Detail::ExpandTls13Label(ClientHandshakeSecret, "finished", {}, Result.ClientFinishedKey) ||
            Detail::ExpandTls13Label(ServerHandshakeSecret, "key", {}, Result.ServerHandshakeKey) ||
            Detail::ExpandTls13Label(ServerHandshakeSecret, "iv", {}, Result.ServerHandshakeIv))
        {
            return {Error::KdfError, Result};
        }

        if (Detail::ExpandTls13Label(HandshakeSecret, "derived", EmptyHash, DerivedSecret))
        {
            return {Error::KdfError, Result};
        }
        Result.MasterSecret = Preview::Crypto::HkdfExtract(DerivedSecret, Zeros);
        return {Error::None, Result};
    }

    /** @brief Compute a SHA-256 transcript hash over an arbitrary number of handshake messages. */
    template <std::size_t Count>
    [[nodiscard]] inline auto HashTranscript(
        const std::array<std::span<const std::uint8_t>, Count> &Parts)
        -> std::array<std::uint8_t, 32>
    {
        std::vector<std::uint8_t> Concatenated;
        std::size_t Size = 0;
        for (const auto Part : Parts)
        {
            Size += Part.size();
        }
        Concatenated.reserve(Size);
        for (const auto Part : Parts)
        {
            Concatenated.insert(Concatenated.end(), Part.begin(), Part.end());
        }
        return Preview::Crypto::Sha256(Concatenated);
    }

    [[nodiscard]] inline auto ComputeFinished(
        std::span<const std::uint8_t> FinishedKey,
        std::span<const std::uint8_t> TranscriptHash) -> std::array<std::uint8_t, 32>
    {
        return Preview::Crypto::HmacSha256(FinishedKey, TranscriptHash);
    }

    /** @brief Derive both application traffic keys from a TLS 1.3 transcript. */
    [[nodiscard]] inline auto DeriveApplicationKeys(
        std::span<const std::uint8_t> MasterSecret,
        std::span<const std::uint8_t> TranscriptHash,
        Tls13Keys &Keys) -> Error
    {
        if (MasterSecret.size() != 32 || TranscriptHash.size() != 32)
        {
            return Error::KdfError;
        }
        std::array<std::uint8_t, 32> ClientApplicationSecret{};
        std::array<std::uint8_t, 32> ServerApplicationSecret{};
        if (Detail::ExpandTls13Label(MasterSecret, "c ap traffic", TranscriptHash,
                                      ClientApplicationSecret) ||
            Detail::ExpandTls13Label(MasterSecret, "s ap traffic", TranscriptHash,
                                     ServerApplicationSecret) ||
            Detail::ExpandTls13Label(ClientApplicationSecret, "key", {}, Keys.ClientApplicationKey) ||
            Detail::ExpandTls13Label(ClientApplicationSecret, "iv", {}, Keys.ClientApplicationIv) ||
            Detail::ExpandTls13Label(ServerApplicationSecret, "key", {}, Keys.ServerApplicationKey) ||
            Detail::ExpandTls13Label(ServerApplicationSecret, "iv", {}, Keys.ServerApplicationIv))
        {
            return Error::KdfError;
        }
        return Error::None;
    }

    /** @brief Encrypt a TLS 1.3 record using AES-128-GCM and an inner content type. */
    [[nodiscard]] inline auto EncryptTlsRecord(
        std::span<const std::uint8_t> Key,
        const std::array<std::uint8_t, 12> &Iv,
        const std::uint64_t Sequence,
        const std::uint8_t ContentType,
        std::span<const std::uint8_t> Data) -> std::pair<Error, std::vector<std::uint8_t>>
    {
        if (Data.size() > 0xFFFFu - 17u)
        {
            return {Error::BadLength, {}};
        }
        std::vector<std::uint8_t> Plaintext(Data.begin(), Data.end());
        Plaintext.push_back(ContentType);
        const auto Nonce = Detail::Tls13Nonce(Iv, Sequence);
        std::vector<std::uint8_t> Ciphertext;
        std::array<std::uint8_t, 5> Header{0x17, 0x03, 0x03, 0, 0};
        const auto CiphertextLength = Plaintext.size() + 16;
        Header[3] = static_cast<std::uint8_t>(CiphertextLength >> 8);
        Header[4] = static_cast<std::uint8_t>(CiphertextLength);
        if (Detail::Aes128GcmSeal(Key, Nonce, Header, Plaintext, Ciphertext))
        {
            return {Error::CryptoError, {}};
        }
        std::vector<std::uint8_t> Record(Header.begin(), Header.end());
        Record.insert(Record.end(), Ciphertext.begin(), Ciphertext.end());
        return {Error::None, std::move(Record)};
    }

    /** @brief Decrypt and remove TLS 1.3 record padding and the inner content type. */
    [[nodiscard]] inline auto DecryptTlsRecord(
        std::span<const std::uint8_t> Record,
        std::span<const std::uint8_t> Key,
        const std::array<std::uint8_t, 12> &Iv,
        const std::uint64_t Sequence) -> std::pair<Error, Tls13Plaintext>
    {
        Tls13Plaintext Result;
        if (Record.size() < 5 + 16 || Record[0] != 0x17 || Record[1] != 0x03 ||
            Record[2] != 0x03)
        {
            return {Error::BadMessage, Result};
        }
        const auto Length = static_cast<std::size_t>(Record[3]) << 8 | Record[4];
        if (Length != Record.size() - 5 || Length < 16)
        {
            return {Error::BadLength, Result};
        }
        const auto Nonce = Detail::Tls13Nonce(Iv, Sequence);
        std::vector<std::uint8_t> Plaintext;
        if (Detail::Aes128GcmOpen(Key, Nonce, Record.first(5), Record.subspan(5), Plaintext) ||
            Plaintext.empty())
        {
            return {Error::CryptoError, Result};
        }
        std::size_t TypeIndex = Plaintext.size();
        while (TypeIndex > 0 && Plaintext[TypeIndex - 1] == 0)
        {
            --TypeIndex;
        }
        if (TypeIndex == 0 || (Plaintext[TypeIndex - 1] != 0x14 &&
                               Plaintext[TypeIndex - 1] != 0x15 &&
                               Plaintext[TypeIndex - 1] != 0x16 &&
                               Plaintext[TypeIndex - 1] != 0x17))
        {
            return {Error::BadMessage, Result};
        }
        Result.ContentType = Plaintext[TypeIndex - 1];
        Result.Data.assign(Plaintext.begin(), Plaintext.begin() +
                                             static_cast<std::ptrdiff_t>(TypeIndex - 1));
        return {Error::None, std::move(Result)};
    }

    /// SessionId 密封输入（AuthKey + random + hello）
    struct SessionIdSealInput
    {
        std::span<const std::uint8_t> AuthKey;      ///< 32 字节认证密钥
        std::span<const std::uint8_t> ClientRandom; ///< TLS ClientRandom（32 字节）
        std::span<const std::uint8_t> plain;         ///< 明文（16 字节）
        std::span<const std::uint8_t> hello;         ///< ClientHello 原始消息（AAD）
    };

    /// SessionId 解析输入（AuthKey + random + hello）
    struct SessionIdOpenInput
    {
        std::span<const std::uint8_t> AuthKey;      ///< 32 字节认证密钥
        std::span<const std::uint8_t> ClientRandom; ///< TLS ClientRandom（32 字节）
        std::span<const std::uint8_t> cipher;        ///< 32 字节密文（16 + tag 16）
        std::span<const std::uint8_t> hello;         ///< ClientHello 原始消息（AAD）
    };

    /**
     * @brief Seal SessionId（客户端侧，对齐 mihomo reality.go）
     * @param Input 密封输入
     * @param Output 输出 32 字节密文（16 + tag 16）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto SealSessionId(
        const SessionIdSealInput &Input,
        std::array<std::uint8_t, SessionIdAuthLen> &Output) -> bool
    {
        Output.fill(0);
        constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
        if (Input.AuthKey.size() != KeyLen || Input.plain.size() != 16 ||
            Input.ClientRandom.size() != 32 || Input.hello.size() < 39 + 32 ||
            Input.hello.size() > MaxInt)
        {
            return true;
        }
        // AAD：hello 且 SessionId 区（偏移 39 起 32 字节）清零
        std::vector<std::uint8_t> AAD(Input.hello.begin(), Input.hello.end());
        std::memset(AAD.data() + 39, 0, 32);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            return true;
        }
        int Len = 0;
        bool Ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, Input.AuthKey.data(),
                                     Input.ClientRandom.data() + 20) == 1;
        if (Ok && !AAD.empty())
        {
            Ok = EVP_EncryptUpdate(ctx, nullptr, &Len, AAD.data(), static_cast<int>(AAD.size())) == 1;
        }
        if (Ok)
        {
            Ok = EVP_EncryptUpdate(ctx, Output.data(), &Len, Input.plain.data(),
                                   static_cast<int>(Input.plain.size())) == 1;
        }
        int OutLen = 0;
        if (Ok)
        {
            OutLen = Len;
        }
        if (Ok)
        {
            Ok = EVP_EncryptFinal_ex(ctx, Output.data() + OutLen, &Len) == 1;
            OutLen += Len;
        }
        if (Ok && OutLen == 16)
        {
            Ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, Output.data() + OutLen) == 1;
        }
        EVP_CIPHER_CTX_free(ctx);
        if (!Ok || OutLen != 16)
        {
            Output.fill(0);
            return true;
        }
        return false;
    }

    /**
     * @brief Open SessionId（服务端侧）
     * @param Input 解析输入
     * @param Output 输出 16 字节明文
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto OpenSessionId(
        const SessionIdOpenInput &Input,
        std::array<std::uint8_t, 16> &Output) -> bool
    {
        Output.fill(0);
        constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
        if (Input.AuthKey.size() != KeyLen || Input.cipher.size() != SessionIdAuthLen ||
            Input.ClientRandom.size() != 32 || Input.hello.size() < 39 + 32 ||
            Input.hello.size() > MaxInt)
        {
            return true;
        }
        std::vector<std::uint8_t> AAD(Input.hello.begin(), Input.hello.end());
        std::memset(AAD.data() + 39, 0, 32);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            return true;
        }
        int Len = 0;
        bool Ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, Input.AuthKey.data(),
                                     Input.ClientRandom.data() + 20) == 1;
        if (Ok && !AAD.empty())
        {
            Ok = EVP_DecryptUpdate(ctx, nullptr, &Len, AAD.data(), static_cast<int>(AAD.size())) == 1;
        }
        if (Ok)
        {
            Ok = EVP_DecryptUpdate(ctx, Output.data(), &Len, Input.cipher.data(), 16) == 1;
        }
        int OutLen = 0;
        if (Ok)
        {
            OutLen = Len;
        }
        if (Ok)
        {
            Ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                     const_cast<std::uint8_t *>(Input.cipher.data()) + 16) == 1;
        }
        if (Ok)
        {
            Ok = EVP_DecryptFinal_ex(ctx, Output.data() + OutLen, &Len) == 1;
            OutLen += Len;
        }
        EVP_CIPHER_CTX_free(ctx);
        if (!Ok || OutLen != 16)
        {
            Output.fill(0);
            return true;
        }
        return false;
    }

    /**
     * @brief 解析 base64url 私钥
     * @param Encoded base64url 字符串
     * @param Output 输出私钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto ParsePrivateKey(
        std::string_view Encoded,
        std::array<std::uint8_t, KeyLen> &Output) -> bool
    {
        Output.fill(0);
        const auto Raw = Base64urlDecode(Encoded);
        if (Raw.size() != KeyLen)
        {
            return true;
        }
        std::copy(Raw.begin(), Raw.end(), Output.begin());
        return false;
    }

    /**
     * @brief 编码公钥为 base64url
     * @param PublicKey 公钥（32 字节）
     * @return base64url 字符串
     */
    [[nodiscard]] inline auto EncodePublicKey(std::span<const std::uint8_t> PublicKey) -> std::string
    {
        return Base64urlEncode(PublicKey);
    }

    /**
     * @brief 解析 16 进制短 ID（最多 8 字节）
     * @param Hex 16 进制字符串
     * @param Output 输出短 ID（8 字节，不足补 0）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto ParseShortId(
        std::string_view Hex,
        std::array<std::uint8_t, MaxShortIdLen> &Output) -> bool
    {
        Output.fill(0);
        if (Hex.size() > 16 || Hex.size() % 2 != 0)
        {
            return true;
        }
        auto Nibble = [](const char Character) -> int
        {
            if (Character >= '0' && Character <= '9')
            {
                return Character - '0';
            }
            if (Character >= 'a' && Character <= 'f')
            {
                return Character - 'a' + 10;
            }
            if (Character >= 'A' && Character <= 'F')
            {
                return Character - 'A' + 10;
            }
            return -1;
        };
        std::size_t Pos = 0;
        for (std::size_t I = 0; I < Hex.size(); I += 2)
        {
            const int Hi = Nibble(Hex[I]);
            const int Lo = Nibble(Hex[I + 1]);
            if (Hi < 0 || Lo < 0)
            {
                return true;
            }
            Output[Pos++] = static_cast<std::uint8_t>((Hi << 4) | Lo);
        }
        return false;
    }

} // namespace Preview::Reality
