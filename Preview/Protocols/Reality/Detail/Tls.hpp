/**
 * @file Tls13.hpp
 * @brief Reality TLS 1.3 密钥调度与记录层加解密。
 * @details 负责 TLS 1.3 transcript、traffic secret、Finished、AES-128-GCM
 *          record 以及 inner content type 和 padding 的 wire 语义。
 * @note 该头只拥有 TLS 1.3 记录层工具；Reality SessionId 认证位于
 *       SessionId.hpp，X25519/AuthKey 位于 KeyMaterial.hpp。
 */

#pragma once

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <expected>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Utility/Crypto/Hkdf.hpp>
#include <Preview/Foundation/Utility/Crypto/SecretScope.hpp>

namespace Preview::Reality::Detail
{

    /// Reality 记录层拥有的 TLS 1.3 AES-128-GCM 流量密钥。
    struct Tls13Keys final
    {
        std::array<std::uint8_t, 32> MasterSecret{};
        std::array<std::uint8_t, 16> ClientHandshakeKey{};
        std::array<std::uint8_t, 12> ClientHandshakeIv{};
        std::array<std::uint8_t, 16> ServerHandshakeKey{};
        std::array<std::uint8_t, 12> ServerHandshakeIv{};
        std::array<std::uint8_t, 32> ClientFinishedKey{};
        std::array<std::uint8_t, 32> ServerFinishedKey{};
        std::array<std::uint8_t, 16> ClientApplicationKey{};
        std::array<std::uint8_t, 12> ClientApplicationIv{};
        std::array<std::uint8_t, 16> ServerApplicationKey{};
        std::array<std::uint8_t, 12> ServerApplicationIv{};
    };

    /// 解密后的 TLS 1.3 record 内容与 inner content type。
    struct Tls13Plaintext final
    {
        std::uint8_t ContentType{0};
        std::vector<std::uint8_t> Data;
    };

    /// TLS 1.3 密钥调度输入；所有 span 仅借用至同步返回。
    struct Tls13KeyScheduleInput final
    {
        std::span<const std::uint8_t> SharedSecret;
        std::span<const std::uint8_t> ClientHello;
        std::span<const std::uint8_t> ServerHello;
    };

    /// TLS 1.3 记录密封输入；密钥、IV 和载荷由调用者拥有。
    struct Tls13RecordSealInput final
    {
        std::span<const std::uint8_t> Key;
        std::span<const std::uint8_t, 12> Iv;
        std::uint64_t Sequence{0};
        std::uint8_t ContentType{0};
        std::span<const std::uint8_t> Data;
    };

    /// TLS 1.3 记录打开输入；记录仅借用至同步返回。
    struct Tls13RecordOpenInput final
    {
        std::span<const std::uint8_t> Record;
        std::span<const std::uint8_t> Key;
        std::span<const std::uint8_t, 12> Iv;
        std::uint64_t Sequence{0};
    };

    namespace TlsDetail
    {

        [[nodiscard]] inline auto Tls13Nonce(std::span<const std::uint8_t, 12> Iv,
                                             const std::uint64_t Sequence)
            -> std::array<std::uint8_t, 12>
        {
            std::array<std::uint8_t, 12> Nonce{};
            std::copy(Iv.begin(), Iv.end(), Nonce.begin());
            for (std::size_t Index = 0; Index < sizeof(Sequence); ++Index)
            {
                Nonce[Nonce.size() - 1 - Index] ^=
                    static_cast<std::uint8_t>(Sequence >> (Index * 8));
            }
            return Nonce;
        }

        struct Aes128GcmSealInput final
        {
            std::span<const std::uint8_t> Key;
            std::span<const std::uint8_t, 12> Nonce;
            std::span<const std::uint8_t> AdditionalData;
            std::span<const std::uint8_t> Plaintext;
        };

        [[nodiscard]] inline auto Aes128GcmSeal(
            const Aes128GcmSealInput Input,
            std::vector<std::uint8_t> &Ciphertext) -> bool
        {
            if (Input.Key.size() != 16 || Input.Plaintext.size() >
                static_cast<std::size_t>((std::numeric_limits<int>::max)()))
            {
                return true;
            }
            Ciphertext.assign(Input.Plaintext.size() + 16, 0);
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
                Ok = EVP_EncryptInit_ex(Context, nullptr, nullptr, Input.Key.data(), Input.Nonce.data()) == 1;
            }
            if (Ok && !Input.AdditionalData.empty())
            {
                Ok = EVP_EncryptUpdate(Context, nullptr, &Length, Input.AdditionalData.data(),
                                       static_cast<int>(Input.AdditionalData.size())) == 1;
            }
            if (Ok && !Input.Plaintext.empty())
            {
                Ok = EVP_EncryptUpdate(Context, Ciphertext.data(), &Written, Input.Plaintext.data(),
                                       static_cast<int>(Input.Plaintext.size())) == 1;
            }
            if (Ok)
            {
                Ok = EVP_EncryptFinal_ex(Context, Ciphertext.data() + Written, &Length) == 1;
                Written += Length;
            }
            if (Ok && Written == static_cast<int>(Input.Plaintext.size()))
            {
                Ok = EVP_CIPHER_CTX_ctrl(Context, EVP_CTRL_GCM_GET_TAG, 16,
                                         Ciphertext.data() + Input.Plaintext.size()) == 1;
            }
            EVP_CIPHER_CTX_free(Context);
            if (!Ok)
            {
                Ciphertext.clear();
            }
            return !Ok;
        }

        struct Aes128GcmOpenInput final
        {
            std::span<const std::uint8_t> Key;
            std::span<const std::uint8_t, 12> Nonce;
            std::span<const std::uint8_t> AdditionalData;
            std::span<const std::uint8_t> Ciphertext;
        };

        [[nodiscard]] inline auto Aes128GcmOpen(
            const Aes128GcmOpenInput Input,
            std::vector<std::uint8_t> &Plaintext) -> bool
        {
            if (Input.Key.size() != 16 || Input.Ciphertext.size() < 16 ||
                Input.Ciphertext.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
            {
                return true;
            }
            const auto PlaintextSize = Input.Ciphertext.size() - 16;
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
                Ok = EVP_DecryptInit_ex(Context, nullptr, nullptr, Input.Key.data(), Input.Nonce.data()) == 1;
            }
            if (Ok && !Input.AdditionalData.empty())
            {
                Ok = EVP_DecryptUpdate(Context, nullptr, &Length, Input.AdditionalData.data(),
                                       static_cast<int>(Input.AdditionalData.size())) == 1;
            }
            if (Ok && PlaintextSize != 0)
            {
                Ok = EVP_DecryptUpdate(Context, Plaintext.data(), &Written, Input.Ciphertext.data(),
                                       static_cast<int>(PlaintextSize)) == 1;
            }
            if (Ok)
            {
                Ok = EVP_CIPHER_CTX_ctrl(
                         Context, EVP_CTRL_GCM_SET_TAG, 16,
                         const_cast<std::uint8_t *>(Input.Ciphertext.data() + PlaintextSize)) == 1;
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

        /**
         * @brief 派生一组 TLS 流量密钥；所有输入和输出仅借用至同步返回。
         * @return 首个完整密码学失败；无取消、半关闭、连接关闭或 executor 行为。
         */
        [[nodiscard]] inline auto ExpandTrafficKeys(
            std::span<const std::uint8_t> Secret,
            const std::array<std::span<std::uint8_t>, 3> &Outputs) -> Fault::Failure
        {
            constexpr std::array<std::string_view, 3> Labels{"key", "iv", "finished"};
            for (std::size_t Index = 0; Index < Outputs.size(); ++Index)
            {
                const auto Failure = Crypto::ExpandLabel({Secret, Labels[Index], {}}, Outputs[Index]);
                if (Failure.Failed())
                {
                    return Failure;
                }
            }
            return {};
        }

    } // namespace TlsDetail

    /**
     * @brief 派生 TLS 1.3 握手密钥；输入同步借用，成功值拥有密钥。
     * @return 参数或原生失败直接返回；无取消、半关闭、连接关闭或 executor 行为。
     */
    [[nodiscard]] inline auto DeriveTls13Keys(const Tls13KeyScheduleInput Input)
        -> std::expected<Tls13Keys, Fault::Failure>
    {
        if (Input.SharedSecret.size() != 32)
        {
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument, {}});
        }
        Tls13Keys Result;
        const Crypto::SecretScope ResultCleanup{
            {reinterpret_cast<std::uint8_t *>(&Result), sizeof(Result)}};
        const std::array<std::uint8_t, 32> Zeros{};
        const auto EmptyHash = Crypto::Sha256(std::span<const std::uint8_t>{});
        if (!EmptyHash)
        {
            return std::unexpected(EmptyHash.error());
        }
        auto EarlySecret = Crypto::HkdfExtract({}, Zeros);
        if (!EarlySecret)
        {
            return std::unexpected(EarlySecret.error());
        }
        const Crypto::SecretScope EarlyCleanup{*EarlySecret};
        std::array<std::uint8_t, 32> DerivedSecret{};
        const Crypto::SecretScope DerivedCleanup{DerivedSecret};
        auto Failure = Crypto::ExpandLabel({*EarlySecret, "derived", *EmptyHash}, DerivedSecret);
        if (Failure.Failed())
        {
            return std::unexpected(Failure);
        }
        auto HandshakeSecret = Crypto::HkdfExtract(DerivedSecret, Input.SharedSecret);
        if (!HandshakeSecret)
        {
            return std::unexpected(HandshakeSecret.error());
        }
        const Crypto::SecretScope HandshakeCleanup{*HandshakeSecret};
        const std::array<std::span<const std::uint8_t>, 2> Parts{Input.ClientHello, Input.ServerHello};
        const auto TranscriptHash = Crypto::Sha256(Crypto::HashInput{Parts});
        if (!TranscriptHash)
        {
            return std::unexpected(TranscriptHash.error());
        }
        std::array<std::uint8_t, 32> TrafficSecret{};
        const Crypto::SecretScope TrafficCleanup{TrafficSecret};
        Failure = Crypto::ExpandLabel({*HandshakeSecret, "c hs traffic", *TranscriptHash}, TrafficSecret);
        if (Failure.Failed())
        {
            return std::unexpected(Failure);
        }
        Failure = TlsDetail::ExpandTrafficKeys(TrafficSecret,
            {Result.ClientHandshakeKey, Result.ClientHandshakeIv, Result.ClientFinishedKey});
        if (Failure.Failed())
        {
            return std::unexpected(Failure);
        }
        Failure = Crypto::ExpandLabel({*HandshakeSecret, "s hs traffic", *TranscriptHash}, TrafficSecret);
        if (Failure.Failed())
        {
            return std::unexpected(Failure);
        }
        Failure = TlsDetail::ExpandTrafficKeys(TrafficSecret,
            {Result.ServerHandshakeKey, Result.ServerHandshakeIv, Result.ServerFinishedKey});
        if (Failure.Failed())
        {
            return std::unexpected(Failure);
        }
        Failure = Crypto::ExpandLabel({*HandshakeSecret, "derived", *EmptyHash}, DerivedSecret);
        if (Failure.Failed())
        {
            return std::unexpected(Failure);
        }
        auto MasterSecret = Crypto::HkdfExtract(DerivedSecret, Zeros);
        if (!MasterSecret)
        {
            return std::unexpected(MasterSecret.error());
        }
        const Crypto::SecretScope MasterCleanup{*MasterSecret};
        Result.MasterSecret = *MasterSecret;
        return Result;
    }

    /** @brief 分段借用握手消息并计算摘要；同步返回拥有型摘要或完整失败，无连接生命周期行为。 */
    template <std::size_t Count>
    [[nodiscard]] inline auto HashTranscript(
        const std::array<std::span<const std::uint8_t>, Count> &Parts)
        -> std::expected<std::array<std::uint8_t, 32>, Fault::Failure>
    {
        return Crypto::Sha256(Crypto::HashInput{Parts});
    }

    /** @brief 同步借用密钥及摘要并计算 Finished；返回拥有型值或完整失败，无连接生命周期行为。 */
    [[nodiscard]] inline auto ComputeFinished(
        std::span<const std::uint8_t> FinishedKey,
        std::span<const std::uint8_t> TranscriptHash)
        -> std::expected<std::array<std::uint8_t, 32>, Fault::Failure>
    {
        return Crypto::HmacSha256(FinishedKey, TranscriptHash);
    }

    /**
     * @brief 同步借用主密钥、摘要和密钥组，全部派生成功后更新应用密钥。
     * @return 完整失败且原密钥组不变；无取消、半关闭、连接关闭或 executor 行为。
     */
    [[nodiscard]] inline auto DeriveApplicationKeys(
        std::span<const std::uint8_t> MasterSecret,
        std::span<const std::uint8_t> TranscriptHash,
        Tls13Keys &Keys) -> std::expected<void, Fault::Failure>
    {
        if (MasterSecret.size() != 32 || TranscriptHash.size() != 32)
        {
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument, {}});
        }
        auto Next = Keys;
        const Crypto::SecretScope KeysCleanup{
            {reinterpret_cast<std::uint8_t *>(&Next), sizeof(Next)}};
        std::array<std::uint8_t, 32> Secret{};
        const Crypto::SecretScope SecretCleanup{Secret};
        constexpr std::array<std::string_view, 2> TrafficLabels{"c ap traffic", "s ap traffic"};
        const std::array<std::span<std::uint8_t>, 4> Outputs{
            Next.ClientApplicationKey, Next.ClientApplicationIv,
            Next.ServerApplicationKey, Next.ServerApplicationIv};
        for (std::size_t Index = 0; Index < TrafficLabels.size(); ++Index)
        {
            auto Failure = Crypto::ExpandLabel({MasterSecret, TrafficLabels[Index], TranscriptHash}, Secret);
            if (Failure.Failed())
            {
                return std::unexpected(Failure);
            }
            Failure = Crypto::ExpandLabel({Secret, "key", {}}, Outputs[Index * 2]);
            if (Failure.Failed())
            {
                return std::unexpected(Failure);
            }
            Failure = Crypto::ExpandLabel({Secret, "iv", {}}, Outputs[Index * 2 + 1]);
            if (Failure.Failed())
            {
                return std::unexpected(Failure);
            }
        }
        Keys = Next;
        return {};
    }
    /**
     * @brief 使用 AES-128-GCM 和 inner content type 加密 TLS 1.3 record。
     * @details Input 中的 key、IV 和 payload 只借用至同步返回；输出 record 由返回值拥有。
     */
    [[nodiscard]] inline auto EncryptTlsRecord(
        const Tls13RecordSealInput Input) -> std::pair<Error, std::vector<std::uint8_t>>
    {
        if (Input.Data.size() > 0xFFFFu - 17u)
        {
            return {Error::BadLength, {}};
        }
        std::vector<std::uint8_t> Plaintext(Input.Data.begin(), Input.Data.end());
        Plaintext.push_back(Input.ContentType);
        const auto Nonce = TlsDetail::Tls13Nonce(Input.Iv, Input.Sequence);
        std::vector<std::uint8_t> Ciphertext;
        std::array<std::uint8_t, 5> Header{0x17, 0x03, 0x03, 0, 0};
        const auto CiphertextLength = Plaintext.size() + 16;
        Header[3] = static_cast<std::uint8_t>(CiphertextLength >> 8);
        Header[4] = static_cast<std::uint8_t>(CiphertextLength);
        if (TlsDetail::Aes128GcmSeal(
                TlsDetail::Aes128GcmSealInput{
                    Input.Key, std::span<const std::uint8_t, 12>(Nonce), Header, Plaintext},
                Ciphertext))
        {
            return {Error::CryptoError, {}};
        }
        std::vector<std::uint8_t> Record(Header.begin(), Header.end());
        Record.insert(Record.end(), Ciphertext.begin(), Ciphertext.end());
        return {Error::None, std::move(Record)};
    }

    /**
     * @brief 解密 TLS 1.3 record，并移除 padding 和 inner content type。
     * @details Input 中的 record、key 和 IV 只借用至同步返回；认证失败返回空明文。
     */
    [[nodiscard]] inline auto DecryptTlsRecord(
        const Tls13RecordOpenInput Input) -> std::pair<Error, Tls13Plaintext>
    {
        Tls13Plaintext Result;
        if (Input.Record.size() < 5 + 16 || Input.Record[0] != 0x17 ||
            Input.Record[1] != 0x03 || Input.Record[2] != 0x03)
        {
            return {Error::BadMessage, Result};
        }
        const auto Length = static_cast<std::size_t>(Input.Record[3]) << 8 | Input.Record[4];
        if (Length != Input.Record.size() - 5 || Length < 16)
        {
            return {Error::BadLength, Result};
        }
        const auto Nonce = TlsDetail::Tls13Nonce(Input.Iv, Input.Sequence);
        std::vector<std::uint8_t> Plaintext;
        if (TlsDetail::Aes128GcmOpen(
                TlsDetail::Aes128GcmOpenInput{
                    Input.Key, std::span<const std::uint8_t, 12>(Nonce),
                    Input.Record.first(5), Input.Record.subspan(5)},
                Plaintext) ||
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

} // namespace Preview::Reality::Detail
