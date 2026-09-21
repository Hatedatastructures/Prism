/**
 * @file Response.hpp
 * @brief Reality TLS 1.3 服务端握手响应构造。
 * @details 生成 Mihomo Reality 所需的 Ed25519 伪证书、CertificateVerify、
 *          Server Finished 和加密握手记录。该职责独立于入站认证与数据面。
 */
#pragma once

#include <Preview/Protocols/Reality/Codec.hpp>

#include <openssl/asn1.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace Preview::Reality::Response
{

    using Bytes = std::vector<std::uint8_t>;

    struct Ed25519Keypair final
    {
        std::array<std::uint8_t, 32> PublicKey{};
        std::array<std::uint8_t, 64> PrivateKey{};
    };

    struct HandshakeResult final
    {
        Bytes Plaintext;
        Bytes Record;
    };

    struct HandshakeRequest final
    {
        std::span<const std::uint8_t> AuthKey;
        const Tls13Keys &Keys;
        std::span<const std::uint8_t> ClientHello;
        std::span<const std::uint8_t> ServerHello;
    };

    namespace detail
    {

        inline auto AppendU16(Bytes &Output, const std::size_t Value) -> void
        {
            Output.push_back(static_cast<std::uint8_t>(Value >> 8));
            Output.push_back(static_cast<std::uint8_t>(Value));
        }

        inline auto AppendU24(Bytes &Output, const std::size_t Value) -> void
        {
            Output.push_back(static_cast<std::uint8_t>(Value >> 16));
            Output.push_back(static_cast<std::uint8_t>(Value >> 8));
            Output.push_back(static_cast<std::uint8_t>(Value));
        }

        [[nodiscard]] inline auto MakeHandshakeMessage(
            const std::uint8_t Type, const std::span<const std::uint8_t> Body) -> Bytes
        {
            Bytes Message;
            Message.reserve(4 + Body.size());
            Message.push_back(Type);
            AppendU24(Message, Body.size());
            Message.insert(Message.end(), Body.begin(), Body.end());
            return Message;
        }

        [[nodiscard]] inline auto HmacSha512(
            const std::span<const std::uint8_t> Key,
            const std::span<const std::uint8_t> Data,
            std::array<std::uint8_t, 64> &Output) -> bool
        {
            unsigned int Length = 0;
            const auto *Result = HMAC(EVP_sha512(), Key.data(), static_cast<int>(Key.size()),
                                      Data.data(), Data.size(), Output.data(), &Length);
            return Result == nullptr || Length != Output.size();
        }

        [[nodiscard]] inline auto GenerateCertificate(
            const std::span<const std::uint8_t> AuthKey)
            -> std::pair<Bytes, Ed25519Keypair>
        {
            Bytes CertificateDer;
            Ed25519Keypair Keypair;
            if (AuthKey.size() != 32)
            {
                return {CertificateDer, Keypair};
            }

            ED25519_keypair(Keypair.PublicKey.data(), Keypair.PrivateKey.data());
            if (std::all_of(Keypair.PublicKey.begin(), Keypair.PublicKey.end(),
                            [](const auto Byte) { return Byte == 0; }))
            {
                return {CertificateDer, Keypair};
            }

            using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
            using CertificatePtr = std::unique_ptr<X509, decltype(&X509_free)>;
            using NamePtr = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;
            PkeyPtr Pkey(EVP_PKEY_from_raw_public_key(
                             EVP_pkey_ed25519(), Keypair.PublicKey.data(), Keypair.PublicKey.size()),
                         EVP_PKEY_free);
            CertificatePtr Certificate(X509_new(), X509_free);
            NamePtr Name(X509_NAME_new(), X509_NAME_free);
            if (!Pkey || !Certificate || !Name || X509_set_version(Certificate.get(), 2) != 1 ||
                ASN1_INTEGER_set(X509_get_serialNumber(Certificate.get()), 1) != 1 ||
                X509_gmtime_adj(X509_get_notBefore(Certificate.get()), 0) == nullptr ||
                X509_gmtime_adj(X509_get_notAfter(Certificate.get()), 3600) == nullptr ||
                X509_NAME_add_entry_by_txt(
                    Name.get(), "CN", MBSTRING_ASC,
                    reinterpret_cast<const unsigned char *>("Reality"), -1, -1, 0) != 1 ||
                X509_set_subject_name(Certificate.get(), Name.get()) != 1 ||
                X509_set_issuer_name(Certificate.get(), Name.get()) != 1 ||
                X509_set_pubkey(Certificate.get(), Pkey.get()) != 1)
            {
                return {CertificateDer, Keypair};
            }

            const auto *Algorithm = OBJ_nid2obj(NID_ED25519);
            auto *TbsAlgorithm = const_cast<X509_ALGOR *>(X509_get0_tbs_sigalg(Certificate.get()));
            X509_ALGOR_set0(TbsAlgorithm, const_cast<ASN1_OBJECT *>(Algorithm), V_ASN1_UNDEF, nullptr);
            const X509_ALGOR *OuterAlgorithmConst = nullptr;
            X509_get0_signature(nullptr, &OuterAlgorithmConst, Certificate.get());
            auto *OuterAlgorithm = const_cast<X509_ALGOR *>(OuterAlgorithmConst);
            X509_ALGOR_set0(OuterAlgorithm, const_cast<ASN1_OBJECT *>(Algorithm), V_ASN1_UNDEF, nullptr);

            std::array<std::uint8_t, 64> Signature{};
            if (HmacSha512(AuthKey, Keypair.PublicKey, Signature) ||
                X509_set1_signature_value(Certificate.get(), Signature.data(), Signature.size()) != 1)
            {
                return {CertificateDer, Keypair};
            }

            const auto Size = i2d_X509(Certificate.get(), nullptr);
            if (Size <= 0)
            {
                return {CertificateDer, Keypair};
            }
            CertificateDer.resize(static_cast<std::size_t>(Size));
            auto *Output = CertificateDer.data();
            if (i2d_X509(Certificate.get(), &Output) != Size)
            {
                CertificateDer.clear();
            }
            return {std::move(CertificateDer), std::move(Keypair)};
        }

        [[nodiscard]] inline auto BuildCertificateBody(
            const std::span<const std::uint8_t> CertificateDer) -> Bytes
        {
            Bytes CertificateList;
            AppendU24(CertificateList, CertificateDer.size());
            CertificateList.insert(CertificateList.end(), CertificateDer.begin(), CertificateDer.end());
            AppendU16(CertificateList, 0);

            Bytes Body{0};
            AppendU24(Body, CertificateList.size());
            Body.insert(Body.end(), CertificateList.begin(), CertificateList.end());
            return Body;
        }

        [[nodiscard]] inline auto BuildCertificateVerifyBody(
            const Ed25519Keypair &Keypair,
            const std::span<const std::uint8_t> TranscriptHash) -> Bytes
        {
            static constexpr std::string_view Context = "TLS 1.3, server CertificateVerify";
            Bytes Message;
            Message.reserve(64 + Context.size() + 1 + TranscriptHash.size());
            Message.insert(Message.end(), 64, 0x20);
            Message.insert(Message.end(), Context.begin(), Context.end());
            Message.push_back(0);
            Message.insert(Message.end(), TranscriptHash.begin(), TranscriptHash.end());

            std::array<std::uint8_t, 64> Signature{};
            ED25519_sign(Signature.data(), Message.data(), Message.size(), Keypair.PrivateKey.data());

            Bytes Body;
            AppendU16(Body, 0x0807);
            AppendU16(Body, Signature.size());
            Body.insert(Body.end(), Signature.begin(), Signature.end());
            return Body;
        }

    } // namespace detail

    [[nodiscard]] inline auto BuildServerHandshake(const HandshakeRequest &Request)
        -> std::pair<Preview::Error, HandshakeResult>
    {
        HandshakeResult Result;
        const auto [CertificateDer, Keypair] = detail::GenerateCertificate(Request.AuthKey);
        if (CertificateDer.empty())
        {
            return {Preview::Error::CryptoError, Result};
        }

        const Bytes EncryptedExtensions = {0x08, 0x00, 0x00, 0x02, 0x00, 0x00};
        const auto EncryptedExtensionsMessage = detail::MakeHandshakeMessage(
            0x08, std::span<const std::uint8_t>(EncryptedExtensions).subspan(4));
        const auto CertificateMessage = detail::MakeHandshakeMessage(
            0x0B, detail::BuildCertificateBody(CertificateDer));
        Result.Plaintext.insert(Result.Plaintext.end(), EncryptedExtensionsMessage.begin(),
                                EncryptedExtensionsMessage.end());
        Result.Plaintext.insert(Result.Plaintext.end(), CertificateMessage.begin(), CertificateMessage.end());

        const auto CertificateVerifyTranscript = std::array<std::span<const std::uint8_t>, 3>{
            Request.ClientHello, Request.ServerHello, Result.Plaintext};
        const auto CertificateVerifyHash = HashTranscript(CertificateVerifyTranscript);
        const auto CertificateVerifyMessage = detail::MakeHandshakeMessage(
            0x0F, detail::BuildCertificateVerifyBody(Keypair, CertificateVerifyHash));
        Result.Plaintext.insert(Result.Plaintext.end(), CertificateVerifyMessage.begin(),
                                CertificateVerifyMessage.end());

        const auto FinishedTranscript = std::array<std::span<const std::uint8_t>, 3>{
            Request.ClientHello, Request.ServerHello, Result.Plaintext};
        const auto FinishedHash = HashTranscript(FinishedTranscript);
        const auto VerifyData = ComputeFinished(Request.Keys.ServerFinishedKey, FinishedHash);
        const auto FinishedMessage = detail::MakeHandshakeMessage(0x14, VerifyData);
        Result.Plaintext.insert(Result.Plaintext.end(), FinishedMessage.begin(), FinishedMessage.end());

        const auto [EncryptError, Record] = EncryptTlsRecord(
            Request.Keys.ServerHandshakeKey, Request.Keys.ServerHandshakeIv, 0, 0x16, Result.Plaintext);
        if (EncryptError != Preview::Error::None)
        {
            Result = {};
            return {EncryptError, Result};
        }
        Result.Record = Record;
        return {Preview::Error::None, std::move(Result)};
    }

} // namespace Preview::Reality::Response
