/**
 * @file Handshake.hpp
 * @brief Reality TLS 1.3 服务端握手响应构造。
 * @details 生成 Mihomo Reality 所需的 Ed25519 伪证书、CertificateVerify、
 *          Server Finished 和加密握手记录。该职责独立于入站认证与数据面。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Reality/Types.hpp>
#include <Prism/Protocols/Reality/Detail/Key.hpp>
#include <Prism/Protocols/Reality/Detail/Hello.hpp>
#include <Prism/Protocols/Reality/Detail/Record.hpp>
#include <Prism/Protocols/Reality/Detail/Authentication.hpp>
#include <Prism/Protocols/Reality/Detail/Tls.hpp>

#include <boost/asio/awaitable.hpp>

#include <openssl/asn1.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

#include <algorithm>
#include <expected>
#include <exception>
#include <new>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Reality::Detail::Response
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

    namespace ResponseDetail
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
            const Crypto::SecretScope PrivateCleanup{Keypair.PrivateKey};
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

    } // namespace ResponseDetail

    /**
     * @brief 同步借用认证密钥、握手密钥和 transcript，返回拥有的服务端 flight。
     * @return 密码学失败保留完整 Failure；不执行取消、半关闭、连接关闭，无 executor 要求。
     */
    [[nodiscard]] inline auto BuildServerHandshake(const HandshakeRequest &Request)
        -> std::expected<HandshakeResult, Fault::Failure>
    {
        HandshakeResult Result;
        auto [CertificateDer, Keypair] = ResponseDetail::GenerateCertificate(Request.AuthKey);
        const Crypto::SecretScope KeyCleanup{Keypair.PrivateKey};
        if (CertificateDer.empty())
        {
            return std::unexpected(Fault::Failure{Fault::Code::CryptoError, {}});
        }

        const Bytes EncryptedExtensions = {0x08, 0x00, 0x00, 0x02, 0x00, 0x00};
        const auto EncryptedExtensionsMessage = ResponseDetail::MakeHandshakeMessage(
            0x08, std::span<const std::uint8_t>(EncryptedExtensions).subspan(4));
        const auto CertificateMessage = ResponseDetail::MakeHandshakeMessage(
            0x0B, ResponseDetail::BuildCertificateBody(CertificateDer));
        Result.Plaintext.insert(Result.Plaintext.end(), EncryptedExtensionsMessage.begin(),
                                EncryptedExtensionsMessage.end());
        Result.Plaintext.insert(Result.Plaintext.end(), CertificateMessage.begin(), CertificateMessage.end());

        const auto CertificateVerifyTranscript = std::array<std::span<const std::uint8_t>, 3>{
            Request.ClientHello, Request.ServerHello, Result.Plaintext};
        const auto CertificateVerifyHash = HashTranscript(CertificateVerifyTranscript);
        if (!CertificateVerifyHash)
        {
            return std::unexpected(CertificateVerifyHash.error());
        }
        const auto CertificateVerifyMessage = ResponseDetail::MakeHandshakeMessage(
            0x0F, ResponseDetail::BuildCertificateVerifyBody(Keypair, *CertificateVerifyHash));
        Result.Plaintext.insert(Result.Plaintext.end(), CertificateVerifyMessage.begin(),
                                CertificateVerifyMessage.end());

        const auto FinishedTranscript = std::array<std::span<const std::uint8_t>, 3>{
            Request.ClientHello, Request.ServerHello, Result.Plaintext};
        const auto FinishedHash = HashTranscript(FinishedTranscript);
        if (!FinishedHash)
        {
            return std::unexpected(FinishedHash.error());
        }
        auto VerifyData = ComputeFinished(Request.Keys.ServerFinishedKey, *FinishedHash);
        if (!VerifyData)
        {
            return std::unexpected(VerifyData.error());
        }
        const Crypto::SecretScope VerifyCleanup{*VerifyData};
        const auto FinishedMessage = ResponseDetail::MakeHandshakeMessage(0x14, *VerifyData);
        Result.Plaintext.insert(Result.Plaintext.end(), FinishedMessage.begin(), FinishedMessage.end());

        const auto [EncryptError, Record] = EncryptTlsRecord(
            Tls13RecordSealInput{Request.Keys.ServerHandshakeKey,
                                 std::span<const std::uint8_t, 12>(Request.Keys.ServerHandshakeIv),
                                 0, 0x16, Result.Plaintext});
        if (EncryptError != Prism::Error::None)
        {
            Result = {};
            return std::unexpected(Fault::Failure{Fault::Code::CryptoError, {}});
        }
        Result.Record = Record;
        return Result;
    }


} // namespace Prism::Reality::Detail::Response

namespace Prism::Reality::Detail
{
    namespace Net = boost::asio;

        struct ServerHandshake final
        {
            Bytes ServerHelloMessage;
            Bytes ServerHelloRecord;
            Tls13Keys Keys;
            Response::HandshakeResult Handshake;
        };

        [[nodiscard]] inline auto FailureFromError(const Prism::Error ErrorCode) noexcept
            -> Prism::Fault::Failure
        {
            if (ErrorCode == Prism::Error::None)
            {
                return {Prism::Fault::Code::ProtocolError};
            }
            return Prism::Fault::FromNative(Prism::make_error_code(ErrorCode));
        }

        /** @brief 生成 ServerHello、TLS handshake keys 和加密服务端 flight。 */
        [[nodiscard]] inline auto BuildServerHandshake(
            const PreparedRequest &Request,
            const AuthenticatedClient &Authenticated)
            -> std::expected<ServerHandshake, Prism::Fault::Failure>
        {
            std::array<std::uint8_t, KeyLen> EphemeralPrivate{};
            const Crypto::SecretScope EphemeralCleanup{EphemeralPrivate};
            if (RAND_bytes(EphemeralPrivate.data(), static_cast<int>(EphemeralPrivate.size())) != 1)
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::TlsHsfail});
            }
            std::array<std::uint8_t, KeyLen> EphemeralPublic{};
            X25519_public_from_private(EphemeralPublic.data(), EphemeralPrivate.data());
            auto [ServerHelloMessage, ServerHelloRecord] =
                BuildServerHello(Authenticated.Client, EphemeralPublic);

            std::array<std::uint8_t, KeyLen> TlsShared{};
            const Crypto::SecretScope SharedCleanup{TlsShared};
            if (X25519Shared(EphemeralPrivate, Request.X25519Key, TlsShared))
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Kexfail});
            }
            auto KeyResult = DeriveTls13Keys(
                Tls13KeyScheduleInput{TlsShared, Request.RawMessage, ServerHelloMessage});
            if (!KeyResult)
            {
                return std::unexpected(KeyResult.error());
            }

            auto &Keys = *KeyResult;
            const Crypto::SecretScope KeysCleanup{
                {reinterpret_cast<std::uint8_t *>(&Keys), sizeof(Keys)}};
            auto HandshakeResult =
                Response::BuildServerHandshake(
                    Response::HandshakeRequest{
                        Authenticated.AuthKey, Keys, Request.RawMessage, ServerHelloMessage});
            if (!HandshakeResult)
            {
                return std::unexpected(HandshakeResult.error());
            }

            auto &Handshake = *HandshakeResult;
            ServerHandshake Result;
            Result.ServerHelloMessage = std::move(ServerHelloMessage);
            Result.ServerHelloRecord = std::move(ServerHelloRecord);
            Result.Keys = std::move(Keys);
            Result.Handshake = std::move(Handshake);
            return Result;
        }

        /** @brief 写出 ServerHello/CCS/加密 handshake flight，保留 Inbound 的最终关闭权。 */
        [[nodiscard]] inline auto WriteServerFlight(
            Prism::SharedTransmission &Inbound,
            const ServerHandshake &Handshake) -> Net::awaitable<Prism::Fault::Failure>
        {
            const std::array<std::uint8_t, 6> ChangeCipherSpec{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
            Bytes Flight;
            Flight.reserve(Handshake.ServerHelloRecord.size() + ChangeCipherSpec.size() +
                           Handshake.Handshake.Record.size());
            Flight.insert(Flight.end(), Handshake.ServerHelloRecord.begin(),
                          Handshake.ServerHelloRecord.end());
            Flight.insert(Flight.end(), ChangeCipherSpec.begin(), ChangeCipherSpec.end());
            Flight.insert(Flight.end(), Handshake.Handshake.Record.begin(),
                          Handshake.Handshake.Record.end());
            const auto Written = co_await WriteAll(
                Inbound, std::as_bytes(std::span<const std::uint8_t>(Flight)));
            co_return Written.Failure;
        }

        /** @brief 消费 CCS/Finished，校验 transcript 后派生 application keys。 */
        [[nodiscard]] inline auto VerifyClientFinished(
            Prism::SharedTransmission &Inbound,
            std::span<const std::uint8_t> RawMessage,
            ServerHandshake &Handshake) -> Net::awaitable<Prism::Fault::Failure>
        {
            Bytes ClientFinishedRecord;
            do
            {
                auto ReadResult = co_await ReadRecord(Inbound);
                if (!ReadResult)
                {
                    co_return ReadResult.error();
                }
                ClientFinishedRecord = std::move(*ReadResult);
            } while (!ClientFinishedRecord.empty() && ClientFinishedRecord[0] == 0x14);

            auto [FinishedDecryptError, ClientFinished] = DecryptTlsRecord(
                Tls13RecordOpenInput{ClientFinishedRecord, Handshake.Keys.ClientHandshakeKey,
                                     std::span<const std::uint8_t, 12>(Handshake.Keys.ClientHandshakeIv), 0});
            const auto TranscriptParts = std::array<std::span<const std::uint8_t>, 3>{
                RawMessage, Handshake.ServerHelloMessage, Handshake.Handshake.Plaintext};
            const auto TranscriptHash = HashTranscript(TranscriptParts);
            if (!TranscriptHash)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::Kdferr};
            }
            auto ExpectedFinished = ComputeFinished(
                Handshake.Keys.ClientFinishedKey, *TranscriptHash);
            if (!ExpectedFinished)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::Kdferr};
            }
            const Crypto::SecretScope FinishedCleanup{*ExpectedFinished};
            if (FinishedDecryptError != Prism::Error::None || ClientFinished.ContentType != 0x16 ||
                ClientFinished.Data.size() != 4 + ExpectedFinished->size() ||
                ClientFinished.Data[0] != 0x14 || ClientFinished.Data[1] != 0x00 ||
                ClientFinished.Data[2] != 0x00 || ClientFinished.Data[3] != 0x20 ||
                !std::equal(ExpectedFinished->begin(), ExpectedFinished->end(),
                             ClientFinished.Data.begin() + 4))
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::Unauth};
            }
            if (!DeriveApplicationKeys(
                    Handshake.Keys.MasterSecret, *TranscriptHash, Handshake.Keys))
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::Kdferr};
            }
            co_return Prism::Fault::Failure{};
        }


} // namespace Prism::Reality::Detail
