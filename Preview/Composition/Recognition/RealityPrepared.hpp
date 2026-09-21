/**
 * @file RealityPrepared.hpp
 * @brief recognition 提交阶段的 Reality 完整服务端握手。
 * @details ClientHello 已由 recognition 预读并消费后，这里继续完成
 *          SessionId 认证、TLS 1.3 服务端 flight、Finished 校验和 record stream 接管。
 */
#pragma once

#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Protocols/Reality/Carrier.hpp>
#include <Preview/Runtime/Recognition/Profile.hpp>

#include <openssl/curve25519.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace Preview::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;

    struct PreparedRealityRequest final
    {
        Preview::SharedTransmission Inbound;
        std::array<std::uint8_t, Preview::Reality::KeyLen> PrivateKey{};
        std::vector<std::array<std::uint8_t, Preview::Reality::MaxShortIdLen>> ShortIds;
        std::span<const std::uint8_t> Random;
        std::span<const std::uint8_t> SessionId;
        std::span<const std::uint8_t> X25519Key;
        std::span<const std::uint8_t> RawMessage;
    };

    [[nodiscard]] inline auto AcceptPreparedReality(PreparedRealityRequest Request)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "reality";
        auto Inbound = std::move(Request.Inbound);
        auto Reject = [&](const Preview::Error ErrorCode) -> Core::CarrierAcceptResult
        {
            Result.Code = ErrorCode == Preview::Error::None
                              ? Preview::Fault::Code::ProtocolError
                              : Preview::Fault::ToCode(Preview::make_error_code(ErrorCode));
            if (Inbound)
            {
                Inbound->Close();
            }
            return Result;
        };

        if (!Inbound || Request.Random.size() != 32 || Request.SessionId.size() !=
                              Preview::Reality::SessionIdAuthLen ||
            Request.X25519Key.size() != Preview::Reality::KeyLen || Request.RawMessage.empty() ||
            Request.ShortIds.empty())
        {
            co_return Reject(Preview::Error::BadMessage);
        }

        std::array<std::uint8_t, Preview::Reality::KeyLen> AuthShared{};
        if (Preview::Reality::X25519Shared(Request.PrivateKey, Request.X25519Key, AuthShared))
        {
            co_return Reject(Preview::Error::KdfError);
        }
        std::array<std::uint8_t, Preview::Reality::KeyLen> AuthKey{};
        if (Preview::Reality::DeriveAuthKey(AuthShared, Request.Random, AuthKey))
        {
            co_return Reject(Preview::Error::KdfError);
        }

        std::array<std::uint8_t, 16> SessionPlain{};
        if (Preview::Reality::OpenSessionId(
                Preview::Reality::SessionIdOpenInput{
                    AuthKey, Request.Random, Request.SessionId, Request.RawMessage},
                SessionPlain) ||
            SessionPlain[0] != 0x01)
        {
            co_return Reject(Preview::Error::BadAuth);
        }

        std::array<std::uint8_t, Preview::Reality::MaxShortIdLen> ShortId{};
        std::copy_n(SessionPlain.data() + 8, ShortId.size(), ShortId.data());
        if (std::find(Request.ShortIds.begin(), Request.ShortIds.end(), ShortId) ==
            Request.ShortIds.end())
        {
            co_return Reject(Preview::Error::BadAuth);
        }

        Preview::Reality::Detail::ClientHelloView Client;
        std::copy(Request.Random.begin(), Request.Random.end(), Client.Random.begin());
        std::copy(Request.SessionId.begin(), Request.SessionId.end(), Client.SessionId.begin());
        std::copy(Request.X25519Key.begin(), Request.X25519Key.end(), Client.PublicKey.begin());
        std::array<std::uint8_t, Preview::Reality::KeyLen> EphemeralPrivate{};
        if (RAND_bytes(EphemeralPrivate.data(), static_cast<int>(EphemeralPrivate.size())) != 1)
        {
            co_return Reject(Preview::Error::CryptoError);
        }
        std::array<std::uint8_t, Preview::Reality::KeyLen> EphemeralPublic{};
        X25519_public_from_private(EphemeralPublic.data(), EphemeralPrivate.data());
        auto [ServerHelloMessage, ServerHelloRecord] =
            Preview::Reality::Detail::BuildServerHello(Client, EphemeralPublic);

        std::array<std::uint8_t, Preview::Reality::KeyLen> TlsShared{};
        if (Preview::Reality::X25519Shared(EphemeralPrivate, Request.X25519Key, TlsShared))
        {
            co_return Reject(Preview::Error::KdfError);
        }
        auto [KeyError, Keys] = Preview::Reality::DeriveTls13Keys(
            TlsShared, Request.RawMessage, ServerHelloMessage);
        if (KeyError != Preview::Error::None)
        {
            co_return Reject(KeyError);
        }

        const auto [HandshakeError, Handshake] = Preview::Reality::Response::BuildServerHandshake(
            Preview::Reality::Response::HandshakeRequest{
                AuthKey, Keys, Request.RawMessage, ServerHelloMessage});
        if (HandshakeError != Preview::Error::None)
        {
            co_return Reject(HandshakeError);
        }

        const std::array<std::uint8_t, 6> ChangeCipherSpec{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        std::vector<std::uint8_t> Flight;
        Flight.reserve(ServerHelloRecord.size() + ChangeCipherSpec.size() + Handshake.Record.size());
        Flight.insert(Flight.end(), ServerHelloRecord.begin(), ServerHelloRecord.end());
        Flight.insert(Flight.end(), ChangeCipherSpec.begin(), ChangeCipherSpec.end());
        Flight.insert(Flight.end(), Handshake.Record.begin(), Handshake.Record.end());
        if (co_await Preview::Reality::Detail::WriteAll(
                Inbound, std::as_bytes(std::span<const std::uint8_t>(Flight))) !=
            Preview::Error::None)
        {
            co_return Reject(Preview::Error::IoError);
        }

        Preview::Reality::Detail::Bytes ClientFinishedRecord;
        Preview::Error FinishedReadError = Preview::Error::None;
        do
        {
            auto ReadResult = co_await Preview::Reality::Detail::ReadRecord(Inbound);
            FinishedReadError = ReadResult.first;
            ClientFinishedRecord = std::move(ReadResult.second);
            if (FinishedReadError != Preview::Error::None)
            {
                co_return Reject(FinishedReadError);
            }
        } while (!ClientFinishedRecord.empty() && ClientFinishedRecord[0] == 0x14);
        auto [FinishedDecryptError, ClientFinished] = Preview::Reality::DecryptTlsRecord(
            ClientFinishedRecord, Keys.ClientHandshakeKey, Keys.ClientHandshakeIv, 0);
        const auto TranscriptParts = std::array<std::span<const std::uint8_t>, 3>{
            Request.RawMessage, ServerHelloMessage, Handshake.Plaintext};
        const auto TranscriptHash = Preview::Reality::HashTranscript(TranscriptParts);
        const auto ExpectedFinished = Preview::Reality::ComputeFinished(
            Keys.ClientFinishedKey, TranscriptHash);
        if (FinishedDecryptError != Preview::Error::None || ClientFinished.ContentType != 0x16 ||
            ClientFinished.Data.size() != 4 + ExpectedFinished.size() ||
            ClientFinished.Data[0] != 0x14 || ClientFinished.Data[1] != 0x00 ||
            ClientFinished.Data[2] != 0x00 || ClientFinished.Data[3] != 0x20 ||
            !std::equal(ExpectedFinished.begin(), ExpectedFinished.end(),
                        ClientFinished.Data.begin() + 4))
        {
            co_return Reject(Preview::Error::BadAuth);
        }
        if (Preview::Reality::DeriveApplicationKeys(Keys.MasterSecret, TranscriptHash, Keys) !=
            Preview::Error::None)
        {
            co_return Reject(Preview::Error::KdfError);
        }

        Result.Transport = std::make_shared<Preview::Reality::Detail::TlsRecordStream>(
            std::move(Inbound), std::move(Keys));
        Result.Metadata.Carrier = "reality";
        co_return Result;
    }

} // namespace Preview::Composition::Recognition
