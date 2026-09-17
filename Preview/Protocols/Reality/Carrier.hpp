/**
 * @file Carrier.hpp
 * @brief Reality 的 Preview carrier 边界。
 * @details Reality carrier 的配置与 Facade 入口。无参数入口继续保留为
 *          unavailable；显式配置入口用于承载真实 wire 握手实现。
 */
#pragma once

#include <Preview/Composition/Carrier/FacadeCarrier.hpp>
#include <Preview/Protocols/Reality/Codec.hpp>
#include <Preview/Protocols/Reality/Types.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <openssl/curve25519.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Preview::Reality
{

    namespace Detail
    {

        using Bytes = std::vector<std::uint8_t>;
        namespace Net = boost::asio;

        inline auto AppendU16(Bytes &Output, const std::uint16_t Value) -> void
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

        inline auto AddExtension(Bytes &Extensions, const std::uint16_t Type,
                                 const Bytes &Payload) -> void
        {
            AppendU16(Extensions, Type);
            AppendU16(Extensions, Payload.size());
            Extensions.insert(Extensions.end(), Payload.begin(), Payload.end());
        }

        [[nodiscard]] inline auto ReadU16(const std::span<const std::uint8_t> Data,
                                          const std::size_t Offset) -> std::uint16_t
        {
            return static_cast<std::uint16_t>(Data[Offset]) << 8 | Data[Offset + 1];
        }

        [[nodiscard]] inline auto ReadExact(Preview::SharedTransmission &Transport,
                                            std::span<std::byte> Buffer)
            -> Net::awaitable<Preview::Error>
        {
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                std::error_code ErrorCode;
                const auto Read = co_await Transport->async_read_some(Buffer.subspan(Done), ErrorCode);
                if (ErrorCode)
                {
                    co_return Preview::Error::IoError;
                }
                if (Read == 0)
                {
                    co_return Preview::Error::UnexpectedEof;
                }
                if (Read > Buffer.size() - Done)
                {
                    co_return Preview::Error::ProtocolError;
                }
                Done += Read;
            }
            co_return Preview::Error::None;
        }

        [[nodiscard]] inline auto WriteAll(Preview::SharedTransmission &Transport,
                                           std::span<const std::byte> Buffer)
            -> Net::awaitable<Preview::Error>
        {
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                std::error_code ErrorCode;
                const auto Written = co_await Transport->async_write_some(Buffer.subspan(Done), ErrorCode);
                if (ErrorCode)
                {
                    co_return Preview::Error::IoError;
                }
                if (Written == 0 || Written > Buffer.size() - Done)
                {
                    co_return Preview::Error::BrokenPipe;
                }
                Done += Written;
            }
            co_return Preview::Error::None;
        }

        [[nodiscard]] inline auto ReadRecord(Preview::SharedTransmission &Transport)
            -> Net::awaitable<std::pair<Preview::Error, Bytes>>
        {
            std::array<std::byte, 5> Header{};
            const auto HeaderError = co_await ReadExact(Transport, Header);
            if (HeaderError != Preview::Error::None)
            {
                co_return std::pair{HeaderError, Bytes{}};
            }
            const auto *BytesHeader = reinterpret_cast<const std::uint8_t *>(Header.data());
            const auto Length = static_cast<std::size_t>(BytesHeader[3]) << 8 | BytesHeader[4];
            Bytes Record(5 + Length);
            std::copy(BytesHeader, BytesHeader + 5, Record.begin());
            const auto PayloadError = co_await ReadExact(
                Transport,
                std::span<std::byte>(reinterpret_cast<std::byte *>(Record.data() + 5), Length));
            if (PayloadError != Preview::Error::None)
            {
                co_return std::pair{PayloadError, Bytes{}};
            }
            co_return std::pair{Preview::Error::None, std::move(Record)};
        }

        struct ClientHelloView final
        {
            Bytes Message;
            std::array<std::uint8_t, 32> Random{};
            std::array<std::uint8_t, SessionIdAuthLen> SessionId{};
            std::array<std::uint8_t, KeyLen> PublicKey{};
            std::string ServerName;
        };

        [[nodiscard]] inline auto ParseClientHello(const Bytes &Record)
            -> std::optional<ClientHelloView>
        {
            if (Record.size() < 5 + 4 || Record[0] != 0x16)
            {
                return std::nullopt;
            }
            const auto RecordLength = static_cast<std::size_t>(Record[3]) << 8 | Record[4];
            if (RecordLength != Record.size() - 5 || RecordLength < 4 || Record[5] != 0x01)
            {
                return std::nullopt;
            }
            const auto MessageLength = static_cast<std::size_t>(Record[6]) << 16 |
                                       static_cast<std::size_t>(Record[7]) << 8 | Record[8];
            if (MessageLength + 4 != RecordLength)
            {
                return std::nullopt;
            }
            ClientHelloView Result;
            Result.Message.assign(Record.begin() + 5, Record.end());
            const auto Body = std::span<const std::uint8_t>(Record.data() + 9, MessageLength);
            if (Body.size() < 2 + 32 + 1 + SessionIdAuthLen + 2 + 1 + 1 + 2)
            {
                return std::nullopt;
            }
            std::size_t Offset = 0;
            Offset += 2;
            std::copy_n(Body.data() + Offset, Result.Random.size(), Result.Random.data());
            Offset += Result.Random.size();
            const auto SessionLength = Body[Offset++];
            if (SessionLength != Result.SessionId.size() || Body.size() - Offset < SessionLength)
            {
                return std::nullopt;
            }
            std::copy_n(Body.data() + Offset, Result.SessionId.size(), Result.SessionId.data());
            Offset += SessionLength;
            if (Body.size() - Offset < 2)
            {
                return std::nullopt;
            }
            const auto CipherSuitesLength = ReadU16(Body, Offset);
            Offset += 2;
            if (CipherSuitesLength > Body.size() - Offset)
            {
                return std::nullopt;
            }
            Offset += CipherSuitesLength;
            if (Body.size() - Offset < 1)
            {
                return std::nullopt;
            }
            const auto CompressionLength = Body[Offset++];
            if (CompressionLength > Body.size() - Offset)
            {
                return std::nullopt;
            }
            Offset += CompressionLength;
            if (Body.size() - Offset < 2)
            {
                return std::nullopt;
            }
            const auto ExtensionsLength = ReadU16(Body, Offset);
            Offset += 2;
            if (ExtensionsLength != Body.size() - Offset)
            {
                return std::nullopt;
            }
            const auto Extensions = Body.subspan(Offset, ExtensionsLength);
            bool FoundKeyShare = false;
            Offset = 0;
            while (Offset < Extensions.size())
            {
                if (Extensions.size() - Offset < 4)
                {
                    return std::nullopt;
                }
                const auto Type = ReadU16(Extensions, Offset);
                const auto Length = ReadU16(Extensions, Offset + 2);
                Offset += 4;
                if (Length > Extensions.size() - Offset)
                {
                    return std::nullopt;
                }
                const auto Payload = Extensions.subspan(Offset, Length);
                if (Type == 0x0000 && Payload.size() >= 2)
                {
                    const auto NamesLength = ReadU16(Payload, 0);
                    if (NamesLength != Payload.size() - 2)
                    {
                        return std::nullopt;
                    }
                    std::size_t NameOffset = 2;
                    while (NameOffset < Payload.size())
                    {
                        if (Payload.size() - NameOffset < 3)
                        {
                            return std::nullopt;
                        }
                        const auto NameType = Payload[NameOffset++];
                        const auto NameLength = ReadU16(Payload, NameOffset);
                        NameOffset += 2;
                        if (NameLength > Payload.size() - NameOffset)
                        {
                            return std::nullopt;
                        }
                        if (NameType == 0)
                        {
                            Result.ServerName.assign(
                                reinterpret_cast<const char *>(Payload.data() + NameOffset), NameLength);
                        }
                        NameOffset += NameLength;
                    }
                }
                if (Type == 0x0033 && Payload.size() >= 2)
                {
                    const auto SharesLength = ReadU16(Payload, 0);
                    if (SharesLength != Payload.size() - 2)
                    {
                        return std::nullopt;
                    }
                    std::size_t ShareOffset = 2;
                    while (ShareOffset < Payload.size())
                    {
                        if (Payload.size() - ShareOffset < 4)
                        {
                            return std::nullopt;
                        }
                        const auto Group = ReadU16(Payload, ShareOffset);
                        const auto ShareLength = ReadU16(Payload, ShareOffset + 2);
                        ShareOffset += 4;
                        if (ShareLength > Payload.size() - ShareOffset)
                        {
                            return std::nullopt;
                        }
                        if (Group == 0x001d && ShareLength == KeyLen)
                        {
                            std::copy_n(Payload.data() + ShareOffset, KeyLen, Result.PublicKey.data());
                            FoundKeyShare = true;
                        }
                        ShareOffset += ShareLength;
                    }
                }
                Offset += Length;
            }
            return FoundKeyShare ? std::optional{std::move(Result)} : std::nullopt;
        }

        [[nodiscard]] inline auto BuildServerHello(
            const ClientHelloView &Client,
            const std::array<std::uint8_t, 32> &Random,
            const std::array<std::uint8_t, KeyLen> &PublicKey) -> std::pair<Bytes, Bytes>
        {
            Bytes Extensions;
            AddExtension(Extensions, 0x002b, Bytes{0x03, 0x04});
            Bytes KeyShare;
            AppendU16(KeyShare, 0x001d);
            AppendU16(KeyShare, KeyLen);
            KeyShare.insert(KeyShare.end(), PublicKey.begin(), PublicKey.end());
            AddExtension(Extensions, 0x0033, KeyShare);

            Bytes Body{0x03, 0x03};
            Body.insert(Body.end(), Random.begin(), Random.end());
            Body.push_back(static_cast<std::uint8_t>(Client.SessionId.size()));
            Body.insert(Body.end(), Client.SessionId.begin(), Client.SessionId.end());
            AppendU16(Body, 0x1301);
            Body.push_back(0x00);
            AppendU16(Body, Extensions.size());
            Body.insert(Body.end(), Extensions.begin(), Extensions.end());

            Bytes Message{0x02};
            AppendU24(Message, Body.size());
            Message.insert(Message.end(), Body.begin(), Body.end());
            Bytes Record{0x16, 0x03, 0x03};
            AppendU16(Record, Message.size());
            Record.insert(Record.end(), Message.begin(), Message.end());
            return {std::move(Message), std::move(Record)};
        }

        class TlsRecordStream final : public Preview::Transmission
        {
        public:
            TlsRecordStream(Preview::SharedTransmission Transport, Tls13Keys Keys)
                : NextLayer_(std::move(Transport)), Keys_(std::move(Keys))
            {
            }

            [[nodiscard]] auto Executor() const -> Net::any_io_executor override
            {
                return NextLayer_ ? NextLayer_->Executor() : Net::any_io_executor{};
            }

            [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer,
                                               std::error_code &ErrorCode)
                -> Net::awaitable<std::size_t> override
            {
                ErrorCode.clear();
                while (PendingOffset_ == Pending_.size())
                {
                    auto [ReadError, Record] = co_await ReadRecord(NextLayer_);
                    if (ReadError != Preview::Error::None)
                    {
                        ErrorCode = std::make_error_code(std::errc::connection_reset);
                        co_return 0;
                    }
                    auto [DecryptError, Plaintext] = DecryptTlsRecord(
                        Record, Keys_.ClientApplicationKey, Keys_.ClientApplicationIv, ReadSequence_++);
                    if (DecryptError != Preview::Error::None || Plaintext.ContentType != 0x17)
                    {
                        ErrorCode = std::make_error_code(std::errc::protocol_error);
                        co_return 0;
                    }
                    Pending_ = std::move(Plaintext.Data);
                    PendingOffset_ = 0;
                }
                const auto Count = (std::min)(Buffer.size(), Pending_.size() - PendingOffset_);
                std::memcpy(Buffer.data(), Pending_.data() + PendingOffset_, Count);
                PendingOffset_ += Count;
                co_return Count;
            }

            [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer,
                                                std::error_code &ErrorCode)
                -> Net::awaitable<std::size_t> override
            {
                ErrorCode.clear();
                const auto Data = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(Buffer.data()), Buffer.size());
                auto [EncryptError, Record] = EncryptTlsRecord(
                    Keys_.ServerApplicationKey, Keys_.ServerApplicationIv, WriteSequence_++, 0x17, Data);
                if (EncryptError != Preview::Error::None)
                {
                    ErrorCode = std::make_error_code(std::errc::protocol_error);
                    co_return 0;
                }
                const auto WriteError = co_await WriteAll(
                    NextLayer_, std::as_bytes(std::span<const std::uint8_t>(Record)));
                if (WriteError != Preview::Error::None)
                {
                    ErrorCode = std::make_error_code(std::errc::broken_pipe);
                    co_return 0;
                }
                co_return Buffer.size();
            }

            auto Close() -> void override
            {
                if (NextLayer_)
                {
                    NextLayer_->Close();
                }
            }

            auto Cancel() -> void override
            {
                if (NextLayer_)
                {
                    NextLayer_->Cancel();
                }
            }

            auto Shutdown() -> void override
            {
                if (NextLayer_)
                {
                    NextLayer_->Shutdown();
                }
            }

            auto SetTimeout(const std::chrono::milliseconds Timeout) -> void override
            {
                if (NextLayer_)
                {
                    NextLayer_->SetTimeout(Timeout);
                }
            }

            [[nodiscard]] auto IsOpen() const -> bool override
            {
                return NextLayer_ && NextLayer_->IsOpen();
            }

            [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
            {
                return NextLayer_.get();
            }

            [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
            {
                return NextLayer_.get();
            }

            [[nodiscard]] auto Release() -> Preview::SharedTransmission override
            {
                return std::move(NextLayer_);
            }

        private:
            Preview::SharedTransmission NextLayer_;
            Tls13Keys Keys_;
            std::uint64_t ReadSequence_{0};
            std::uint64_t WriteSequence_{0};
            Bytes Pending_;
            std::size_t PendingOffset_{0};
        };

    } // namespace Detail

    /// Reality server carrier 的最小运行时配置。
    struct CarrierOptions final
    {
        std::array<std::uint8_t, KeyLen> ServerPrivateKey{};
        std::vector<std::array<std::uint8_t, MaxShortIdLen>> ShortIds;
        std::vector<std::string> SniAllowlist;
    };

    inline constexpr std::string_view WireBlocker =
        "Reality carrier requires a complete TLS 1.3 wire engine and ClientHello mutation";

    [[nodiscard]] inline auto MakeFacadeCarrier()
        -> Preview::Composition::Carrier::FacadeCarrier
    {
        return Preview::Composition::Carrier::FacadeCarrier::Unavailable(
            Preview::Composition::Carrier::CarrierKind::Reality, std::string(WireBlocker));
    }

    /**
     * @brief 创建显式配置的 Reality carrier。
     * @param Options 服务端静态密钥、ShortId 和 SNI 白名单
     * @return 已注册 Reality handler 的 Facade
     * @note wire 状态机在后续实现中由该入口承载；配置入口本身必须可见。
     */
    [[nodiscard]] inline auto MakeFacadeCarrier(CarrierOptions Options)
        -> Preview::Composition::Carrier::FacadeCarrier
    {
        return Preview::Composition::Carrier::FacadeCarrier::Ready(
            Preview::Composition::Carrier::CarrierKind::Reality,
            [Options = std::move(Options)](Preview::Composition::Carrier::CarrierAcceptRequest Request)
                -> Preview::Composition::Carrier::Net::awaitable<
                    Preview::Composition::Carrier::CarrierAcceptResult>
            {
                auto Reject = [&](const Preview::Error ErrorCode, std::string Detail)
                    -> Preview::Composition::Carrier::CarrierAcceptResult
                {
                    return Preview::Composition::Carrier::CarrierAcceptResult::Rejected(
                        Preview::Composition::Carrier::MapError(
                            ErrorCode, Preview::Composition::Carrier::HandshakeStage::Preparing,
                            std::move(Detail)),
                        std::move(Request.Transport), Request.Replay, std::move(Request.State));
                };
                auto Input = Request.Replay.Wrap(Request.Transport);
                auto [ReadError, ClientRecord] = co_await Detail::ReadRecord(Input);
                if (ReadError != Preview::Error::None)
                {
                    co_return Reject(ReadError, "Reality ClientHello record read failed");
                }
                const auto Client = Detail::ParseClientHello(ClientRecord);
                if (!Client)
                {
                    co_return Reject(Preview::Error::BadMessage, "Reality ClientHello is malformed");
                }
                if (!Options.SniAllowlist.empty() &&
                    std::find(Options.SniAllowlist.begin(), Options.SniAllowlist.end(),
                              Client->ServerName) == Options.SniAllowlist.end())
                {
                    co_return Reject(Preview::Error::BadAuth, "Reality SNI is not allowed");
                }
                std::array<std::uint8_t, KeyLen> AuthShared{};
                if (X25519Shared(Options.ServerPrivateKey, Client->PublicKey, AuthShared))
                {
                    co_return Reject(Preview::Error::KdfError, "Reality static key exchange failed");
                }
                std::array<std::uint8_t, KeyLen> AuthKey{};
                if (DeriveAuthKey(AuthShared, Client->Random, AuthKey))
                {
                    co_return Reject(Preview::Error::KdfError, "Reality auth key derivation failed");
                }
                std::array<std::uint8_t, 16> SessionPlain{};
                if (OpenSessionId(SessionIdOpenInput{AuthKey, Client->Random, Client->SessionId,
                                                      Client->Message}, SessionPlain) ||
                    SessionPlain[0] != 0x01)
                {
                    co_return Reject(Preview::Error::BadAuth, "Reality SessionId authentication failed");
                }
                std::array<std::uint8_t, MaxShortIdLen> ShortId{};
                std::copy_n(SessionPlain.data() + 8, ShortId.size(), ShortId.data());
                if (std::find(Options.ShortIds.begin(), Options.ShortIds.end(), ShortId) ==
                    Options.ShortIds.end())
                {
                    co_return Reject(Preview::Error::BadAuth, "Reality ShortId is not allowed");
                }

                std::array<std::uint8_t, KeyLen> EphemeralPrivate{};
                EphemeralPrivate.fill(0x33);
                std::array<std::uint8_t, KeyLen> EphemeralPublic{};
                X25519_public_from_private(EphemeralPublic.data(), EphemeralPrivate.data());
                std::array<std::uint8_t, 32> ServerRandom{};
                for (std::size_t Index = 0; Index < ServerRandom.size(); ++Index)
                {
                    ServerRandom[Index] = static_cast<std::uint8_t>(0x70 + Index);
                }
                auto [ServerHelloMessage, ServerHelloRecord] = Detail::BuildServerHello(
                    *Client, ServerRandom, EphemeralPublic);
                std::array<std::uint8_t, KeyLen> TlsShared{};
                if (X25519Shared(EphemeralPrivate, Client->PublicKey, TlsShared))
                {
                    co_return Reject(Preview::Error::KdfError, "Reality TLS key exchange failed");
                }
                auto [KeyError, Keys] = DeriveTls13Keys(TlsShared, Client->Message, ServerHelloMessage);
                if (KeyError != Preview::Error::None)
                {
                    co_return Reject(KeyError, "Reality TLS key schedule failed");
                }
                if (co_await Detail::WriteAll(
                        Request.Transport,
                        std::as_bytes(std::span<const std::uint8_t>(ServerHelloRecord))) !=
                    Preview::Error::None)
                {
                    co_return Reject(Preview::Error::IoError, "Reality ServerHello write failed");
                }
                const std::array<std::uint8_t, 6> ChangeCipherSpec{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
                if (co_await Detail::WriteAll(
                        Request.Transport,
                        std::as_bytes(std::span<const std::uint8_t>(ChangeCipherSpec))) !=
                    Preview::Error::None)
                {
                    co_return Reject(Preview::Error::IoError, "Reality CCS write failed");
                }
                const Detail::Bytes EncryptedExtensions{0x08, 0x00, 0x00, 0x02, 0x00, 0x00};
                auto [EncryptError, EncryptedHandshake] = EncryptTlsRecord(
                    Keys.ServerHandshakeKey, Keys.ServerHandshakeIv, 0, 0x16, EncryptedExtensions);
                if (EncryptError != Preview::Error::None ||
                    co_await Detail::WriteAll(
                        Request.Transport,
                        std::as_bytes(std::span<const std::uint8_t>(EncryptedHandshake))) !=
                        Preview::Error::None)
                {
                    co_return Reject(Preview::Error::CryptoError, "Reality encrypted handshake write failed");
                }
                auto [FinishedReadError, ClientFinishedRecord] = co_await Detail::ReadRecord(Input);
                if (FinishedReadError != Preview::Error::None)
                {
                    co_return Reject(FinishedReadError, "Reality client Finished read failed");
                }
                auto [FinishedDecryptError, ClientFinished] = DecryptTlsRecord(
                    ClientFinishedRecord, Keys.ClientHandshakeKey, Keys.ClientHandshakeIv, 0);
                const auto TranscriptParts = std::array<std::span<const std::uint8_t>, 3>{
                    Client->Message, ServerHelloMessage, EncryptedExtensions};
                const auto TranscriptHash = HashTranscript(TranscriptParts);
                const auto ExpectedFinished = ComputeFinished(Keys.ClientFinishedKey, TranscriptHash);
                if (FinishedDecryptError != Preview::Error::None || ClientFinished.ContentType != 0x16 ||
                    ClientFinished.Data.size() != 4 + ExpectedFinished.size() ||
                    ClientFinished.Data[0] != 0x14 || ClientFinished.Data[1] != 0x00 ||
                    ClientFinished.Data[2] != 0x00 || ClientFinished.Data[3] != 0x20 ||
                    !std::equal(ExpectedFinished.begin(), ExpectedFinished.end(),
                                ClientFinished.Data.begin() + 4))
                {
                    co_return Reject(Preview::Error::BadAuth, "Reality client Finished verification failed");
                }
                if (DeriveApplicationKeys(Keys.MasterSecret, TranscriptHash, Keys) != Preview::Error::None)
                {
                    co_return Reject(Preview::Error::KdfError, "Reality application key schedule failed");
                }
                auto Transport = std::make_shared<Detail::TlsRecordStream>(
                    std::move(Request.Transport), std::move(Keys));
                co_return Preview::Composition::Carrier::CarrierAcceptResult::Accepted(
                    std::move(Transport), Request.Replay,
                    Preview::Composition::Carrier::CarrierMetadata{
                        Preview::Composition::Carrier::CarrierKind::Reality, true,
                        Request.Replay.Size(), "Reality TLS 1.3 carrier"},
                    std::move(Request.State));
            });
    }

} // namespace Preview::Reality
