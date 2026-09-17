/**
 * @file RealityCarrierTest.cpp
 * @brief Reality BoringSSL carrier 最小配置入口 RED 测试。
 */

#include <Preview/Protocols/Reality/Carrier.hpp>
#include <Preview/Protocols/Reality/Codec.hpp>
#include <Preview/Transport/MemoryStream.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/detached.hpp>

#include <openssl/curve25519.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{

    namespace Carrier = Preview::Composition::Carrier;
    namespace Net = boost::asio;

    using Bytes = std::vector<std::uint8_t>;

    auto AppendU16(Bytes &Output, const std::uint16_t Value) -> void
    {
        Output.push_back(static_cast<std::uint8_t>(Value >> 8));
        Output.push_back(static_cast<std::uint8_t>(Value));
    }

    auto AppendU24(Bytes &Output, const std::size_t Value) -> void
    {
        Output.push_back(static_cast<std::uint8_t>(Value >> 16));
        Output.push_back(static_cast<std::uint8_t>(Value >> 8));
        Output.push_back(static_cast<std::uint8_t>(Value));
    }

    auto AddExtension(Bytes &Extensions, const std::uint16_t Type, const Bytes &Payload) -> void
    {
        AppendU16(Extensions, Type);
        AppendU16(Extensions, static_cast<std::uint16_t>(Payload.size()));
        Extensions.insert(Extensions.end(), Payload.begin(), Payload.end());
    }

    struct ClientHelloWire final
    {
        Bytes Message;
        Bytes Record;
        std::array<std::uint8_t, Preview::Reality::KeyLen> PrivateKey{};
    };

    auto BuildClientHello(const std::array<std::uint8_t, Preview::Reality::KeyLen> &ServerPublicKey,
                          const std::array<std::uint8_t, Preview::Reality::KeyLen> &ClientPrivateKey,
                          const std::array<std::uint8_t, 32> &Random,
                          const std::array<std::uint8_t, Preview::Reality::MaxShortIdLen> &ShortId,
                          const std::string_view ServerName) -> ClientHelloWire
    {
        std::array<std::uint8_t, Preview::Reality::KeyLen> ClientPublicKey{};
        X25519_public_from_private(ClientPublicKey.data(), ClientPrivateKey.data());

        std::array<std::uint8_t, Preview::Reality::KeyLen> Shared{};
        if (Preview::Reality::X25519Shared(ClientPrivateKey, ServerPublicKey, Shared))
        {
            return {};
        }

        std::array<std::uint8_t, Preview::Reality::KeyLen> AuthKey{};
        if (Preview::Reality::DeriveAuthKey(Shared, Random, AuthKey))
        {
            return {};
        }

        Bytes Extensions;
        Bytes Name;
        Name.push_back(0);
        AppendU16(Name, static_cast<std::uint16_t>(ServerName.size()));
        Name.insert(Name.end(), ServerName.begin(), ServerName.end());
        Bytes Names;
        AppendU16(Names, static_cast<std::uint16_t>(Name.size()));
        Names.insert(Names.end(), Name.begin(), Name.end());
        AddExtension(Extensions, 0x0000, Names);
        AddExtension(Extensions, 0x002b, Bytes{0x02, 0x03, 0x04});
        AddExtension(Extensions, 0x000a, Bytes{0x00, 0x02, 0x00, 0x1d});

        Bytes KeyShare;
        AppendU16(KeyShare, 0x0024);
        AppendU16(KeyShare, 0x001d);
        AppendU16(KeyShare, Preview::Reality::KeyLen);
        KeyShare.insert(KeyShare.end(), ClientPublicKey.begin(), ClientPublicKey.end());
        AddExtension(Extensions, 0x0033, KeyShare);
        AddExtension(Extensions, 0x000d, Bytes{0x00, 0x02, 0x08, 0x07});

        Bytes Body;
        AppendU16(Body, 0x0303);
        Body.insert(Body.end(), Random.begin(), Random.end());
        Body.push_back(static_cast<std::uint8_t>(Preview::Reality::SessionIdAuthLen));
        Body.insert(Body.end(), Preview::Reality::SessionIdAuthLen, 0);
        AppendU16(Body, 0x0002);
        AppendU16(Body, 0x1301);
        Body.push_back(0x01);
        Body.push_back(0x00);
        AppendU16(Body, static_cast<std::uint16_t>(Extensions.size()));
        Body.insert(Body.end(), Extensions.begin(), Extensions.end());

        Bytes Message{0x01};
        AppendU24(Message, Body.size());
        Message.insert(Message.end(), Body.begin(), Body.end());

        std::array<std::uint8_t, 16> Plain{};
        Plain[0] = 0x01;
        std::copy(ShortId.begin(), ShortId.end(), Plain.begin() + 8);
        std::array<std::uint8_t, Preview::Reality::SessionIdAuthLen> Sealed{};
        if (Preview::Reality::SealSessionId(
                Preview::Reality::SessionIdSealInput{AuthKey, Random, Plain, Message}, Sealed))
        {
            return {};
        }
        std::copy(Sealed.begin(), Sealed.end(), Message.begin() + 39);

        ClientHelloWire Result;
        Result.Message = Message;
        Result.Record = {0x16, 0x03, 0x03,
                         static_cast<std::uint8_t>(Message.size() >> 8),
                         static_cast<std::uint8_t>(Message.size())};
        Result.Record.insert(Result.Record.end(), Message.begin(), Message.end());
        Result.PrivateKey = ClientPrivateKey;
        return Result;
    }

    auto ReadExact(Preview::SharedTransmission &Transport, std::span<std::byte> Buffer)
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
            if (Read == 0 || Read > Buffer.size() - Done)
            {
                co_return Preview::Error::UnexpectedEof;
            }
            Done += Read;
        }
        co_return Preview::Error::None;
    }

    auto WriteAll(Preview::SharedTransmission &Transport, std::span<const std::byte> Buffer)
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

    auto ReadRecord(Preview::SharedTransmission &Transport)
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
            Transport, std::span<std::byte>(reinterpret_cast<std::byte *>(Record.data() + 5), Length));
        if (PayloadError != Preview::Error::None)
        {
            co_return std::pair{PayloadError, Bytes{}};
        }
        co_return std::pair{Preview::Error::None, std::move(Record)};
    }

    struct ServerHelloView final
    {
        Bytes Message;
        std::array<std::uint8_t, 32> Random{};
        std::array<std::uint8_t, Preview::Reality::KeyLen> PublicKey{};
    };

    auto ParseServerHello(const Bytes &Record, const Bytes &ClientHello) -> std::optional<ServerHelloView>
    {
        if (Record.size() < 5 + 4 || Record[0] != 0x16 || Record[5] != 0x02)
        {
            return std::nullopt;
        }
        const auto MessageLength = static_cast<std::size_t>(Record[6]) << 16 |
                                   static_cast<std::size_t>(Record[7]) << 8 | Record[8];
        if (MessageLength + 9 != Record.size())
        {
            return std::nullopt;
        }
        const auto Body = std::span<const std::uint8_t>(Record.data() + 9, MessageLength);
        if (Body.size() < 2 + 32 + 1 + Preview::Reality::SessionIdAuthLen + 3)
        {
            return std::nullopt;
        }
        ServerHelloView Result;
        Result.Message.assign(Record.begin() + 5, Record.end());
        std::copy_n(Body.data() + 2, Result.Random.size(), Result.Random.data());
        const auto SessionLength = Body[34];
        if (SessionLength != Preview::Reality::SessionIdAuthLen ||
            ClientHello.size() < 39 + SessionLength || Body.size() < 35 + SessionLength + 3)
        {
            return std::nullopt;
        }
        if (!std::equal(Body.begin() + 35, Body.begin() + 35 + SessionLength,
                        ClientHello.begin() + 39))
        {
            return std::nullopt;
        }
        const auto ExtensionsLength = static_cast<std::size_t>(Body[38 + SessionLength]) << 8 |
                                       Body[39 + SessionLength];
        const auto ExtensionsBegin = Body.begin() + 40 + SessionLength;
        if (ExtensionsLength != static_cast<std::size_t>(Body.end() - ExtensionsBegin))
        {
            return std::nullopt;
        }
        auto Offset = std::size_t{0};
        const auto Extensions = std::span<const std::uint8_t>(
            &*ExtensionsBegin, ExtensionsLength);
        bool FoundVersion = false;
        bool FoundKeyShare = false;
        while (Offset < Extensions.size())
        {
            if (Extensions.size() - Offset < 4)
            {
                return std::nullopt;
            }
            const auto Type = static_cast<std::uint16_t>(Extensions[Offset]) << 8 | Extensions[Offset + 1];
            const auto Length = static_cast<std::size_t>(Extensions[Offset + 2]) << 8 |
                                Extensions[Offset + 3];
            Offset += 4;
            if (Length > Extensions.size() - Offset)
            {
                return std::nullopt;
            }
            const auto Payload = Extensions.subspan(Offset, Length);
            if (Type == 0x002b && Payload.size() == 2 && Payload[0] == 0x03 && Payload[1] == 0x04)
            {
                FoundVersion = true;
            }
            if (Type == 0x0033 && Payload.size() == 36 && Payload[0] == 0x00 && Payload[1] == 0x1d &&
                Payload[2] == 0x00 && Payload[3] == 0x20)
            {
                std::copy_n(Payload.data() + 4, Result.PublicKey.size(), Result.PublicKey.data());
                FoundKeyShare = true;
            }
            Offset += Length;
        }
        return FoundVersion && FoundKeyShare ? std::optional{std::move(Result)} : std::nullopt;
    }

    struct WireRunResult final
    {
        bool Completed{false};
        std::string Failure;
    };

    auto RunClientWire(Preview::SharedTransmission Transport,
                       ClientHelloWire Hello,
                       std::array<std::uint8_t, Preview::Reality::KeyLen> ServerPublicKey,
                       WireRunResult &Result) -> Net::awaitable<void>
    {
        auto Fail = [&Result](const std::string_view Detail) -> bool
        {
            Result.Failure = std::string(Detail);
            return false;
        };
        if (co_await WriteAll(Transport, std::as_bytes(std::span<const std::uint8_t>(Hello.Record))) !=
            Preview::Error::None)
        {
            Fail("client hello write failed");
            co_return;
        }

        auto [ServerHelloError, ServerHelloRecord] = co_await ReadRecord(Transport);
        if (ServerHelloError != Preview::Error::None)
        {
            Fail("server hello read failed");
            co_return;
        }
        const auto ServerHello = ParseServerHello(ServerHelloRecord, Hello.Message);
        if (!ServerHello)
        {
            Fail("server hello parse failed");
            co_return;
        }

        std::array<std::uint8_t, Preview::Reality::KeyLen> Shared{};
        if (Preview::Reality::X25519Shared(Hello.PrivateKey, ServerHello->PublicKey, Shared))
        {
            Fail("client tls key exchange failed");
            co_return;
        }
        auto [KeyError, Keys] = Preview::Reality::DeriveTls13Keys(
            Shared, Hello.Message, ServerHello->Message);
        if (KeyError != Preview::Error::None)
        {
            Fail("client tls key schedule failed");
            co_return;
        }

        auto [CcsError, CcsRecord] = co_await ReadRecord(Transport);
        if (CcsError != Preview::Error::None || CcsRecord.size() != 6 || CcsRecord[0] != 0x14 ||
            CcsRecord[5] != 0x01)
        {
            Fail("server ccs invalid");
            co_return;
        }
        auto [EncryptedError, EncryptedRecord] = co_await ReadRecord(Transport);
        if (EncryptedError != Preview::Error::None)
        {
            Fail("encrypted server handshake read failed");
            co_return;
        }
        auto [DecryptError, ServerPlain] = Preview::Reality::DecryptTlsRecord(
            EncryptedRecord, Keys.ServerHandshakeKey, Keys.ServerHandshakeIv, 0);
        if (DecryptError != Preview::Error::None || ServerPlain.ContentType != 0x16)
        {
            Fail("encrypted server handshake invalid");
            co_return;
        }

        const auto TranscriptParts = std::array<std::span<const std::uint8_t>, 3>{
            Hello.Message, ServerHello->Message, ServerPlain.Data};
        const auto TranscriptHash = Preview::Reality::HashTranscript(TranscriptParts);
        const auto ClientVerify = Preview::Reality::ComputeFinished(
            Keys.ClientFinishedKey, TranscriptHash);
        Bytes ClientFinished{0x14, 0x00, 0x00, 0x20};
        ClientFinished.insert(ClientFinished.end(), ClientVerify.begin(), ClientVerify.end());
        auto [FinishedError, FinishedRecord] = Preview::Reality::EncryptTlsRecord(
            Keys.ClientHandshakeKey, Keys.ClientHandshakeIv, 0, 0x16, ClientFinished);
        if (FinishedError != Preview::Error::None)
        {
            Fail("client finished encryption failed");
            co_return;
        }
        if (co_await WriteAll(Transport, std::as_bytes(std::span<const std::uint8_t>(FinishedRecord))) !=
            Preview::Error::None)
        {
            Fail("client finished write failed");
            co_return;
        }

        if (Preview::Reality::DeriveApplicationKeys(Keys.MasterSecret, TranscriptHash, Keys) !=
            Preview::Error::None)
        {
            Fail("client application key schedule failed");
            co_return;
        }
        const Bytes ClientPayload{'c', 'l', 'i', 'e', 'n', 't', '-', 'i', 'n', 'n', 'e', 'r'};
        auto [ClientAppError, ClientAppRecord] = Preview::Reality::EncryptTlsRecord(
            Keys.ClientApplicationKey, Keys.ClientApplicationIv, 0, 0x17, ClientPayload);
        if (ClientAppError != Preview::Error::None ||
            co_await WriteAll(Transport, std::as_bytes(std::span<const std::uint8_t>(ClientAppRecord))) !=
                Preview::Error::None)
        {
            Fail("client application write failed");
            co_return;
        }

        auto [ServerAppReadError, ServerAppRecord] = co_await ReadRecord(Transport);
        if (ServerAppReadError != Preview::Error::None)
        {
            Fail("server application read failed");
            co_return;
        }
        auto [ServerAppDecryptError, ServerPlaintext] = Preview::Reality::DecryptTlsRecord(
            ServerAppRecord, Keys.ServerApplicationKey, Keys.ServerApplicationIv, 0);
        const Bytes Expected{'s', 'e', 'r', 'v', 'e', 'r', '-', 'i', 'n', 'n', 'e', 'r'};
        if (ServerAppDecryptError != Preview::Error::None || ServerPlaintext.ContentType != 0x17 ||
            ServerPlaintext.Data != Expected)
        {
            Fail("server application payload invalid");
            co_return;
        }
        Result.Completed = true;
        co_return;
    }

    auto RunServerWire(Carrier::FacadeCarrier &Facade,
                       Preview::SharedTransmission Transport,
                       WireRunResult &Result) -> Net::awaitable<void>
    {
        auto Accepted = co_await Facade.Accept(Carrier::CarrierAcceptRequest{Transport, {}, {}});
        if (!Accepted.Accepted())
        {
            Result.Failure = "carrier rejected wire handshake";
            co_return;
        }
        std::array<std::byte, 12> ClientPayload{};
        std::error_code ReadError;
        const auto Read = co_await Accepted.Transport->AsyncRead(ClientPayload, ReadError);
        const auto Expected = std::array<std::byte, 12>{
            std::byte{'c'}, std::byte{'l'}, std::byte{'i'}, std::byte{'e'}, std::byte{'n'}, std::byte{'t'},
            std::byte{'-'}, std::byte{'i'}, std::byte{'n'}, std::byte{'n'}, std::byte{'e'}, std::byte{'r'}};
        if (Read != Expected.size() || ReadError || ClientPayload != Expected)
        {
            Result.Failure = "carrier inner read failed";
            co_return;
        }
        const auto Response = std::array<std::byte, 12>{
            std::byte{'s'}, std::byte{'e'}, std::byte{'r'}, std::byte{'v'}, std::byte{'e'}, std::byte{'r'},
            std::byte{'-'}, std::byte{'i'}, std::byte{'n'}, std::byte{'n'}, std::byte{'e'}, std::byte{'r'}};
        std::error_code WriteError;
        const auto Written = co_await Accepted.Transport->AsyncWrite(Response, WriteError);
        if (Written != Response.size() || WriteError)
        {
            Result.Failure = "carrier inner write failed";
            co_return;
        }
        Accepted.Transport->Close();
        Result.Completed = true;
        co_return;
    }

    TEST(RealityCarrier, ConfiguredProfileIsWireReady)
    {
        Preview::Reality::CarrierOptions Options;
        Options.ServerPrivateKey.fill(0x11);
        Options.ShortIds.push_back(std::array<std::uint8_t, Preview::Reality::MaxShortIdLen>{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
        Options.SniAllowlist.emplace_back("example.com");

        const auto Carrier = Preview::Reality::MakeFacadeCarrier(std::move(Options));
        EXPECT_TRUE(Carrier.WireReady());
    }

    TEST(RealityCarrier, CompletesTls13WireHandshakeAndInnerTransport)
    {
        Net::io_context Context;
        auto [ServerStream, ClientStream] = Preview::MakeMemoryPair(Context.get_executor());
        auto ServerTransport = std::make_shared<Preview::MemoryStream>(std::move(ServerStream));
        auto ClientTransport = std::make_shared<Preview::MemoryStream>(std::move(ClientStream));

        std::array<std::uint8_t, Preview::Reality::KeyLen> ServerPrivateKey{};
        std::array<std::uint8_t, Preview::Reality::KeyLen> ServerPublicKey{};
        std::array<std::uint8_t, Preview::Reality::KeyLen> ClientPrivateKey{};
        ServerPrivateKey.fill(0x11);
        ClientPrivateKey.fill(0x22);
        X25519_public_from_private(ServerPublicKey.data(), ServerPrivateKey.data());

        const std::array<std::uint8_t, Preview::Reality::MaxShortIdLen> ShortId{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        std::array<std::uint8_t, 32> Random{};
        for (std::size_t Index = 0; Index < Random.size(); ++Index)
        {
            Random[Index] = static_cast<std::uint8_t>(0x30 + Index);
        }
        const auto Hello = BuildClientHello(
            ServerPublicKey, ClientPrivateKey, Random, ShortId, "example.com");
        ASSERT_FALSE(Hello.Message.empty());

        Preview::Reality::CarrierOptions Options;
        Options.ServerPrivateKey = ServerPrivateKey;
        Options.ShortIds.push_back(ShortId);
        Options.SniAllowlist.emplace_back("example.com");
        auto Facade = Preview::Reality::MakeFacadeCarrier(std::move(Options));

        WireRunResult ServerResult;
        WireRunResult ClientResult;
        std::exception_ptr Failure;
        int Completed = 0;
        const auto Finish = [&](std::exception_ptr Error)
        {
            if (Error)
            {
                Failure = std::move(Error);
            }
            ++Completed;
            if (Completed == 2)
            {
                Context.stop();
            }
        };
        Net::co_spawn(Context,
                      RunServerWire(Facade, ServerTransport, ServerResult),
                      Finish);
        Net::co_spawn(Context,
                      RunClientWire(ClientTransport, Hello, ServerPublicKey, ClientResult),
                      Finish);
        Context.run();

        EXPECT_FALSE(Failure);
        EXPECT_TRUE(ServerResult.Completed) << ServerResult.Failure;
        EXPECT_TRUE(ClientResult.Completed) << ClientResult.Failure;
    }

} // namespace
