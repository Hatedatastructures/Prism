/**
 * @file RealityCarrierTest.cpp
 * @brief Reality BoringSSL carrier 最小配置入口 RED 测试。
 */

#include <Preview/Protocols/Reality/Prepared.hpp>
#include <Preview/Protocols/Reality/Detail/Key.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include "RealityCarrierTestSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <openssl/curve25519.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{

    namespace Net = boost::asio;
    namespace Test = Preview::Tests::Protocols::Reality;
    using Test::BuildClientHello;
    using Test::Bytes;
    using Test::ClientHelloKeyMaterial;
    using Test::ClientHelloWire;

    auto ReadExact(Preview::SharedTransmission &Transport, std::span<std::byte> Buffer)
        -> Net::awaitable<Preview::Error>
    {
        std::size_t Done = 0;
        while (Done < Buffer.size())
        {
            const auto Read = co_await Transport->ReadSome(Buffer.subspan(Done));
            if (Read.Failure.Failed())
            {
                co_return Preview::Error::IoError;
            }
            if (Read.Bytes == 0 || Read.Bytes > Buffer.size() - Done)
            {
                co_return Preview::Error::UnexpectedEof;
            }
            Done += Read.Bytes;
        }
        co_return Preview::Error::None;
    }

    auto WriteAll(Preview::SharedTransmission &Transport, std::span<const std::byte> Buffer)
        -> Net::awaitable<Preview::Error>
    {
        std::size_t Done = 0;
        while (Done < Buffer.size())
        {
            const auto Written = co_await Transport->WriteSome(Buffer.subspan(Done));
            if (Written.Failure.Failed())
            {
                co_return Preview::Error::IoError;
            }
            if (Written.Bytes == 0 || Written.Bytes > Buffer.size() - Done)
            {
                co_return Preview::Error::BrokenPipe;
            }
            Done += Written.Bytes;
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

    auto HasHandshakeMessage(const Bytes &Plaintext, const std::uint8_t Type) -> bool
    {
        std::size_t Offset = 0;
        while (Offset + 4 <= Plaintext.size())
        {
            const auto Length = static_cast<std::size_t>(Plaintext[Offset + 1]) << 16 |
                                  static_cast<std::size_t>(Plaintext[Offset + 2]) << 8 |
                                  Plaintext[Offset + 3];
            Offset += 4;
            if (Length > Plaintext.size() - Offset)
            {
                return false;
            }
            if (Plaintext[Offset - 4] == Type)
            {
                return true;
            }
            Offset += Length;
        }
        return false;
    }

    struct WireRunResult final
    {
        bool Completed{false};
        std::string Failure;
    };

    struct ClientHandshakeResult final
    {
        bool Ready{false};
        std::string Failure;
        Bytes ClientHello;
        Bytes ServerHello;
        Bytes ServerPlain;
        Preview::Reality::Detail::Tls13Keys Keys;
    };

    auto RunClientHandshake(
        Preview::SharedTransmission Transport,
        const ClientHelloWire &Hello)
        -> Net::awaitable<ClientHandshakeResult>
    {
        ClientHandshakeResult Result;
        Result.ClientHello = Hello.Message;
        const auto Fail = [&Result](const std::string_view Detail)
        {
            Result.Failure = std::string(Detail);
        };
        if (co_await WriteAll(Transport, std::as_bytes(std::span<const std::uint8_t>(Hello.Record))) !=
            Preview::Error::None)
        {
            Fail("client hello write failed");
            co_return Result;
        }

        auto [ServerHelloError, ServerHelloRecord] = co_await ReadRecord(Transport);
        if (ServerHelloError != Preview::Error::None)
        {
            Fail("server hello read failed");
            co_return Result;
        }
        const auto ServerHello = ParseServerHello(ServerHelloRecord, Hello.Message);
        if (!ServerHello)
        {
            Fail("server hello parse failed");
            co_return Result;
        }
        Result.ServerHello = ServerHello->Message;

        std::array<std::uint8_t, Preview::Reality::KeyLen> Shared{};
        if (Preview::Reality::Detail::X25519Shared(Hello.PrivateKey, ServerHello->PublicKey, Shared))
        {
            Fail("client tls key exchange failed");
            co_return Result;
        }
        auto KeyResult = Preview::Reality::Detail::DeriveTls13Keys(
            Preview::Reality::Detail::Tls13KeyScheduleInput{Shared, Hello.Message, ServerHello->Message});
        if (!KeyResult)
        {
            Fail("client tls key schedule failed");
            co_return Result;
        }
        const auto &Keys = *KeyResult;
        Result.Keys = Keys;

        auto [CcsError, CcsRecord] = co_await ReadRecord(Transport);
        if (CcsError != Preview::Error::None || CcsRecord.size() != 6 || CcsRecord[0] != 0x14 ||
            CcsRecord[5] != 0x01)
        {
            Fail("server ccs invalid");
            co_return Result;
        }
        auto [EncryptedError, EncryptedRecord] = co_await ReadRecord(Transport);
        if (EncryptedError != Preview::Error::None)
        {
            Fail("encrypted server handshake read failed");
            co_return Result;
        }
        auto [DecryptError, ServerPlain] = Preview::Reality::Detail::DecryptTlsRecord(
            Preview::Reality::Detail::Tls13RecordOpenInput{
                EncryptedRecord, Keys.ServerHandshakeKey,
                std::span<const std::uint8_t, 12>(Keys.ServerHandshakeIv), 0});
        if (DecryptError != Preview::Error::None || ServerPlain.ContentType != 0x16)
        {
            Fail("encrypted server handshake invalid");
            co_return Result;
        }
        if (!HasHandshakeMessage(ServerPlain.Data, 0x08) ||
            !HasHandshakeMessage(ServerPlain.Data, 0x0B) ||
            !HasHandshakeMessage(ServerPlain.Data, 0x0F) ||
            !HasHandshakeMessage(ServerPlain.Data, 0x14))
        {
            Fail("Reality server handshake is incomplete");
            co_return Result;
        }
        Result.ServerPlain = std::move(ServerPlain.Data);
        Result.Ready = true;
        co_return Result;
    }

    auto RunClientApplication(Preview::SharedTransmission Transport,
                              ClientHandshakeResult Handshake,
                              WireRunResult &Result) -> Net::awaitable<void>
    {
        const auto TranscriptParts = std::array<std::span<const std::uint8_t>, 3>{
            Handshake.ClientHello, Handshake.ServerHello, Handshake.ServerPlain};
        const auto TranscriptHash = Preview::Reality::Detail::HashTranscript(TranscriptParts);
        if (!TranscriptHash)
        {
            Result.Failure = "client transcript hash failed";
            co_return;
        }
        const auto ClientVerify = Preview::Reality::Detail::ComputeFinished(
            Handshake.Keys.ClientFinishedKey, *TranscriptHash);
        if (!ClientVerify)
        {
            Result.Failure = "client finished computation failed";
            co_return;
        }
        Bytes ClientFinished{0x14, 0x00, 0x00, 0x20};
        ClientFinished.insert(ClientFinished.end(), ClientVerify->begin(), ClientVerify->end());
        auto [FinishedError, FinishedRecord] = Preview::Reality::Detail::EncryptTlsRecord(
            Preview::Reality::Detail::Tls13RecordSealInput{
                Handshake.Keys.ClientHandshakeKey,
                std::span<const std::uint8_t, 12>(Handshake.Keys.ClientHandshakeIv),
                0, 0x16, ClientFinished});
        if (FinishedError != Preview::Error::None)
        {
            Result.Failure = "client finished encryption failed";
            co_return;
        }
        const std::array<std::uint8_t, 6> ClientChangeCipherSpec{
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        if (co_await WriteAll(
                Transport, std::as_bytes(std::span<const std::uint8_t>(ClientChangeCipherSpec))) !=
            Preview::Error::None)
        {
            Result.Failure = "client ccs write failed";
            co_return;
        }
        if (co_await WriteAll(Transport, std::as_bytes(std::span<const std::uint8_t>(FinishedRecord))) !=
            Preview::Error::None)
        {
            Result.Failure = "client finished write failed";
            co_return;
        }

        if (!Preview::Reality::Detail::DeriveApplicationKeys(Handshake.Keys.MasterSecret, *TranscriptHash, Handshake.Keys))
        {
            Result.Failure = "client application key schedule failed";
            co_return;
        }
        const Bytes ClientPayload{'c', 'l', 'i', 'e', 'n', 't', '-', 'i', 'n', 'n', 'e', 'r'};
        auto [ClientAppError, ClientAppRecord] = Preview::Reality::Detail::EncryptTlsRecord(
            Preview::Reality::Detail::Tls13RecordSealInput{
                Handshake.Keys.ClientApplicationKey,
                std::span<const std::uint8_t, 12>(Handshake.Keys.ClientApplicationIv),
                0, 0x17, ClientPayload});
        if (ClientAppError != Preview::Error::None ||
            co_await WriteAll(Transport, std::as_bytes(std::span<const std::uint8_t>(ClientAppRecord))) !=
                Preview::Error::None)
        {
            Result.Failure = "client application write failed";
            co_return;
        }

        auto [ServerAppReadError, ServerAppRecord] = co_await ReadRecord(Transport);
        if (ServerAppReadError != Preview::Error::None)
        {
            Result.Failure = "server application read failed";
            co_return;
        }
        auto [ServerAppDecryptError, ServerPlaintext] = Preview::Reality::Detail::DecryptTlsRecord(
            Preview::Reality::Detail::Tls13RecordOpenInput{
                ServerAppRecord, Handshake.Keys.ServerApplicationKey,
                std::span<const std::uint8_t, 12>(Handshake.Keys.ServerApplicationIv), 0});
        const Bytes Expected{'s', 'e', 'r', 'v', 'e', 'r', '-', 'i', 'n', 'n', 'e', 'r'};
        if (ServerAppDecryptError != Preview::Error::None || ServerPlaintext.ContentType != 0x17 ||
            ServerPlaintext.Data != Expected)
        {
            Result.Failure = "server application payload invalid";
            co_return;
        }
        Result.Completed = true;
    }

    struct ClientWireRequest final
    {
        Preview::SharedTransmission Transport;
        ClientHelloWire Hello;
        WireRunResult &Result;
    };

    auto RunClientWire(ClientWireRequest Request) -> Net::awaitable<void>
    {
        auto Handshake = co_await RunClientHandshake(
            Request.Transport, Request.Hello);
        if (!Handshake.Ready)
        {
            Request.Result.Failure = std::move(Handshake.Failure);
            Request.Transport->Close();
            co_return;
        }
        co_await RunClientApplication(Request.Transport, std::move(Handshake), Request.Result);
        Request.Transport->Close();
    }

    struct ServerWireRequest final
    {
        Preview::Reality::PreparedConfig Config;
        ClientHelloWire Hello;
        Preview::SharedTransmission Transport;
        WireRunResult &Result;
    };

    auto RunServerWire(ServerWireRequest Request) -> Net::awaitable<void>
    {
        auto [RecordError, Record] = co_await ReadRecord(Request.Transport);
        if (RecordError != Preview::Error::None || Record != Request.Hello.Record)
        {
            Request.Result.Failure = "prepared ClientHello snapshot did not match transport bytes";
            Request.Transport->Close();
            co_return;
        }
        auto Accepted = co_await Preview::Reality::AcceptPrepared(
            Preview::Reality::PreparedRequest{
                Request.Transport, std::move(Request.Config), Request.Hello.Random,
                Request.Hello.SessionId, Request.Hello.PublicKey, Request.Hello.Message,
                "example.com"});
        if (!Accepted)
        {
            Request.Result.Failure = "prepared carrier rejected wire handshake";
            Request.Transport->Close();
            co_return;
        }
        auto Stream = std::move(*Accepted);
        std::array<std::byte, 12> ClientPayload{};
        const auto Read = co_await Stream->ReadExact(ClientPayload);
        const auto Expected = std::array<std::byte, 12>{
            std::byte{'c'}, std::byte{'l'}, std::byte{'i'}, std::byte{'e'}, std::byte{'n'}, std::byte{'t'},
            std::byte{'-'}, std::byte{'i'}, std::byte{'n'}, std::byte{'n'}, std::byte{'e'}, std::byte{'r'}};
        if (Read.Bytes != Expected.size() || Read.Failure.Failed() || ClientPayload != Expected)
        {
            Request.Result.Failure = "carrier inner read failed";
            Stream->Close();
            co_return;
        }
        const auto Response = std::array<std::byte, 12>{
            std::byte{'s'}, std::byte{'e'}, std::byte{'r'}, std::byte{'v'}, std::byte{'e'}, std::byte{'r'},
            std::byte{'-'}, std::byte{'i'}, std::byte{'n'}, std::byte{'n'}, std::byte{'e'}, std::byte{'r'}};
        const auto Written = co_await Stream->WriteExact(Response);
        if (Written.Bytes != Response.size() || Written.Failure.Failed())
        {
            Request.Result.Failure = "carrier inner write failed";
            Stream->Close();
            co_return;
        }
        Stream->Close();
        Request.Result.Completed = true;
        co_return;
    }

    struct TlsReadResult final
    {
        std::size_t Read{0};
        Preview::Fault::Failure Failure;
    };

    /**
     * @brief 读取 TLS record stream 直到记录边界 EOF。
     * @details stream 按值进入 coroutine frame；缓冲区和错误值也由 frame
     *          持有，避免把临时 coroutine lambda 的 closure 当作 owner。
     */
    auto ReadTlsRecordAtEof(
        std::shared_ptr<Preview::Reality::Detail::TlsRecordStream> Stream)
        -> Net::awaitable<TlsReadResult>
    {
        std::array<std::byte, 1> Buffer{};
        const auto Read = co_await Stream->ReadSome(Buffer);
        co_return TlsReadResult{Read.Bytes, Read.Failure};
    }

    auto WriteShutdownAndRead(
        std::shared_ptr<Preview::MemoryStream> ClientTransport,
        std::shared_ptr<Preview::Reality::Detail::TlsRecordStream> Stream)
        -> Net::awaitable<TlsReadResult>
    {
        const auto Shutdown = co_await ClientTransport->WriteShutdown();
        if (!Shutdown)
        {
            co_return TlsReadResult{0, Shutdown.error()};
        }
        co_return co_await ReadTlsRecordAtEof(std::move(Stream));
    }

    /**
     * @brief 发送 TLS close_notify 后读取对端的清洁 EOF。
     * @details transport、stream 和告警记录按值进入 coroutine frame；测试
     *          完成回调只接收结果，不借用 coroutine closure 的捕获成员。
     */
    auto SendCloseNotifyAndRead(
        std::shared_ptr<Preview::MemoryStream> ClientTransport,
        std::shared_ptr<Preview::Reality::Detail::TlsRecordStream> Stream,
        Bytes AlertRecord) -> Net::awaitable<TlsReadResult>
    {
        const auto Write = co_await ClientTransport->WriteExact(
            std::as_bytes(std::span<const std::uint8_t>(AlertRecord)));
        if (Write.Failure.Failed())
        {
            co_return TlsReadResult{0, Write.Failure};
        }
        const auto Shutdown = co_await ClientTransport->WriteShutdown();
        if (!Shutdown)
        {
            co_return TlsReadResult{0, Shutdown.error()};
        }
        co_return co_await ReadTlsRecordAtEof(std::move(Stream));
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
            ClientHelloKeyMaterial{ServerPublicKey, ClientPrivateKey, Random}, ShortId, "example.com");
        ASSERT_FALSE(Hello.Message.empty());

        Preview::Reality::PreparedConfig Config{ServerPrivateKey, {ShortId}, {"example.com"}};

        WireRunResult ServerResult;
        WireRunResult ClientResult;
        std::exception_ptr Failure;
        Net::co_spawn(Context,
                      RunServerWire(ServerWireRequest{
                          std::move(Config), Hello, ServerTransport, ServerResult}),
                      [&](std::exception_ptr Error)
                      {
                          if (Error) Failure = std::move(Error);
                      });
        Net::co_spawn(Context,
                      RunClientWire(ClientWireRequest{ClientTransport, Hello, ClientResult}),
                      [&](std::exception_ptr Error)
                      {
                          if (Error) Failure = std::move(Error);
                      });
        Context.run();

        EXPECT_FALSE(Failure);
        EXPECT_TRUE(ServerResult.Completed) << ServerResult.Failure;
        EXPECT_TRUE(ClientResult.Completed) << ClientResult.Failure;
    }

    TEST(RealityCarrier, TlsRecordStreamReportsCleanEofAtRecordBoundary)
    {
        Net::io_context Context;
        auto [ServerStream, ClientStream] = Preview::MakeMemoryPair(Context.get_executor());
        auto ServerTransport = std::make_shared<Preview::MemoryStream>(std::move(ServerStream));
        auto ClientTransport = std::make_shared<Preview::MemoryStream>(std::move(ClientStream));
        auto Stream = std::make_shared<Preview::Reality::Detail::TlsRecordStream>(
            ServerTransport, Preview::Reality::Detail::Tls13Keys{});
        Preview::Fault::Failure ReadError;
        std::size_t Read = 0;
        std::exception_ptr Failure;
        Net::co_spawn(
            Context,
            WriteShutdownAndRead(ClientTransport, Stream),
            [&](std::exception_ptr Error, TlsReadResult Result)
            {
                Failure = std::move(Error);
                if (!Failure)
                {
                    Read = Result.Read;
                    ReadError = Result.Failure;
                }
            });
        Context.run();

        EXPECT_FALSE(Failure);
        EXPECT_EQ(Read, 0U);
        EXPECT_EQ(ReadError.Code, Preview::Fault::Code::Eof);
        EXPECT_FALSE(ReadError.Native);
    }

    TEST(RealityCarrier, TlsRecordStreamTreatsCloseNotifyAsCleanEof)
    {
        Net::io_context Context;
        auto [ServerStream, ClientStream] = Preview::MakeMemoryPair(Context.get_executor());
        auto ServerTransport = std::make_shared<Preview::MemoryStream>(std::move(ServerStream));
        auto ClientTransport = std::make_shared<Preview::MemoryStream>(std::move(ClientStream));

        Preview::Reality::Detail::Tls13Keys Keys;
        for (std::size_t Index = 0; Index < Keys.ClientApplicationKey.size(); ++Index)
        {
            Keys.ClientApplicationKey[Index] = static_cast<std::uint8_t>(Index + 1);
        }
        for (std::size_t Index = 0; Index < Keys.ClientApplicationIv.size(); ++Index)
        {
            Keys.ClientApplicationIv[Index] = static_cast<std::uint8_t>(0x20 + Index);
        }
        const auto [EncryptError, AlertRecord] = Preview::Reality::Detail::EncryptTlsRecord(
            Preview::Reality::Detail::Tls13RecordSealInput{
                Keys.ClientApplicationKey,
                std::span<const std::uint8_t, 12>(Keys.ClientApplicationIv),
                0, 0x15, {}});
        ASSERT_EQ(EncryptError, Preview::Error::None);

        auto Stream = std::make_shared<Preview::Reality::Detail::TlsRecordStream>(
            ServerTransport, Keys);
        Preview::Fault::Failure ReadError;
        std::size_t Read = 0;
        std::exception_ptr Failure;
        Net::co_spawn(
            Context,
            SendCloseNotifyAndRead(ClientTransport, Stream, AlertRecord),
            [&](std::exception_ptr Error, TlsReadResult Result)
            {
                Failure = std::move(Error);
                if (!Failure)
                {
                    Read = Result.Read;
                    ReadError = Result.Failure;
                }
            });
        Context.run();

        EXPECT_FALSE(Failure);
        EXPECT_EQ(Read, 0U);
        EXPECT_EQ(ReadError.Code, Preview::Fault::Code::Eof);
        EXPECT_FALSE(ReadError.Native);
    }

} // namespace
