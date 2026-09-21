/**
 * @file RestlsServerRelayTest.cpp
 * @brief Restls 服务端中间人 relay 的真实内存 wire 测试。
 */

#include <Preview/Protocols/Restls/Server.hpp>
#include <Preview/Transport/MemoryStream.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace
{

    namespace Net = boost::asio;
    namespace Restls = Preview::Restls;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    struct RelayState final
    {
        bool ClientSawServerHello{false};
        bool ClientSawProtectedFirst{false};
        bool ClientSentFinished{false};
        bool BackendSawClientHello{false};
        bool BackendSentServerHello{false};
        bool BackendSentFirst{false};
    };

    [[nodiscard]] auto MakeRecord(
        const std::uint8_t Type,
        std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Record(Restls::TlsHdrlen + Payload.size());
        Record[0] = Type;
        Record[1] = 0x03;
        Record[2] = 0x03;
        Record[3] = static_cast<std::uint8_t>(Payload.size() >> 8U);
        Record[4] = static_cast<std::uint8_t>(Payload.size());
        std::copy(Payload.begin(), Payload.end(), Record.begin() + Restls::TlsHdrlen);
        return Record;
    }

    [[nodiscard]] auto MakeServerHello(
        const std::array<std::uint8_t, 32> &Random) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Body{0x03, 0x03};
        Body.insert(Body.end(), Random.begin(), Random.end());
        Body.insert(Body.end(), {0x00, 0x13, 0x01, 0x00, 0x00, 0x00});
        std::vector<std::uint8_t> Message{0x02,
                                          static_cast<std::uint8_t>(Body.size() >> 16U),
                                          static_cast<std::uint8_t>(Body.size() >> 8U),
                                          static_cast<std::uint8_t>(Body.size())};
        Message.insert(Message.end(), Body.begin(), Body.end());
        return MakeRecord(0x16, Message);
    }

    [[nodiscard]] auto ReadExact(
        const Preview::SharedTransmission &Transport,
        std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            std::error_code ErrorCode;
            const auto Read = co_await Transport->async_read_some(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data() + Offset),
                                     Buffer.size() - Offset),
                ErrorCode);
            if (ErrorCode || Read == 0 || Read > Buffer.size() - Offset)
            {
                co_return false;
            }
            Offset += Read;
        }
        co_return true;
    }

    [[nodiscard]] auto ReadRecord(
        const Preview::SharedTransmission &Transport,
        std::vector<std::uint8_t> &Record) -> Net::awaitable<bool>
    {
        std::array<std::uint8_t, Restls::TlsHdrlen> Header{};
        if (!co_await ReadExact(Transport, Header))
        {
            co_return false;
        }
        const auto Length = (static_cast<std::size_t>(Header[3]) << 8U) | Header[4];
        Record.resize(Restls::TlsHdrlen + Length);
        std::copy(Header.begin(), Header.end(), Record.begin());
        co_return co_await ReadExact(
            Transport,
            std::span<std::uint8_t>(Record).subspan(Restls::TlsHdrlen));
    }

    [[nodiscard]] auto WriteAll(
        const Preview::SharedTransmission &Transport,
        std::span<const std::uint8_t> Buffer) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            std::error_code ErrorCode;
            const auto Written = co_await Transport->async_write_some(
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Buffer.data() + Offset),
                    Buffer.size() - Offset),
                ErrorCode);
            if (ErrorCode || Written == 0 || Written > Buffer.size() - Offset)
            {
                co_return false;
            }
            Offset += Written;
        }
        co_return true;
    }

    TEST(RestlsServerRelay, CompletesTlsFlightAndProtectsFirstEncryptedRecord)
    {
        Net::io_context Context;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context.get_executor());
        auto [BackendEndpoint, BackendServerEndpoint] = MakeMemoryPair(Context.get_executor());
        auto Client = std::make_shared<MemoryStream>(std::move(ClientEndpoint));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
        auto Backend = std::make_shared<MemoryStream>(std::move(BackendEndpoint));
        auto BackendServer = std::make_shared<MemoryStream>(std::move(BackendServerEndpoint));
        auto State = std::make_shared<RelayState>();

        std::array<std::uint8_t, 32> ServerRandom{};
        for (std::size_t Index = 0; Index < ServerRandom.size(); ++Index)
        {
            ServerRandom[Index] = static_cast<std::uint8_t>(0x40U + Index);
        }
        const std::vector<std::uint8_t> ClientHello =
            MakeRecord(0x16, std::array<std::uint8_t, 5>{0x01, 0x00, 0x00, 0x01, 0x00});
        const std::vector<std::uint8_t> ServerHello = MakeServerHello(ServerRandom);
        const std::vector<std::uint8_t> FirstEncrypted =
            MakeRecord(0x17, std::array<std::uint8_t, 16>{0xa0, 0xa1, 0xa2, 0xa3,
                                                          0xa4, 0xa5, 0xa6, 0xa7,
                                                          0xa8, 0xa9, 0xaa, 0xab,
                                                          0xac, 0xad, 0xae, 0xaf});
        const std::vector<std::uint8_t> ClientFinished =
            MakeRecord(0x17, std::array<std::uint8_t, 16>{0xb0, 0xb1, 0xb2, 0xb3,
                                                          0xb4, 0xb5, 0xb6, 0xb7,
                                                          0xb8, 0xb9, 0xba, 0xbb,
                                                          0xbc, 0xbd, 0xbe, 0xbf});
        const auto Password = std::string{"restls-relay-password"};
        const auto Secret = Restls::DeriveSecret(Password);

        Restls::ServerOptions Options;
        Options.DialTarget = [Backend](std::span<const std::uint8_t>)
            -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            co_return std::pair{Preview::Fault::Code::Success,
                                Preview::SharedTransmission{Backend}};
        };
        Restls::ServerSession Session(std::move(Options));
        Restls::ServerConfig Config{Password};
        std::optional<Restls::ServerResult> Result;

        Net::co_spawn(
            Context,
            [Client, ClientHello, ServerHello, FirstEncrypted, ClientFinished, State,
             ServerRandom, Secret]() -> Net::awaitable<void>
            {
                std::vector<std::uint8_t> Received;
                if (!co_await WriteAll(Client, ClientHello) ||
                    !co_await ReadRecord(Client, Received) || Received != ServerHello)
                {
                    co_return;
                }
                State->ClientSawServerHello = true;
                std::vector<std::uint8_t> Protected;
                if (!co_await ReadRecord(Client, Protected))
                {
                    co_return;
                }
                const auto Expected = Restls::ProtectFirstEncrypted(
                    FirstEncrypted, Secret, ServerRandom);
                State->ClientSawProtectedFirst =
                    Expected.first == Preview::Error::None && Protected == Expected.second;
                State->ClientSentFinished = co_await WriteAll(Client, ClientFinished);
            },
            Net::detached);

        Net::co_spawn(
            Context,
            [BackendServer, ClientHello, ServerHello, FirstEncrypted, ClientFinished,
             State]() -> Net::awaitable<void>
            {
                std::vector<std::uint8_t> Received;
                if (!co_await ReadRecord(BackendServer, Received) || Received != ClientHello)
                {
                    co_return;
                }
                State->BackendSawClientHello = true;
                State->BackendSentServerHello = co_await WriteAll(BackendServer, ServerHello);
                State->BackendSentFirst = co_await WriteAll(BackendServer, FirstEncrypted);
                std::vector<std::uint8_t> Finished;
                (void)co_await ReadRecord(BackendServer, Finished);
                (void)ClientFinished;
            },
            Net::detached);

        Net::co_spawn(
            Context,
            [&Session, Server, Config, &Result]() -> Net::awaitable<void>
            {
                Result = co_await Session.Run(Server, Config);
            },
            [&Context](std::exception_ptr Failure)
            {
                if (Failure)
                {
                    Context.stop();
                }
            });

        Context.run();

        ASSERT_TRUE(Result.has_value());
        ASSERT_EQ(Result->Status, Preview::Error::None);
        ASSERT_TRUE(Result->Connection);
        EXPECT_TRUE(State->ClientSawServerHello);
        EXPECT_TRUE(State->ClientSawProtectedFirst);
        EXPECT_TRUE(State->ClientSentFinished);
        EXPECT_TRUE(State->BackendSawClientHello);
        EXPECT_TRUE(State->BackendSentServerHello);
        EXPECT_TRUE(State->BackendSentFirst);

        const std::vector<std::uint8_t> RawPayload{
            'r', 'e', 's', 't', 'l', 's', '-', 'h', 'a', 'n', 'd', 'o', 'f', 'f'};
        const auto RawFrame = Restls::BuildFrame(Restls::FrameOptions{
            .Secret = Secret,
            .ServerRandom = ServerRandom,
            .Direction = Restls::FlowDirection::ToServer,
            .Counter = 0,
            .ClientFinished = ClientFinished,
            .Data = RawPayload,
            .PaddingLength = 0,
            .Command = Restls::CmdTypeNoop,
            .CommandArgument = 0});
        ASSERT_EQ(RawFrame.first, Preview::Error::None);
        const auto RawRecord = RawFrame.second;
        std::array<std::byte, 64> RawBuffer{};
        std::size_t RawRead = 0;
        std::error_code RawError;
        Context.restart();
        Net::co_spawn(
            Context,
            [Client, Connection = Result->Connection, RawRecord, &RawBuffer, &RawRead, &RawError]()
                -> Net::awaitable<void>
            {
                if (!co_await WriteAll(Client, RawRecord))
                {
                    RawError = std::make_error_code(std::errc::io_error);
                    co_return;
                }
                RawRead = co_await Connection->async_read_some(RawBuffer, RawError);
            },
            [&Context](std::exception_ptr Failure)
            {
                if (Failure)
                {
                    Context.stop();
                }
            });
        Context.run();

        EXPECT_FALSE(RawError);
        EXPECT_EQ(RawRead, RawPayload.size());
        EXPECT_EQ(std::vector<std::uint8_t>(
                      reinterpret_cast<const std::uint8_t *>(RawBuffer.data()),
                      reinterpret_cast<const std::uint8_t *>(RawBuffer.data()) + RawRead),
                  RawPayload);
    }

} // namespace
