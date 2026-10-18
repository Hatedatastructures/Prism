/**
 * @file RestlsServerRelayTest.cpp
 * @brief Restls 服务端中间人 relay 的真实内存 wire 测试。
 */

#include <Prism/Protocols/Restls/Detail/Control.hpp>
#include <Prism/Protocols/Restls/Detail/Session.hpp>
#include <Prism/Protocols/Restls/Server.hpp>
#include <Prism/Protocols/Restls/Types.hpp>
#include <Prism/Protocols/Restls/Detail/Io.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{

    namespace Net = boost::asio;
    namespace Restls = Prism::Restls;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;

    auto RetireAndVerify(Prism::SharedTransmission Transport) -> Net::awaitable<void>
    {
        const auto Retired = co_await Restls::Detail::TransportRetirement::RetireAndDrain(
            std::move(Transport));
        EXPECT_TRUE(Retired);
    }

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct CompletionState final
    {
        explicit CompletionState(Net::any_io_executor Executor) : Done(std::move(Executor), 1) {}

        CompletionChannel Done;
        std::exception_ptr Failure;
    };

    auto RecordCompletion(const std::shared_ptr<CompletionState> &State,
                          std::exception_ptr Failure) -> void
    {
        if (Failure && !State->Failure)
        {
            State->Failure = Failure;
        }
        (void)State->Done.try_send(boost::system::error_code{});
    }

    auto AwaitCompletion(const std::shared_ptr<CompletionState> &State) -> Net::awaitable<void>
    {
        co_await State->Done.async_receive(Net::use_awaitable);
        if (State->Failure)
        {
            std::rethrow_exception(State->Failure);
        }
    }

    auto RunCoro(Net::io_context &Context, Net::awaitable<void> Operation) -> void
    {
        Context.restart();
        std::exception_ptr Failure;
        Net::co_spawn(Context, std::move(Operation),
                      [&Failure](std::exception_ptr Error) { Failure = Error; });
        Context.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    struct RelayState final
    {
        bool ClientSawServerHello{false};
        bool ClientSawProtectedFirst{false};
        bool ClientSentFinished{false};
        bool BackendSawClientHello{false};
        bool BackendSentServerHello{false};
        bool BackendSentFirst{false};
        bool BackendSawClientFinished{false};
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
        const Prism::SharedTransmission &Transport,
        std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            std::error_code ErrorCode;
            const auto ReadResult = co_await Transport->ReadSome(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data() + Offset),
                                     Buffer.size() - Offset));
            ErrorCode = Prism::Fault::ToNative(ReadResult.Failure);
            const auto Read = ReadResult.Bytes;
            if (ErrorCode || Read == 0 || Read > Buffer.size() - Offset)
            {
                co_return false;
            }
            Offset += Read;
        }
        co_return true;
    }

    [[nodiscard]] auto ReadRecord(
        const Prism::SharedTransmission &Transport,
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
        const Prism::SharedTransmission &Transport,
        std::span<const std::uint8_t> Buffer) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            std::error_code ErrorCode;
            const auto Write = co_await Transport->WriteSome(
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Buffer.data() + Offset),
                    Buffer.size() - Offset));
            ErrorCode = Prism::Fault::ToNative(Write.Failure);
            const auto Written = Write.Bytes;
            if (ErrorCode || Written == 0 || Written > Buffer.size() - Offset)
            {
                co_return false;
            }
            Offset += Written;
        }
        co_return true;
    }

    struct RelayClientRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        std::vector<std::uint8_t> ClientHello;
        std::vector<std::uint8_t> ServerHello;
        std::vector<std::uint8_t> FirstEncrypted;
        std::vector<std::uint8_t> ClientFinished;
        std::shared_ptr<RelayState> State;
        std::array<std::uint8_t, 32> ServerRandom;
        std::array<std::uint8_t, 32> Secret;
    };

    auto RunRelayClient(RelayClientRequest Request) -> Net::awaitable<void>
    {
        std::vector<std::uint8_t> Received;
        if (!co_await WriteAll(Request.Client, Request.ClientHello) ||
            !co_await ReadRecord(Request.Client, Received) || Received != Request.ServerHello)
        {
            co_await RetireAndVerify(Request.Client);
            co_return;
        }
        Request.State->ClientSawServerHello = true;
        std::vector<std::uint8_t> Protected;
        if (!co_await ReadRecord(Request.Client, Protected))
        {
            co_await RetireAndVerify(Request.Client);
            co_return;
        }
        const auto Expected = Restls::Detail::ProtectFirstEncrypted(
            Request.FirstEncrypted, Request.Secret, Request.ServerRandom);
        Request.State->ClientSawProtectedFirst =
            Expected.first == Prism::Error::None && Protected == Expected.second;
        Request.State->ClientSentFinished = co_await WriteAll(Request.Client, Request.ClientFinished);
    }

    struct RelayBackendRequest final
    {
        std::shared_ptr<MemoryStream> BackendServer;
        std::vector<std::uint8_t> ClientHello;
        std::vector<std::uint8_t> ServerHello;
        std::vector<std::uint8_t> FirstEncrypted;
        std::vector<std::uint8_t> ClientFinished;
        std::shared_ptr<RelayState> State;
    };

    auto RunRelayBackend(RelayBackendRequest Request) -> Net::awaitable<void>
    {
        std::vector<std::uint8_t> Received;
        if (!co_await ReadRecord(Request.BackendServer, Received) || Received != Request.ClientHello)
        {
            co_await RetireAndVerify(Request.BackendServer);
            co_return;
        }
        Request.State->BackendSawClientHello = true;
        Request.State->BackendSentServerHello = co_await WriteAll(Request.BackendServer, Request.ServerHello);
        Request.State->BackendSentFirst = co_await WriteAll(Request.BackendServer, Request.FirstEncrypted);
        std::vector<std::uint8_t> Finished;
        const auto FinishedRead = co_await ReadRecord(Request.BackendServer, Finished);
        Request.State->BackendSawClientFinished =
            FinishedRead && Finished == Request.ClientFinished;
        co_await RetireAndVerify(Request.BackendServer);
    }

    struct RelayHandshakeRequest final
    {
        Net::io_context &Context;
        Restls::ServerSession &Session;
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
        std::shared_ptr<MemoryStream> Backend;
        std::shared_ptr<MemoryStream> BackendServer;
        Restls::ServerConfig Config;
        std::vector<std::uint8_t> ClientHello;
        std::vector<std::uint8_t> ServerHello;
        std::vector<std::uint8_t> FirstEncrypted;
        std::vector<std::uint8_t> ClientFinished;
        std::shared_ptr<RelayState> State;
        std::array<std::uint8_t, 32> ServerRandom;
        std::array<std::uint8_t, 32> Secret;
        std::optional<Restls::Result<Restls::SharedConn>> &Result;
    };

    auto RunRelayHandshake(RelayHandshakeRequest Request) -> Net::awaitable<void>
    {
        const auto ClientDone = std::make_shared<CompletionState>(Request.Context.get_executor());
        const auto BackendDone = std::make_shared<CompletionState>(Request.Context.get_executor());
        Net::co_spawn(
            Request.Context.get_executor(),
            RunRelayClient(RelayClientRequest{
                Request.Client, Request.ClientHello, Request.ServerHello, Request.FirstEncrypted,
                Request.ClientFinished, Request.State, Request.ServerRandom, Request.Secret}),
            [ClientDone](std::exception_ptr Failure)
            { RecordCompletion(ClientDone, Failure); });
        Net::co_spawn(
            Request.Context.get_executor(),
            RunRelayBackend(RelayBackendRequest{
                Request.BackendServer, Request.ClientHello, Request.ServerHello,
                Request.FirstEncrypted, Request.ClientFinished, Request.State}),
            [BackendDone](std::exception_ptr Failure)
            { RecordCompletion(BackendDone, Failure); });
        std::exception_ptr Exception;
        try
        {
            Request.Result = co_await Request.Session.Run(Request.Server, Request.Config);
        }
        catch (...) { Exception = std::current_exception(); }
        if (Exception || !Request.Result.has_value() || !*Request.Result)
        {
            co_await RetireAndVerify(Request.Server);
            co_await RetireAndVerify(Request.Backend);
        }
        std::exception_ptr ClientFailure;
        std::exception_ptr BackendFailure;
        try { co_await AwaitCompletion(ClientDone); }
        catch (...) { ClientFailure = std::current_exception(); }
        try { co_await AwaitCompletion(BackendDone); }
        catch (...) { BackendFailure = std::current_exception(); }
        if ((Exception || ClientFailure || BackendFailure) && Request.Result.has_value() &&
            *Request.Result)
        {
            co_await RetireAndVerify(**Request.Result);
        }
        if (Exception) std::rethrow_exception(Exception);
        if (ClientFailure) std::rethrow_exception(ClientFailure);
        if (BackendFailure) std::rethrow_exception(BackendFailure);
    }

    struct RelayPayloadRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        Restls::SharedConn Connection;
        std::vector<std::uint8_t> RawRecord;
        std::array<std::byte, 64> &RawBuffer;
        std::size_t &RawRead;
        std::error_code &RawError;
    };

    auto RunRelayPayload(RelayPayloadRequest Request) -> Net::awaitable<void>
    {
        if (!co_await WriteAll(Request.Client, Request.RawRecord))
        {
            Request.RawError = std::make_error_code(std::errc::io_error);
            co_await RetireAndVerify(Request.Connection);
            co_await RetireAndVerify(Request.Client);
            co_return;
        }
        const auto RawReadResult = co_await Request.Connection->ReadSome(Request.RawBuffer);
        Request.RawError = Prism::Fault::ToNative(RawReadResult.Failure);
        Request.RawRead = RawReadResult.Bytes;
        co_await RetireAndVerify(Request.Connection);
        co_await RetireAndVerify(Request.Client);
    }

    struct RecordLengthRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
    };

    auto RunRecordLengthScenario(RecordLengthRequest Request) -> Net::awaitable<void>
    {
        const std::array<std::uint8_t, 5> HandshakePayload{0x01, 0x00, 0x00, 0x01, 0x00};
        const auto HandshakeWire = MakeRecord(0x16, HandshakePayload);
        const auto HandshakeWrite = co_await WriteAll(Request.Client, HandshakeWire);
        EXPECT_TRUE(HandshakeWrite);
        if (!HandshakeWrite)
        {
            co_await RetireAndVerify(Request.Client);
            co_await RetireAndVerify(Request.Server);
            co_return;
        }
        const auto HandshakeRead = co_await Restls::Detail::ReadRecordWire(Request.Server);
        EXPECT_TRUE(HandshakeRead);
        if (!HandshakeRead)
        {
            co_await RetireAndVerify(Request.Client);
            co_await RetireAndVerify(Request.Server);
            co_return;
        }
        EXPECT_EQ(*HandshakeRead, HandshakeWire);

        const std::array<std::uint8_t, Restls::AuthHdrlen - 1> ApplicationPayload{};
        const auto ApplicationWire = MakeRecord(0x17, ApplicationPayload);
        const auto ApplicationWrite = co_await WriteAll(Request.Client, ApplicationWire);
        EXPECT_TRUE(ApplicationWrite);
        if (!ApplicationWrite)
        {
            co_await RetireAndVerify(Request.Client);
            co_await RetireAndVerify(Request.Server);
            co_return;
        }
        const auto ApplicationRead = co_await Restls::Detail::ReadRecordWire(Request.Server);
        EXPECT_FALSE(ApplicationRead);
        if (!ApplicationRead)
        {
            EXPECT_EQ(ApplicationRead.error().Code, Prism::Error::BadLength);
        }
        co_await RetireAndVerify(Request.Client);
        co_await RetireAndVerify(Request.Server);
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
        const auto Secret = Restls::Detail::DeriveSecret(Password);

        Restls::ServerOptions Options;
        Options.DialTarget = [Backend](std::span<const std::uint8_t>)
            -> Net::awaitable<std::expected<Prism::SharedTransmission,
                                             Prism::Fault::Failure>>
        {
            co_return Prism::SharedTransmission{Backend};
        };
        Restls::ServerSession Session(std::move(Options));
        Restls::ServerConfig Config{Password};
        std::optional<Restls::Result<Restls::SharedConn>> Result;

        RunCoro(Context, RunRelayHandshake(RelayHandshakeRequest{
            Context, Session, Client, Server, Backend, BackendServer, Config,
            ClientHello, ServerHello, FirstEncrypted, ClientFinished, State,
            ServerRandom, Secret, Result}));

        ASSERT_TRUE(Result.has_value());
        ASSERT_TRUE(Result->has_value());
        ASSERT_TRUE(**Result);
        auto Connection = std::move(**Result);
        EXPECT_TRUE(State->ClientSawServerHello);
        EXPECT_TRUE(State->ClientSawProtectedFirst);
        EXPECT_TRUE(State->ClientSentFinished);
        EXPECT_TRUE(State->BackendSawClientHello);
        EXPECT_TRUE(State->BackendSentServerHello);
        EXPECT_TRUE(State->BackendSentFirst);
        EXPECT_TRUE(State->BackendSawClientFinished);

        const std::vector<std::uint8_t> RawPayload{
            'r', 'e', 's', 't', 'l', 's', '-', 'h', 'a', 'n', 'd', 'o', 'f', 'f'};
        const auto RawFrame = Restls::Detail::BuildFrame(Restls::Detail::FrameOptions{
            .Secret = Secret,
            .ServerRandom = ServerRandom,
            .Direction = Restls::FlowDirection::ToServer,
            .Counter = 0,
            .ClientFinished = ClientFinished,
            .Data = RawPayload,
            .PaddingLength = 0,
            .Command = Restls::CmdTypeNoop,
            .CommandArgument = 0});
        ASSERT_EQ(RawFrame.first, Prism::Error::None);
        const auto RawRecord = RawFrame.second;
        std::array<std::byte, 64> RawBuffer{};
        std::size_t RawRead = 0;
        std::error_code RawError;
        RunCoro(Context, RunRelayPayload(RelayPayloadRequest{
            Client, Connection, RawRecord, RawBuffer, RawRead, RawError}));

        EXPECT_FALSE(RawError);
        EXPECT_EQ(RawRead, RawPayload.size());
        EXPECT_EQ(std::vector<std::uint8_t>(
                      reinterpret_cast<const std::uint8_t *>(RawBuffer.data()),
                      reinterpret_cast<const std::uint8_t *>(RawBuffer.data()) + RawRead),
                  RawPayload);
    }

    struct NativeFailureRequest final
    {
        Restls::ServerSession &Session;
        std::shared_ptr<Prism::PrismMockTransport> Inbound;
        std::optional<Restls::Result<Restls::SharedConn>> &Result;
    };

    auto RunNativeFailure(NativeFailureRequest Request) -> Net::awaitable<void>
    {
        Restls::ServerConfig Config{"restls-failure"};
        Request.Result = co_await Request.Session.Run(Request.Inbound, Config);
    }

    TEST(RestlsServerRelay, PreservesFirstNativeReadFailureAndWaitsForRetirement)
    {
        Net::io_context Context;
        auto Inbound = std::make_shared<Prism::PrismMockTransport>(Context.get_executor());
        const auto Native = std::make_error_code(std::errc::address_in_use);
        Inbound->SetReadError(Native);

        Restls::ServerOptions Options;
        Options.DialTarget = [](std::span<const std::uint8_t>)
            -> Net::awaitable<std::expected<Prism::SharedTransmission,
                                             Prism::Fault::Failure>>
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadGateway});
        };
        Restls::ServerSession Session(std::move(Options));
        std::optional<Restls::Result<Restls::SharedConn>> Result;
        RunCoro(Context, RunNativeFailure(NativeFailureRequest{Session, Inbound, Result}));

        ASSERT_TRUE(Result.has_value());
        ASSERT_FALSE(*Result);
        EXPECT_EQ(Result->error().Code, Prism::Error::IoError);
        EXPECT_EQ(Result->error().Native, Native);
        EXPECT_TRUE(Inbound->IsClosed());
    }

    TEST(RestlsServerRelay, AllowsShortHandshakeAndRejectsUndersizedApplicationRecords)
    {
        Net::io_context Context;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context.get_executor());
        RunCoro(Context, RunRecordLengthScenario(RecordLengthRequest{
            std::make_shared<MemoryStream>(std::move(ClientEndpoint)),
            std::make_shared<MemoryStream>(std::move(ServerEndpoint))}));
    }

} // namespace
