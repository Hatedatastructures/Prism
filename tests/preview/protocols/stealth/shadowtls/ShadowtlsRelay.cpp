/**
 * @file ShadowtlsRelay.cpp
 * @brief ShadowTLS v3 服务端标准 TLS relay 核心测试
 * @details 使用独立 client/target/server 三端内存传输验证：
 *          ClientHello 转发、ServerHello random 提取、TLS 握手 flight
 *          转换、首个客户端 C 方向 application-data 认证和内层回注。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <preview/Protocols/Shadowtls/Server.hpp>
#include <preview/Transport/MemoryStream.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Shadowtls = Preview::Shadowtls;

    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using SharedTransmission = Preview::SharedTransmission;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct TaskState final
    {
        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Exception;
    };

    struct RelayRequest final
    {
        std::shared_ptr<Shadowtls::ServerSession> Relay;
        SharedTransmission Server;
        Shadowtls::ServerConfig Config;
        std::shared_ptr<std::optional<Shadowtls::ServerResult>> Result;
    };

    struct TargetHandshakeRequest final
    {
        SharedTransmission Target;
        std::vector<std::uint8_t> ServerHello;
        std::vector<std::uint8_t> TargetPayload;
    };

    struct TargetBadApplicationRequest final
    {
        SharedTransmission Target;
        std::vector<std::uint8_t> ServerHello;
    };

    struct SuccessfulRelayRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        SharedTransmission TargetClient;
        SharedTransmission Target;
        std::string Password;
        std::vector<std::uint8_t> ServerHello;
        std::vector<std::uint8_t> FirstPayload;
        std::vector<std::uint8_t> ResponsePayload;
        std::vector<std::uint8_t> TargetPayload;
    };

    struct BadClientHelloRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        std::vector<std::uint8_t> ClientHello;
        std::string Password;
        std::shared_ptr<std::size_t> DialCalls;
    };

    struct TargetDialFailureRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        std::vector<std::uint8_t> ClientHello;
        std::string Password;
    };

    struct BadApplicationRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        SharedTransmission TargetClient;
        SharedTransmission Target;
        std::vector<std::uint8_t> ServerHello;
        std::vector<std::uint8_t> ClientHello;
        std::vector<std::uint8_t> Payload;
    };

    template <typename Awaitable>
    auto SpawnTask(Net::any_io_executor Executor, Awaitable Operation) -> TaskState
    {
        TaskState State;
        State.Done = std::make_shared<CompletionChannel>(Executor, 1);
        State.Exception = std::make_shared<std::exception_ptr>();
        auto Completion = [State](std::exception_ptr ErrorValue) -> void
        {
            *State.Exception = ErrorValue;
            (void)State.Done->try_send(boost::system::error_code{});
        };
        Net::co_spawn(Executor, std::move(Operation), std::move(Completion));
        return State;
    }

    auto WaitForTask(TaskState State) -> Net::awaitable<void>
    {
        boost::system::error_code WaitError;
        auto ReceiveOperation = State.Done->async_receive(
            Net::redirect_error(Net::use_awaitable, WaitError));
        (void)co_await std::move(ReceiveOperation);
        if (WaitError)
        {
            throw std::system_error(WaitError);
        }
        if (*State.Exception)
        {
            std::rethrow_exception(*State.Exception);
        }
        co_return;
    }

    template <typename Awaitable>
    auto RunCoroutine(
        const std::shared_ptr<Net::io_context> &Context,
        Awaitable Operation) -> void
    {
        Context->restart();
        auto Failure = std::make_shared<std::exception_ptr>();
        auto Completion = [Context, Failure](std::exception_ptr ErrorValue) -> void
        {
            *Failure = ErrorValue;
            Context->stop();
        };
        Net::co_spawn(*Context, std::move(Operation), std::move(Completion));
        Context->run();
        if (*Failure)
        {
            std::rethrow_exception(*Failure);
        }
    }

    auto CloseTransport(const SharedTransmission &Transport) -> void
    {
        if (Transport)
        {
            Transport->Cancel();
            Transport->Close();
        }
    }

    auto ToByteVector(std::span<const std::byte> Bytes) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result(Bytes.size());
        if (!Bytes.empty())
        {
            std::memcpy(Result.data(), Bytes.data(), Bytes.size());
        }
        return Result;
    }

    auto MakeServerHello() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Hello(78, 0);
        Hello[0] = 0x03;
        Hello[1] = 0x03;
        for (std::size_t Index = 0; Index < Shadowtls::TlsRndSize; ++Index)
        {
            Hello[2 + Index] = static_cast<std::uint8_t>(0x80 + Index);
        }
        Hello[34] = Shadowtls::TlsSessionIdSz;
        Hello[67] = 0x13;
        Hello[68] = 0x01;
        Hello[69] = 0;
        Hello[70] = 0;
        Hello[71] = 6;
        Hello[72] = 0;
        Hello[73] = 43;
        Hello[74] = 0;
        Hello[75] = 2;
        Hello[76] = 3;
        Hello[77] = 4;

        std::vector<std::uint8_t> Record(Shadowtls::TlsHdrsize + 4 + Hello.size(), 0);
        Record[0] = 0x16;
        Record[1] = 0x03;
        Record[2] = 0x03;
        const auto BodyLength = static_cast<std::uint16_t>(4 + Hello.size());
        Record[3] = static_cast<std::uint8_t>(BodyLength >> 8);
        Record[4] = static_cast<std::uint8_t>(BodyLength);
        Record[5] = 2;
        Record[7] = static_cast<std::uint8_t>(Hello.size() >> 8);
        Record[8] = static_cast<std::uint8_t>(Hello.size());
        std::copy(Hello.begin(), Hello.end(), Record.begin() + 9);
        return Record;
    }

    auto MakeClientHello(
        std::string_view Password,
        std::uint8_t Seed = 0x20) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Hello(75, 0);
        Hello[0] = 0x03;
        Hello[1] = 0x03;
        for (std::size_t Index = 0; Index < Shadowtls::TlsRndSize; ++Index)
        {
            Hello[2 + Index] = static_cast<std::uint8_t>(Seed + Index);
        }
        Hello[34] = Shadowtls::TlsSessionIdSz;
        Hello[67] = 0;
        Hello[68] = 2;
        Hello[69] = 0x13;
        Hello[70] = 0x01;
        Hello[71] = 1;
        Hello[72] = 0;
        Hello[73] = 0;
        Hello[74] = 0;

        std::vector<std::uint8_t> Record(Shadowtls::TlsHdrsize + 4 + Hello.size(), 0);
        Record[0] = 0x16;
        Record[1] = 0x03;
        Record[2] = 0x03;
        const auto BodyLength = static_cast<std::uint16_t>(4 + Hello.size());
        Record[3] = static_cast<std::uint8_t>(BodyLength >> 8);
        Record[4] = static_cast<std::uint8_t>(BodyLength);
        Record[5] = Shadowtls::HsTypeClienthello;
        Record[7] = 0;
        Record[8] = static_cast<std::uint8_t>(Hello.size());
        std::copy(Hello.begin(), Hello.end(), Record.begin() + 9);

        std::span<std::uint8_t, Shadowtls::TlsSessionIdSz> SessionId(
            Record.data() + Shadowtls::TlsHdrsize + Shadowtls::SessionIdStart,
            Shadowtls::TlsSessionIdSz);
        const auto HelloBytes = std::span<const std::uint8_t>(Record).subspan(Shadowtls::TlsHdrsize);
        const auto SessionInput = Shadowtls::SessionIdInput{Password, HelloBytes, SessionId};
        EXPECT_EQ(Shadowtls::GenerateSessionId(SessionInput), Error::None);
        return Record;
    }

    auto RunRelay(RelayRequest Request) -> Net::awaitable<void>
    {
        const auto Result = co_await Request.Relay->Run(Request.Server, Request.Config);
        *Request.Result = Result;
        co_return;
    }

    auto RunTargetHandshake(TargetHandshakeRequest Request) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        std::error_code ErrorCode;
        auto ReadOperation = Request.Target->async_read_some(Buffer, ErrorCode);
        const auto Count = co_await std::move(ReadOperation);
        EXPECT_FALSE(ErrorCode);
        EXPECT_GT(Count, 0U);

        const auto ServerHelloBytes = std::as_bytes(
            std::span<const std::uint8_t>(Request.ServerHello));
        auto ServerHelloWrite = Request.Target->async_write_some(ServerHelloBytes, ErrorCode);
        const auto ServerHelloWritten = co_await std::move(ServerHelloWrite);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(ServerHelloWritten, Request.ServerHello.size());

        std::vector<std::uint8_t> TargetRecord(
            Shadowtls::TlsHdrsize + Request.TargetPayload.size());
        TargetRecord[0] = Shadowtls::TlsContentApplicationData;
        TargetRecord[1] = Shadowtls::TlsRecordVersionMajor;
        TargetRecord[2] = Shadowtls::TlsRecordVersionMinor;
        const auto TargetLength = static_cast<std::uint16_t>(Request.TargetPayload.size());
        TargetRecord[3] = static_cast<std::uint8_t>(TargetLength >> 8);
        TargetRecord[4] = static_cast<std::uint8_t>(TargetLength);
        std::copy(Request.TargetPayload.begin(), Request.TargetPayload.end(),
                  TargetRecord.begin() + Shadowtls::TlsHdrsize);
        const auto TargetRecordBytes = std::as_bytes(
            std::span<const std::uint8_t>(TargetRecord));
        auto FlightWrite = Request.Target->async_write_some(TargetRecordBytes, ErrorCode);
        const auto FlightWritten = co_await std::move(FlightWrite);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(FlightWritten, TargetRecord.size());
        co_return;
    }

    auto RunTargetBadApplication(TargetBadApplicationRequest Request) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        std::error_code ErrorCode;
        auto ReadOperation = Request.Target->async_read_some(Buffer, ErrorCode);
        const auto Count = co_await std::move(ReadOperation);
        EXPECT_FALSE(ErrorCode);
        EXPECT_GT(Count, 0U);

        const auto ServerHelloBytes = std::as_bytes(
            std::span<const std::uint8_t>(Request.ServerHello));
        auto ServerHelloWrite = Request.Target->async_write_some(ServerHelloBytes, ErrorCode);
        const auto ServerHelloWritten = co_await std::move(ServerHelloWrite);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(ServerHelloWritten, Request.ServerHello.size());

        std::array<std::byte, 256> BadRecord{};
        auto BadRecordRead = Request.Target->async_read_some(BadRecord, ErrorCode);
        const auto BadCount = co_await std::move(BadRecordRead);
        EXPECT_FALSE(ErrorCode);
        EXPECT_GT(BadCount, 0U);
        CloseTransport(Request.Target);
        co_return;
    }

    auto RunSuccessfulRelay(SuccessfulRelayRequest Request) -> Net::awaitable<void>
    {
        Shadowtls::ServerOptions Options;
        Options.DialTarget = [TargetClient = Request.TargetClient](
                                 std::span<const std::uint8_t>) -> Net::awaitable<SharedTransmission>
        {
            co_return TargetClient;
        };
        auto Relay = std::make_shared<Shadowtls::ServerSession>(std::move(Options));
        auto RelayResult = std::make_shared<std::optional<Shadowtls::ServerResult>>();
        const auto RelayTask = SpawnTask(
            Request.Server->Executor(),
            RunRelay(RelayRequest{
                Relay,
                Request.Server,
                Shadowtls::ServerConfig{Request.Password},
                RelayResult}));
        const auto TargetTask = SpawnTask(
            Request.Target->Executor(),
            RunTargetHandshake(TargetHandshakeRequest{
                Request.Target,
                Request.ServerHello,
                Request.TargetPayload}));

        const auto ClientHello = MakeClientHello(Request.Password);
        const auto ClientHelloBytes = std::as_bytes(std::span<const std::uint8_t>(ClientHello));
        std::error_code ErrorCode;
        auto ClientHelloWrite = Request.Client->async_write_some(ClientHelloBytes, ErrorCode);
        const auto ClientHelloWritten = co_await std::move(ClientHelloWrite);
        EXPECT_EQ(ClientHelloWritten, ClientHello.size());
        EXPECT_FALSE(ErrorCode);

        std::vector<std::uint8_t> ForwardedServerHello(Request.ServerHello.size());
        std::size_t ServerHelloDone = 0;
        while (ServerHelloDone < ForwardedServerHello.size())
        {
            const auto Remaining = std::span<std::uint8_t>(ForwardedServerHello).subspan(ServerHelloDone);
            const auto ReadBuffer = std::as_writable_bytes(Remaining);
            auto ReadOperation = Request.Client->async_read_some(ReadBuffer, ErrorCode);
            const auto Count = co_await std::move(ReadOperation);
            EXPECT_FALSE(ErrorCode);
            EXPECT_GT(Count, 0U);
            if (ErrorCode || Count == 0)
            {
                co_return;
            }
            ServerHelloDone += Count;
        }
        EXPECT_EQ(ForwardedServerHello, Request.ServerHello);

        std::array<std::uint8_t, Shadowtls::TlsHdrsize> FlightHeader{};
        auto FlightHeaderBuffer = std::as_writable_bytes(std::span<std::uint8_t>(FlightHeader));
        auto FlightHeaderRead = Request.Client->async_read_some(FlightHeaderBuffer, ErrorCode);
        const auto FlightHeaderCount = co_await std::move(FlightHeaderRead);
        EXPECT_EQ(FlightHeaderCount, FlightHeader.size());
        EXPECT_FALSE(ErrorCode);

        const auto FlightLength = (static_cast<std::size_t>(FlightHeader[3]) << 8) | FlightHeader[4];
        std::vector<std::uint8_t> ForwardedFlight(Shadowtls::TlsHdrsize + FlightLength);
        std::copy(FlightHeader.begin(), FlightHeader.end(), ForwardedFlight.begin());
        const auto FlightPayload = std::span<std::uint8_t>(ForwardedFlight).subspan(Shadowtls::TlsHdrsize);
        const auto FlightPayloadBuffer = std::as_writable_bytes(FlightPayload);
        auto FlightRead = Request.Client->async_read_some(FlightPayloadBuffer, ErrorCode);
        const auto FlightCount = co_await std::move(FlightRead);
        EXPECT_EQ(FlightCount, FlightLength);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(ForwardedFlight,
                  (std::vector<std::uint8_t>{0x17, 0x03, 0x03, 0x00, 0x07, 0x46, 0x0E, 0xD6, 0xE8,
                                             0x23, 0xC5, 0x69}));

        const auto ServerRandom = std::span<const std::uint8_t>(Request.ServerHello).subspan(
            11, Shadowtls::TlsRndSize);
        Shadowtls::RecordProtector FlightDecoder{
            Request.Password,
            ServerRandom,
            Shadowtls::TagServer,
            Shadowtls::RecordSeed::ServerRandomOnly,
            true,
            false};
        std::vector<std::uint8_t> DecodedFlight;
        EXPECT_EQ(FlightDecoder.Decode(ForwardedFlight, DecodedFlight), Error::None);
        EXPECT_EQ(DecodedFlight, Request.TargetPayload);

        Shadowtls::RecordProtector ClientEncoder{
            Request.Password, ServerRandom, Shadowtls::TagClient};
        std::vector<std::uint8_t> FirstRecord;
        EXPECT_EQ(ClientEncoder.Encode(Request.FirstPayload, FirstRecord), Error::None);
        const auto FirstRecordBytes = std::as_bytes(std::span<const std::uint8_t>(FirstRecord));
        auto FirstRecordWrite = Request.Client->async_write_some(FirstRecordBytes, ErrorCode);
        const auto FirstRecordWritten = co_await std::move(FirstRecordWrite);
        EXPECT_EQ(FirstRecordWritten, FirstRecord.size());
        EXPECT_FALSE(ErrorCode);

        co_await WaitForTask(TargetTask);
        co_await WaitForTask(RelayTask);
        EXPECT_TRUE(RelayResult->has_value());
        if (!RelayResult->has_value())
        {
            co_return;
        }
        const auto &Result = **RelayResult;
        EXPECT_EQ(Result.Status, Error::None);
        auto ClientConnection = Result.Connection;
        EXPECT_TRUE(ClientConnection);
        if (!ClientConnection)
        {
            CloseTransport(Request.Client);
            CloseTransport(Request.Server);
            CloseTransport(Request.TargetClient);
            CloseTransport(Request.Target);
            co_return;
        }

        std::array<std::byte, 32> InnerBuffer{};
        auto InnerRead = ClientConnection->async_read_some(InnerBuffer, ErrorCode);
        const auto InnerCount = co_await std::move(InnerRead);
        EXPECT_FALSE(ErrorCode);
        const auto InnerBytes = std::span<const std::byte>(InnerBuffer).first(InnerCount);
        EXPECT_EQ(ToByteVector(InnerBytes), Request.FirstPayload);

        const auto ResponseBytes = std::as_bytes(
            std::span<const std::uint8_t>(Request.ResponsePayload));
        auto ResponseWrite = ClientConnection->async_write_some(ResponseBytes, ErrorCode);
        const auto ResponseWritten = co_await std::move(ResponseWrite);
        EXPECT_EQ(ResponseWritten, Request.ResponsePayload.size());
        EXPECT_FALSE(ErrorCode);
        CloseTransport(ClientConnection);
        CloseTransport(Request.Client);
        CloseTransport(Request.Server);
        CloseTransport(Request.TargetClient);
        CloseTransport(Request.Target);
        co_return;
    }

    auto RunBadClientHello(BadClientHelloRequest Request) -> Net::awaitable<void>
    {
        Shadowtls::ServerOptions Options;
        Options.DialTarget = [DialCalls = Request.DialCalls](
                                 std::span<const std::uint8_t>) -> Net::awaitable<SharedTransmission>
        {
            ++*DialCalls;
            co_return nullptr;
        };
        auto Relay = std::make_shared<Shadowtls::ServerSession>(std::move(Options));
        auto RelayResult = std::make_shared<std::optional<Shadowtls::ServerResult>>();
        const auto RelayTask = SpawnTask(
            Request.Server->Executor(),
            RunRelay(RelayRequest{
                Relay,
                Request.Server,
                Shadowtls::ServerConfig{Request.Password},
                RelayResult}));

        const auto ClientHelloBytes = std::as_bytes(std::span<const std::uint8_t>(Request.ClientHello));
        std::error_code ErrorCode;
        auto ClientHelloWrite = Request.Client->async_write_some(ClientHelloBytes, ErrorCode);
        const auto ClientHelloWritten = co_await std::move(ClientHelloWrite);
        EXPECT_EQ(ClientHelloWritten, Request.ClientHello.size());
        EXPECT_FALSE(ErrorCode);

        co_await WaitForTask(RelayTask);
        EXPECT_TRUE(RelayResult->has_value());
        if (!RelayResult->has_value())
        {
            co_return;
        }
        EXPECT_EQ((*RelayResult)->Status, Error::BadAuth);
        EXPECT_FALSE((*RelayResult)->Connection);
        EXPECT_EQ(*Request.DialCalls, 0U);
        CloseTransport(Request.Client);
        CloseTransport(Request.Server);
        co_return;
    }

    auto RunTargetDialFailure(TargetDialFailureRequest Request) -> Net::awaitable<void>
    {
        Shadowtls::ServerOptions Options;
        Options.DialTarget = [](std::span<const std::uint8_t>)
            -> Net::awaitable<SharedTransmission>
        {
            co_return nullptr;
        };
        auto Relay = std::make_shared<Shadowtls::ServerSession>(std::move(Options));
        auto RelayResult = std::make_shared<std::optional<Shadowtls::ServerResult>>();
        const auto RelayTask = SpawnTask(
            Request.Server->Executor(),
            RunRelay(RelayRequest{
                Relay,
                Request.Server,
                Shadowtls::ServerConfig{Request.Password},
                RelayResult}));

        const auto ClientHelloBytes = std::as_bytes(std::span<const std::uint8_t>(Request.ClientHello));
        std::error_code ErrorCode;
        auto ClientHelloWrite = Request.Client->async_write_some(ClientHelloBytes, ErrorCode);
        const auto ClientHelloWritten = co_await std::move(ClientHelloWrite);
        EXPECT_EQ(ClientHelloWritten, Request.ClientHello.size());
        EXPECT_FALSE(ErrorCode);

        co_await WaitForTask(RelayTask);
        EXPECT_TRUE(RelayResult->has_value());
        if (!RelayResult->has_value())
        {
            co_return;
        }
        EXPECT_EQ((*RelayResult)->Status, Error::IoError);
        EXPECT_FALSE((*RelayResult)->Connection);
        std::array<std::byte, 1> Buffer{};
        auto CloseRead = Request.Client->async_read_some(Buffer, ErrorCode);
        const auto Count = co_await std::move(CloseRead);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(Count, 0U);
        CloseTransport(Request.Client);
        CloseTransport(Request.Server);
        co_return;
    }

    auto RunBadApplication(BadApplicationRequest Request) -> Net::awaitable<void>
    {
        Shadowtls::ServerOptions Options;
        Options.DialTarget = [TargetClient = Request.TargetClient](
                                 std::span<const std::uint8_t>) -> Net::awaitable<SharedTransmission>
        {
            co_return TargetClient;
        };
        auto Relay = std::make_shared<Shadowtls::ServerSession>(std::move(Options));
        auto RelayResult = std::make_shared<std::optional<Shadowtls::ServerResult>>();
        const auto RelayTask = SpawnTask(
            Request.Server->Executor(),
            RunRelay(RelayRequest{
                Relay,
                Request.Server,
                Shadowtls::ServerConfig{"relay-password"},
                RelayResult}));
        const auto TargetTask = SpawnTask(
            Request.Target->Executor(),
            RunTargetBadApplication(TargetBadApplicationRequest{
                Request.Target,
                Request.ServerHello}));

        const auto ClientHelloBytes = std::as_bytes(std::span<const std::uint8_t>(Request.ClientHello));
        std::error_code ErrorCode;
        auto ClientHelloWrite = Request.Client->async_write_some(ClientHelloBytes, ErrorCode);
        const auto ClientHelloWritten = co_await std::move(ClientHelloWrite);
        EXPECT_EQ(ClientHelloWritten, Request.ClientHello.size());
        EXPECT_FALSE(ErrorCode);

        std::array<std::byte, 4096> Buffer{};
        auto ServerHelloRead = Request.Client->async_read_some(Buffer, ErrorCode);
        const auto ServerHelloCount = co_await std::move(ServerHelloRead);
        EXPECT_EQ(ServerHelloCount, Request.ServerHello.size());
        EXPECT_FALSE(ErrorCode);

        const auto ServerRandom = std::span<const std::uint8_t>(Request.ServerHello).subspan(
            11, Shadowtls::TlsRndSize);
        Shadowtls::RecordProtector WrongEncoder{
            "wrong-password", ServerRandom, Shadowtls::TagClient};
        std::vector<std::uint8_t> BadRecord;
        EXPECT_EQ(WrongEncoder.Encode(Request.Payload, BadRecord), Error::None);
        const auto BadRecordBytes = std::as_bytes(std::span<const std::uint8_t>(BadRecord));
        auto BadRecordWrite = Request.Client->async_write_some(BadRecordBytes, ErrorCode);
        const auto BadRecordWritten = co_await std::move(BadRecordWrite);
        EXPECT_EQ(BadRecordWritten, BadRecord.size());
        EXPECT_FALSE(ErrorCode);

        co_await WaitForTask(TargetTask);
        co_await WaitForTask(RelayTask);
        EXPECT_TRUE(RelayResult->has_value());
        if (!RelayResult->has_value())
        {
            co_return;
        }
        EXPECT_NE((*RelayResult)->Status, Error::None);
        EXPECT_FALSE((*RelayResult)->Connection);
        CloseTransport(Request.Client);
        CloseTransport(Request.Server);
        CloseTransport(Request.TargetClient);
        CloseTransport(Request.Target);
        co_return;
    }
} // namespace

TEST(ShadowtlsRelay, RelaysHandshakeAndReturnsAuthenticatedInnerConnection)
{
    auto Context = std::make_shared<Net::io_context>();
    auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context->get_executor());
    auto [TargetClientEndpoint, TargetEndpoint] = MakeMemoryPair(Context->get_executor());
    const auto Client = std::make_shared<MemoryStream>(std::move(ClientEndpoint));
    const auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
    const auto TargetClient = std::make_shared<MemoryStream>(std::move(TargetClientEndpoint));
    const auto Target = std::make_shared<MemoryStream>(std::move(TargetEndpoint));

    RunCoroutine(
        Context,
        RunSuccessfulRelay(SuccessfulRelayRequest{
            Client,
            Server,
            TargetClient,
            Target,
            "relay-password",
            MakeServerHello(),
            {0x31, 0x32, 0x33, 0x34},
            {0xA1, 0xA2, 0xA3},
            {0xD1, 0xD2, 0xD3}}));
}

TEST(ShadowtlsRelay, RejectsBadClientHelloBeforeTargetDial)
{
    auto Context = std::make_shared<Net::io_context>();
    auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context->get_executor());
    const auto Client = std::make_shared<MemoryStream>(std::move(ClientEndpoint));
    const auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
    const auto DialCalls = std::make_shared<std::size_t>(0);

    RunCoroutine(
        Context,
        RunBadClientHello(BadClientHelloRequest{
            Client,
            Server,
            MakeClientHello("wrong-password"),
            "expected",
            DialCalls}));
}

TEST(ShadowtlsRelay, ReportsTargetDialFailure)
{
    auto Context = std::make_shared<Net::io_context>();
    auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context->get_executor());
    const auto Client = std::make_shared<MemoryStream>(std::move(ClientEndpoint));
    const auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));

    RunCoroutine(
        Context,
        RunTargetDialFailure(TargetDialFailureRequest{
            Client,
            Server,
            MakeClientHello("relay-password", 0x31),
            "relay-password"}));
}

TEST(ShadowtlsRelay, RejectsBadApplicationRecordAfterServerHello)
{
    auto Context = std::make_shared<Net::io_context>();
    auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context->get_executor());
    auto [TargetClientEndpoint, TargetEndpoint] = MakeMemoryPair(Context->get_executor());
    const auto Client = std::make_shared<MemoryStream>(std::move(ClientEndpoint));
    const auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
    const auto TargetClient = std::make_shared<MemoryStream>(std::move(TargetClientEndpoint));
    const auto Target = std::make_shared<MemoryStream>(std::move(TargetEndpoint));

    RunCoroutine(
        Context,
        RunBadApplication(BadApplicationRequest{
            Client,
            Server,
            TargetClient,
            Target,
            MakeServerHello(),
            MakeClientHello("relay-password", 0x47),
            {0x41, 0x42}}));
}
