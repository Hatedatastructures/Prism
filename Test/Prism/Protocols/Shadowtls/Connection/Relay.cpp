/**
 * @file Relay.cpp
 * @brief ShadowTLS v3 服务端标准 TLS relay 核心测试
 * @details 使用独立 client/target/server 三端内存传输验证：
 *          ClientHello 转发、ServerHello random 提取、TLS 握手 flight
 *          转换、首个客户端 C 方向 application-data 认证和内层回注。
 */

#include <boost/asio/awaitable.hpp>
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

#include <Prism/Protocols/Shadowtls/Detail/ClientHello.hpp>
#include <Prism/Protocols/Shadowtls/Detail/RecordProtector.hpp>
#include <Prism/Protocols/Shadowtls/Detail/Retirement.hpp>
#include <Prism/Protocols/Shadowtls/Shadowtls.hpp>
#include <Prism/Transport/MemoryStream.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Shadowtls = Prism::Shadowtls;

    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using SharedTransmission = Prism::SharedTransmission;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    auto ErrorOf(const Shadowtls::Failure &Failure) -> Error
    {
        const auto Native = boost::system::error_code(Failure.Native);
        if (&Native.category() == &Prism::ErrorCategory())
        {
            return static_cast<Error>(Native.value());
        }
        return Shadowtls::ToProtocolError(Failure.Code);
    }

    template <class Value>
    auto ErrorOf(const Shadowtls::Result<Value> &Outcome) -> Error
    {
        if (Outcome)
        {
            return Error::None;
        }
        return ErrorOf(Outcome.error());
    }

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
        std::shared_ptr<std::optional<Shadowtls::Result<Shadowtls::SharedConn>>> Result;
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

    auto CloseTransport(SharedTransmission Transport) -> Net::awaitable<void>
    {
        if (!Transport) co_return;
        auto Retired = co_await Shadowtls::Detail::TransportRetirement::RetireAndDrain(
            std::move(Transport));
        EXPECT_EQ(ErrorOf(Retired), Error::None);
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
        const auto SessionInput = Shadowtls::Detail::SessionIdInput{Password, HelloBytes, SessionId};
        EXPECT_EQ(Shadowtls::Detail::GenerateSessionId(SessionInput), Error::None);
        return Record;
    }

    auto RunRelay(RelayRequest Request) -> Net::awaitable<void>
    {
        auto Result = co_await Request.Relay->Run(Request.Server, Request.Config);
        *Request.Result = std::move(Result);
        co_return;
    }

    auto RunTargetHandshake(TargetHandshakeRequest Request) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        std::error_code ErrorCode;
        const auto ReadOperation = co_await Request.Target->ReadSome(Buffer);
        const auto Count = ReadOperation.Bytes;
        ErrorCode = Prism::Fault::ToNative(ReadOperation.Failure);
        EXPECT_FALSE(ErrorCode);
        EXPECT_GT(Count, 0U);

        const auto ServerHelloBytes = std::as_bytes(
            std::span<const std::uint8_t>(Request.ServerHello));
        const auto ServerHelloWrite = co_await Request.Target->WriteSome(ServerHelloBytes);
        const auto ServerHelloWritten = ServerHelloWrite.Bytes;
        ErrorCode = Prism::Fault::ToNative(ServerHelloWrite.Failure);
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
        const auto FlightWrite = co_await Request.Target->WriteSome(TargetRecordBytes);
        const auto FlightWritten = FlightWrite.Bytes;
        ErrorCode = Prism::Fault::ToNative(FlightWrite.Failure);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(FlightWritten, TargetRecord.size());
        co_return;
    }

    auto RunTargetBadApplication(TargetBadApplicationRequest Request) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        std::error_code ErrorCode;
        const auto ReadOperation = co_await Request.Target->ReadSome(Buffer);
        const auto Count = ReadOperation.Bytes;
        ErrorCode = Prism::Fault::ToNative(ReadOperation.Failure);
        EXPECT_FALSE(ErrorCode);
        EXPECT_GT(Count, 0U);

        const auto ServerHelloBytes = std::as_bytes(
            std::span<const std::uint8_t>(Request.ServerHello));
        const auto ServerHelloWrite = co_await Request.Target->WriteSome(ServerHelloBytes);
        const auto ServerHelloWritten = ServerHelloWrite.Bytes;
        ErrorCode = Prism::Fault::ToNative(ServerHelloWrite.Failure);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(ServerHelloWritten, Request.ServerHello.size());

        std::array<std::byte, 256> BadRecord{};
        const auto BadRecordRead = co_await Request.Target->ReadSome(BadRecord);
        const auto BadCount = BadRecordRead.Bytes;
        ErrorCode = Prism::Fault::ToNative(BadRecordRead.Failure);
        EXPECT_FALSE(ErrorCode);
        EXPECT_GT(BadCount, 0U);
        co_await CloseTransport(Request.Target);
        co_return;
    }

    struct SuccessfulRelayInnerRequest final
    {
        SuccessfulRelayRequest Request;
        std::shared_ptr<std::optional<Shadowtls::Result<Shadowtls::SharedConn>>> RelayResult;
        TaskState RelayTask;
        TaskState TargetTask;
        std::vector<std::uint8_t> ServerRandom;
        SharedTransmission ClientConnection;
    };

    /** @brief 验证 relay 返回的 inner transport、响应记录和全部 close owner。 */
    auto RunSuccessfulRelayInner(SuccessfulRelayInnerRequest Request) -> Net::awaitable<void>
    {
        co_await WaitForTask(Request.TargetTask);
        co_await WaitForTask(Request.RelayTask);
        EXPECT_TRUE(Request.RelayResult->has_value());
        if (!Request.RelayResult->has_value()) co_return;
        const auto &Result = **Request.RelayResult;
        EXPECT_EQ(ErrorOf(Result), Error::None);
        if (!Result)
        {
            co_await CloseTransport(Request.Request.Client);
            co_await CloseTransport(Request.Request.Server);
            co_await CloseTransport(Request.Request.TargetClient);
            co_await CloseTransport(Request.Request.Target);
            co_return;
        }
        Request.ClientConnection = *Result;
        EXPECT_TRUE(Request.ClientConnection);
        std::array<std::byte, 32> InnerBuffer{};
        std::error_code ErrorCode;
        const auto InnerRead = co_await Request.ClientConnection->ReadSome(InnerBuffer);
        const auto InnerCount = InnerRead.Bytes;
        ErrorCode = Prism::Fault::ToNative(InnerRead.Failure);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(ToByteVector(std::span<const std::byte>(InnerBuffer).first(InnerCount)),
                  Request.Request.FirstPayload);
        const auto ResponseBytes = std::as_bytes(
            std::span<const std::uint8_t>(Request.Request.ResponsePayload));
        const auto ResponseWrite = co_await Request.ClientConnection->WriteSome(ResponseBytes);
        const auto ResponseWritten = ResponseWrite.Bytes;
        ErrorCode = Prism::Fault::ToNative(ResponseWrite.Failure);
        EXPECT_EQ(ResponseWritten, Request.Request.ResponsePayload.size());
        EXPECT_FALSE(ErrorCode);
        std::array<std::byte, 4096> ResponseRecordBuffer{};
        const auto ResponseRecordRead = co_await Request.Request.Client->ReadSome(ResponseRecordBuffer);
        const auto ResponseRecordCount = ResponseRecordRead.Bytes;
        ErrorCode = Prism::Fault::ToNative(ResponseRecordRead.Failure);
        EXPECT_FALSE(ErrorCode);
        EXPECT_GT(ResponseRecordCount, Shadowtls::TlsHdrsize + Shadowtls::HmacSize);
        if (ResponseRecordCount <= Shadowtls::TlsHdrsize + Shadowtls::HmacSize) co_return;
        const auto ResponseRecord = std::span<const std::byte>(ResponseRecordBuffer).first(ResponseRecordCount);
        const auto ResponseRecordBytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(ResponseRecord.data()), ResponseRecord.size());
        std::vector<std::uint8_t> DecodedResponse;
        Shadowtls::Detail::RecordProtector ResponseDecoder{Shadowtls::Detail::RecordProtectionOptions{
            Request.Request.Password,
            std::span<const std::uint8_t>(Request.ServerRandom),
            Shadowtls::TagServer}};
        EXPECT_EQ(ResponseDecoder.Decode(ResponseRecordBytes, DecodedResponse), Error::None);
        EXPECT_EQ(DecodedResponse, Request.Request.ResponsePayload);
        co_await CloseTransport(Request.ClientConnection);
        co_await CloseTransport(Request.Request.Client);
        co_await CloseTransport(Request.Request.Server);
        co_await CloseTransport(Request.Request.TargetClient);
        co_await CloseTransport(Request.Request.Target);
    }

    auto RunSuccessfulRelay(SuccessfulRelayRequest Request) -> Net::awaitable<void>
    {
        Shadowtls::ServerOptions Options;
        Options.DialTarget = [TargetClient = Request.TargetClient](
                                 std::span<const std::uint8_t>) -> Net::awaitable<Shadowtls::Result<SharedTransmission>>
        {
            co_return TargetClient;
        };
        auto Relay = std::make_shared<Shadowtls::ServerSession>(std::move(Options));
        auto RelayResult = std::make_shared<std::optional<Shadowtls::Result<Shadowtls::SharedConn>>>();
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
        const auto ClientHelloWrite = co_await Request.Client->WriteSome(ClientHelloBytes);
        const auto ClientHelloWritten = ClientHelloWrite.Bytes;
        ErrorCode = Prism::Fault::ToNative(ClientHelloWrite.Failure);
        EXPECT_EQ(ClientHelloWritten, ClientHello.size());
        EXPECT_FALSE(ErrorCode);

        std::vector<std::uint8_t> ForwardedServerHello(Request.ServerHello.size());
        std::size_t ServerHelloDone = 0;
        while (ServerHelloDone < ForwardedServerHello.size())
        {
            const auto Remaining = std::span<std::uint8_t>(ForwardedServerHello).subspan(ServerHelloDone);
            const auto ReadBuffer = std::as_writable_bytes(Remaining);
            const auto ReadOperation = co_await Request.Client->ReadSome(ReadBuffer);
            const auto Count = ReadOperation.Bytes;
            ErrorCode = Prism::Fault::ToNative(ReadOperation.Failure);
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
        const auto FlightHeaderRead = co_await Request.Client->ReadSome(FlightHeaderBuffer);
        const auto FlightHeaderCount = FlightHeaderRead.Bytes;
        ErrorCode = Prism::Fault::ToNative(FlightHeaderRead.Failure);
        EXPECT_EQ(FlightHeaderCount, FlightHeader.size());
        EXPECT_FALSE(ErrorCode);

        const auto FlightLength = (static_cast<std::size_t>(FlightHeader[3]) << 8) | FlightHeader[4];
        std::vector<std::uint8_t> ForwardedFlight(Shadowtls::TlsHdrsize + FlightLength);
        std::copy(FlightHeader.begin(), FlightHeader.end(), ForwardedFlight.begin());
        const auto FlightPayload = std::span<std::uint8_t>(ForwardedFlight).subspan(Shadowtls::TlsHdrsize);
        const auto FlightPayloadBuffer = std::as_writable_bytes(FlightPayload);
        const auto FlightRead = co_await Request.Client->ReadSome(FlightPayloadBuffer);
        const auto FlightCount = FlightRead.Bytes;
        ErrorCode = Prism::Fault::ToNative(FlightRead.Failure);
        EXPECT_EQ(FlightCount, FlightLength);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(ForwardedFlight,
                  (std::vector<std::uint8_t>{0x17, 0x03, 0x03, 0x00, 0x07, 0x46, 0x0E, 0xD6, 0xE8,
                                             0x23, 0xC5, 0x69}));

        const auto ServerRandom = std::span<const std::uint8_t>(Request.ServerHello).subspan(
            11, Shadowtls::TlsRndSize);
        Shadowtls::Detail::RecordProtector FlightDecoder{Shadowtls::Detail::RecordProtectionOptions{
            Request.Password,
            ServerRandom,
            Shadowtls::TagServer,
            Shadowtls::RecordSeed::ServerRandomOnly,
            Shadowtls::Detail::ProtectionMode::ServerFlight}};
        std::vector<std::uint8_t> DecodedFlight;
        EXPECT_EQ(FlightDecoder.Decode(ForwardedFlight, DecodedFlight), Error::None);
        EXPECT_EQ(DecodedFlight, Request.TargetPayload);

        Shadowtls::Detail::RecordProtector ClientEncoder{Shadowtls::Detail::RecordProtectionOptions{
            Request.Password, ServerRandom, Shadowtls::TagClient}};
        std::vector<std::uint8_t> FirstRecord;
        EXPECT_EQ(ClientEncoder.Encode(Request.FirstPayload, FirstRecord), Error::None);
        const auto FirstRecordBytes = std::as_bytes(std::span<const std::uint8_t>(FirstRecord));
        const auto FirstRecordWrite = co_await Request.Client->WriteSome(FirstRecordBytes);
        const auto FirstRecordWritten = FirstRecordWrite.Bytes;
        ErrorCode = Prism::Fault::ToNative(FirstRecordWrite.Failure);
        EXPECT_EQ(FirstRecordWritten, FirstRecord.size());
        EXPECT_FALSE(ErrorCode);

        co_await RunSuccessfulRelayInner(SuccessfulRelayInnerRequest{
            Request,
            RelayResult,
            RelayTask,
            TargetTask,
            std::vector<std::uint8_t>(ServerRandom.begin(), ServerRandom.end()),
            {}});
    }

    auto RunBadClientHello(BadClientHelloRequest Request) -> Net::awaitable<void>
    {
        Shadowtls::ServerOptions Options;
        Options.DialTarget = [DialCalls = Request.DialCalls](
                                 std::span<const std::uint8_t>) -> Net::awaitable<Shadowtls::Result<SharedTransmission>>
        {
            ++*DialCalls;
            co_return std::unexpected(Shadowtls::FailureFromError(Error::IoError));
        };
        auto Relay = std::make_shared<Shadowtls::ServerSession>(std::move(Options));
        auto RelayResult = std::make_shared<std::optional<Shadowtls::Result<Shadowtls::SharedConn>>>();
        const auto RelayTask = SpawnTask(
            Request.Server->Executor(),
            RunRelay(RelayRequest{
                Relay,
                Request.Server,
                Shadowtls::ServerConfig{Request.Password},
                RelayResult}));

        const auto ClientHelloBytes = std::as_bytes(std::span<const std::uint8_t>(Request.ClientHello));
        std::error_code ErrorCode;
        const auto ClientHelloWrite = co_await Request.Client->WriteSome(ClientHelloBytes);
        const auto ClientHelloWritten = ClientHelloWrite.Bytes;
        ErrorCode = Prism::Fault::ToNative(ClientHelloWrite.Failure);
        EXPECT_EQ(ClientHelloWritten, Request.ClientHello.size());
        EXPECT_FALSE(ErrorCode);

        co_await WaitForTask(RelayTask);
        EXPECT_TRUE(RelayResult->has_value());
        if (!RelayResult->has_value())
        {
            co_return;
        }
        EXPECT_FALSE(**RelayResult);
        EXPECT_EQ(Shadowtls::ToProtocolError((**RelayResult).error().Code), Error::BadAuth);
        EXPECT_EQ(*Request.DialCalls, 0U);
        co_await CloseTransport(Request.Client);
        co_await CloseTransport(Request.Server);
        co_return;
    }

    auto RunTargetDialFailure(TargetDialFailureRequest Request) -> Net::awaitable<void>
    {
        Shadowtls::ServerOptions Options;
        Options.DialTarget = [](std::span<const std::uint8_t>)
            -> Net::awaitable<Shadowtls::Result<SharedTransmission>>
        {
            co_return std::unexpected(Shadowtls::FailureFromError(Error::IoError));
        };
        auto Relay = std::make_shared<Shadowtls::ServerSession>(std::move(Options));
        auto RelayResult = std::make_shared<std::optional<Shadowtls::Result<Shadowtls::SharedConn>>>();
        const auto RelayTask = SpawnTask(
            Request.Server->Executor(),
            RunRelay(RelayRequest{
                Relay,
                Request.Server,
                Shadowtls::ServerConfig{Request.Password},
                RelayResult}));

        const auto ClientHelloBytes = std::as_bytes(std::span<const std::uint8_t>(Request.ClientHello));
        std::error_code ErrorCode;
        const auto ClientHelloWrite = co_await Request.Client->WriteSome(ClientHelloBytes);
        const auto ClientHelloWritten = ClientHelloWrite.Bytes;
        ErrorCode = Prism::Fault::ToNative(ClientHelloWrite.Failure);
        EXPECT_EQ(ClientHelloWritten, Request.ClientHello.size());
        EXPECT_FALSE(ErrorCode);

        co_await WaitForTask(RelayTask);
        EXPECT_TRUE(RelayResult->has_value());
        if (!RelayResult->has_value())
        {
            co_return;
        }
        EXPECT_FALSE(**RelayResult);
        EXPECT_EQ(Shadowtls::ToProtocolError((**RelayResult).error().Code), Error::IoError);
        EXPECT_TRUE((**RelayResult).error().Native);
        std::array<std::byte, 1> Buffer{};
        const auto CloseRead = co_await Request.Client->ReadSome(Buffer);
        const auto Count = CloseRead.Bytes;
        ErrorCode = Prism::Fault::ToNative(CloseRead.Failure);
        EXPECT_EQ(CloseRead.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Count, 0U);
        co_await CloseTransport(Request.Client);
        co_await CloseTransport(Request.Server);
        co_return;
    }

    auto RunBadApplication(BadApplicationRequest Request) -> Net::awaitable<void>
    {
        Shadowtls::ServerOptions Options;
        Options.DialTarget = [TargetClient = Request.TargetClient](
                                 std::span<const std::uint8_t>) -> Net::awaitable<Shadowtls::Result<SharedTransmission>>
        {
            co_return TargetClient;
        };
        auto Relay = std::make_shared<Shadowtls::ServerSession>(std::move(Options));
        auto RelayResult = std::make_shared<std::optional<Shadowtls::Result<Shadowtls::SharedConn>>>();
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
        const auto ClientHelloWrite = co_await Request.Client->WriteSome(ClientHelloBytes);
        const auto ClientHelloWritten = ClientHelloWrite.Bytes;
        ErrorCode = Prism::Fault::ToNative(ClientHelloWrite.Failure);
        EXPECT_EQ(ClientHelloWritten, Request.ClientHello.size());
        EXPECT_FALSE(ErrorCode);

        std::array<std::byte, 4096> Buffer{};
        const auto ServerHelloRead = co_await Request.Client->ReadSome(Buffer);
        const auto ServerHelloCount = ServerHelloRead.Bytes;
        ErrorCode = Prism::Fault::ToNative(ServerHelloRead.Failure);
        EXPECT_EQ(ServerHelloCount, Request.ServerHello.size());
        EXPECT_FALSE(ErrorCode);

        const auto ServerRandom = std::span<const std::uint8_t>(Request.ServerHello).subspan(
            11, Shadowtls::TlsRndSize);
        Shadowtls::Detail::RecordProtector WrongEncoder{Shadowtls::Detail::RecordProtectionOptions{
            "wrong-password", ServerRandom, Shadowtls::TagClient}};
        std::vector<std::uint8_t> BadRecord;
        EXPECT_EQ(WrongEncoder.Encode(Request.Payload, BadRecord), Error::None);
        const auto BadRecordBytes = std::as_bytes(std::span<const std::uint8_t>(BadRecord));
        const auto BadRecordWrite = co_await Request.Client->WriteSome(BadRecordBytes);
        const auto BadRecordWritten = BadRecordWrite.Bytes;
        ErrorCode = Prism::Fault::ToNative(BadRecordWrite.Failure);
        EXPECT_EQ(BadRecordWritten, BadRecord.size());
        EXPECT_FALSE(ErrorCode);

        co_await WaitForTask(TargetTask);
        co_await WaitForTask(RelayTask);
        EXPECT_TRUE(RelayResult->has_value());
        if (!RelayResult->has_value())
        {
            co_return;
        }
        EXPECT_FALSE(**RelayResult);
        co_await CloseTransport(Request.Client);
        co_await CloseTransport(Request.Server);
        co_await CloseTransport(Request.TargetClient);
        co_await CloseTransport(Request.Target);
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
