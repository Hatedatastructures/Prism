/**
 * @file RestlsConnSession.cpp
 * @brief Restls Conn 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手（同一 ServerRandom）→ 双向回显
 * 2. 客户端与服务端使用派生密钥完成双向数据交换
 * 3. 错误分支：bad_length（ServerRandom 长度非法）/ not_open（未握手读写）
 * 4. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <chrono>
#include <cstring>
#include <exception>
#include <memory>
#include <system_error>
#include <string>
#include <utility>
#include <vector>

#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Restls/Detail/Codec.hpp>
#include <Prism/Protocols/Restls/Detail/Conn.hpp>
#include <Prism/Protocols/Restls/Detail/Retirement.hpp>
#include <Prism/Protocols/Restls/Detail/WireIo.hpp>
#include <Prism/Protocols/Restls/Restls.hpp>
#include <Prism/Protocols/Restls/Types.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Restls = Prism::Restls;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;

    auto RetireAndVerify(Prism::SharedTransmission Transport) -> Net::awaitable<void>
    {
        const auto Retired = co_await Restls::Detail::TransportRetirement::RetireAndDrain(
            std::move(Transport));
        EXPECT_TRUE(Retired);
    }

    class FailingRestlsTransport final : public Prism::Transmission
    {
    public:
        FailingRestlsTransport(Net::any_io_executor Executor, std::error_code Native)
            : Transmission(std::move(Executor)), Native_(Native) {}

        /** @brief 设置测试传输下一次写入已完成的底层字节数。 */
        auto SetWriteProgress(std::size_t Bytes) noexcept -> void { WriteProgress_ = Bytes; }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {0, {Prism::Fault::Code::Canceled}});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler),
                {WriteProgress_, Prism::Fault::FromNative(Native_)});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {0, Prism::Fault::FromNative(Native_)});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override { return {}; }
        [[nodiscard]] auto OnCancel() -> ControlResult override { return {}; }

    private:
        std::error_code Native_;
        std::size_t WriteProgress_{0};
    };

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

    /// 运行已拥有完整 frame 的协程直至自然耗尽（异常重抛）。
    auto RunCoro(Net::io_context &IoContext, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Operation),
                      [&Exception](std::exception_ptr ErrorValue)
                      { Exception = ErrorValue; });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    struct RestlsEchoServerRequest final
    {
        std::shared_ptr<MemoryStream> Transport;
        std::array<std::uint8_t, 32> ServerRandom;
        std::string Payload;
    };

    auto RunRestlsEchoServer(RestlsEchoServerRequest Request) -> Net::awaitable<void>
    {
        Restls::ServerConfig ServerConfig{"pw123456"};
        auto Accepted = co_await Restls::Accept(
            std::move(Request.Transport), ServerConfig, Request.ServerRandom);
        if (!Accepted || !*Accepted)
        {
            EXPECT_TRUE(false) << "Accept Failed";
            co_return;
        }
        auto Connection = std::move(*Accepted);
        std::array<std::byte, 1024> Buffer{};
        std::error_code ErrorCode;
        const auto ReadResult = co_await Connection->ReadSome(Buffer);
        ErrorCode = Prism::Fault::ToNative(ReadResult.Failure);
        const auto ReadSize = ReadResult.Bytes;
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), ReadSize), Request.Payload);
        const auto PayloadWrite = co_await Connection->WriteSome(
            std::span<const std::byte>(Buffer.data(), ReadSize));
        ErrorCode = Prism::Fault::ToNative(PayloadWrite.Failure);
        EXPECT_FALSE(ErrorCode);
        const std::string FollowupPayload = "restls followup";
        std::array<std::byte, 1024> FollowupBuffer{};
        const auto FollowupReadResult = co_await Connection->ReadSome(FollowupBuffer);
        ErrorCode = Prism::Fault::ToNative(FollowupReadResult.Failure);
        const auto FollowupRead = FollowupReadResult.Bytes;
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(FollowupBuffer.data()), FollowupRead),
                  FollowupPayload);
        const std::string FollowupResponse = "restls response";
        const auto FollowupWrite = co_await Connection->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(FollowupResponse.data()),
                                       FollowupResponse.size()));
        ErrorCode = Prism::Fault::ToNative(FollowupWrite.Failure);
        EXPECT_FALSE(ErrorCode);
        co_await RetireAndVerify(Connection);
    }

    struct RestlsEchoClientRequest final
    {
        MemoryStream ClientMemory;
        MemoryStream ServerMemory;
        std::array<std::uint8_t, 32> ServerRandom;
        std::string Payload;
    };

    auto RunRestlsEchoClient(RestlsEchoClientRequest Request) -> Net::awaitable<void>
    {
        const auto ServerDone = std::make_shared<CompletionState>(Request.ClientMemory.Executor());
        Net::co_spawn(
            Request.ClientMemory.Executor(),
            RunRestlsEchoServer(RestlsEchoServerRequest{
                std::make_shared<MemoryStream>(std::move(Request.ServerMemory)),
                Request.ServerRandom, Request.Payload}),
            [ServerDone](std::exception_ptr Failure)
            { RecordCompletion(ServerDone, Failure); });

        auto ClientTransport = std::make_shared<MemoryStream>(std::move(Request.ClientMemory));
        Restls::ClientConfig ClientConfig{"pw123456"};
        auto Connected = co_await Restls::Connect(
            std::move(ClientTransport), ClientConfig, Request.ServerRandom);
        EXPECT_TRUE(Connected);
        if (!Connected || !*Connected)
        {
            co_await AwaitCompletion(ServerDone);
            co_return;
        }
        auto Client = std::move(*Connected);
        std::error_code ErrorCode;
        const auto PayloadWrite = co_await Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.Payload.data()),
                                       Request.Payload.size()));
        ErrorCode = Prism::Fault::ToNative(PayloadWrite.Failure);
        EXPECT_FALSE(ErrorCode);
        std::array<std::byte, 1024> Buffer{};
        const auto ReadResult = co_await Client->ReadSome(Buffer);
        ErrorCode = Prism::Fault::ToNative(ReadResult.Failure);
        const auto ReadSize = ReadResult.Bytes;
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), ReadSize), Request.Payload);
        const std::string FollowupPayload = "restls followup";
        const auto FollowupWrite = co_await Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(FollowupPayload.data()),
                                       FollowupPayload.size()));
        ErrorCode = Prism::Fault::ToNative(FollowupWrite.Failure);
        EXPECT_FALSE(ErrorCode);
        const auto FollowupReadResult = co_await Client->ReadSome(Buffer);
        ErrorCode = Prism::Fault::ToNative(FollowupReadResult.Failure);
        const auto FollowupRead = FollowupReadResult.Bytes;
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), FollowupRead),
                  "restls response");
        co_await RetireAndVerify(Client);
        co_await AwaitCompletion(ServerDone);
    }

    struct ServerReadResult final
    {
        std::size_t Count{0};
        std::error_code Error;
    };

    struct ClientReadResult final
    {
        std::vector<std::uint8_t> Data;
        std::error_code Error;
    };

    auto RunServerRead(std::shared_ptr<Restls::Detail::Conn<>> Connection,
                       const std::shared_ptr<ServerReadResult> &Result) -> Net::awaitable<void>
    {
        std::array<std::byte, 128> Buffer{};
        const auto ReadResult = co_await Connection->ReadSome(Buffer);
        Result->Error = Prism::Fault::ToNative(ReadResult.Failure);
        Result->Count = ReadResult.Bytes;
    }

    auto RunClientRead(const std::shared_ptr<MemoryStream> &Transport,
                       const std::shared_ptr<ClientReadResult> &Result) -> Net::awaitable<void>
    {
        std::array<std::byte, 128> Buffer{};
        const auto Read = co_await Transport->ReadSome(Buffer);
        Result->Error = Prism::Fault::ToNative(Read.Failure);
        const auto Count = Read.Bytes;
        Result->Data.resize(Count);
        if (Count > 0)
        {
            std::memcpy(Result->Data.data(), Buffer.data(), Count);
        }
    }

    struct RestlsResponseRequest final
    {
        MemoryStream ClientMemory;
        MemoryStream ServerMemory;
        std::array<std::uint8_t, 32> ServerRandom;
        std::vector<std::uint8_t> ClientFinished;
    };

    auto RunRestlsResponseScenario(RestlsResponseRequest Request) -> Net::awaitable<void>
    {
        auto ClientTransport = std::make_shared<MemoryStream>(std::move(Request.ClientMemory));
        auto ServerTransport = std::make_shared<MemoryStream>(std::move(Request.ServerMemory));
        ClientTransport->SetTimeout(std::chrono::seconds(1));
        ServerTransport->SetTimeout(std::chrono::seconds(1));
        auto ServerConnection = std::make_shared<Restls::Detail::Conn<>>(ServerTransport, "pw");
        const auto Handshake = co_await ServerConnection->ReadHandshake(
            Request.ServerRandom, Request.ClientFinished);
        EXPECT_TRUE(Handshake);

        const auto Secret = Restls::Detail::DeriveSecret("pw");
        const auto [BuildError, CommandFrame] = Restls::Detail::BuildFrame(Restls::Detail::FrameOptions{
            .Secret = Secret,
            .ServerRandom = Request.ServerRandom,
            .Direction = Restls::FlowDirection::ToServer,
            .Counter = 0,
            .ClientFinished = Request.ClientFinished,
            .Data = {},
            .PaddingLength = 0,
            .Command = Restls::CmdTypeResponse,
            .CommandArgument = 1});
        EXPECT_EQ(BuildError, Error::None);
        if (BuildError != Error::None)
        {
            co_await RetireAndVerify(ServerConnection);
            co_await RetireAndVerify(ClientTransport);
            co_return;
        }

        const auto ServerResult = std::make_shared<ServerReadResult>();
        const auto ClientResult = std::make_shared<ClientReadResult>();
        const auto ServerDone = std::make_shared<CompletionState>(ServerTransport->Executor());
        const auto ClientDone = std::make_shared<CompletionState>(ClientTransport->Executor());
        Net::co_spawn(ServerConnection->Executor(), RunServerRead(ServerConnection, ServerResult),
                      [ServerDone](std::exception_ptr Failure)
                      { RecordCompletion(ServerDone, Failure); });
        Net::co_spawn(ClientTransport->Executor(), RunClientRead(ClientTransport, ClientResult),
                      [ClientDone](std::exception_ptr Failure)
                      { RecordCompletion(ClientDone, Failure); });

        auto Sent = co_await Restls::Detail::SendAllWire(
            ClientTransport, std::span<const std::uint8_t>(CommandFrame));
        EXPECT_TRUE(Sent);
        co_await AwaitCompletion(ServerDone);
        EXPECT_EQ(ServerResult->Count, 0U);
        EXPECT_TRUE(ServerResult->Error);
        co_await AwaitCompletion(ClientDone);
        EXPECT_FALSE(ClientResult->Error);
        Restls::Detail::DecodedFrame Decoded;
        EXPECT_EQ(Restls::Detail::DecodeFrame(
                      ClientResult->Data,
                      Restls::Detail::DecodeOptions{
                          .Secret = Secret,
                          .ServerRandom = Request.ServerRandom,
                          .Direction = Restls::FlowDirection::ToClient,
                          .Counter = 0,
                          .ClientFinished = {}},
                      Decoded),
                  Error::None);
        EXPECT_EQ(Decoded.Command, Restls::CmdTypeResponse);
        EXPECT_EQ(Decoded.CommandArgument, 1U);
        EXPECT_TRUE(Decoded.Data.empty());
        co_await RetireAndVerify(ServerConnection);
        co_await RetireAndVerify(ClientTransport);
    }

    auto RunRestlsBadLengthScenario(MemoryStream ClientMemory, MemoryStream ServerMemory)
        -> Net::awaitable<void>
    {
        const std::array<std::uint8_t, 31> ShortRandom{};
        Restls::ClientConfig ClientConfig{"pw"};
        auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
        const auto Connected = co_await Restls::Connect(
            std::move(ClientTransport), ClientConfig, std::span<const std::uint8_t>(ShortRandom));
        EXPECT_FALSE(Connected);
        if (Connected) co_return;
        EXPECT_EQ(Connected.error().Code, Error::BadLength);
        auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto Connection = std::make_shared<Restls::Detail::Conn<>>(std::move(ServerTransport), "pw");
        const std::array<std::uint8_t, 33> LongRandom{};
        const auto Handshake = co_await Connection->ReadHandshake(
            std::span<const std::uint8_t>(LongRandom));
        EXPECT_FALSE(Handshake);
        if (Handshake)
        {
            co_await RetireAndVerify(Connection);
            co_return;
        }
        EXPECT_EQ(Handshake.error().Code, Error::BadLength);
        co_await RetireAndVerify(Connection);
    }

    auto RunRestlsNotOpenScenario(MemoryStream ClientMemory) -> Net::awaitable<void>
    {
        auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Connection = std::make_shared<Restls::Detail::Conn<>>(std::move(ClientTransport), "pw");
        std::array<std::byte, 64> Buffer{};
        const auto ReadResult = co_await Connection->ReadSome(Buffer);
        const auto ReadSize = ReadResult.Bytes;
        EXPECT_EQ(ReadSize, 0u);
        EXPECT_EQ(ReadResult.Failure.Code, Prism::Fault::Code::IoError);
        EXPECT_FALSE(ReadResult.Failure.Native);
        const auto Write = co_await Connection->WriteSome(std::span<const std::byte>(Buffer.data(), 4));
        EXPECT_EQ(Write.Failure.Code, Prism::Fault::Code::IoError);
        EXPECT_FALSE(Write.Failure.Native);
        const auto Retired = co_await Restls::Detail::TransportRetirement::RetireAndDrain(Connection);
        EXPECT_TRUE(Retired);
        EXPECT_TRUE(Connection->Executor());
        EXPECT_NE(Connection->NextLayer(), nullptr);
        EXPECT_NE(Connection->lowest_layer<MemoryStream>(), nullptr);
        const Restls::Detail::Conn<> *ConstConnection = Connection.get();
        EXPECT_NE(ConstConnection->NextLayer(), nullptr);
        auto Released = Connection->Release();
        EXPECT_TRUE(Released);
        EXPECT_EQ(Connection->NextLayer(), nullptr);
    }

    auto RunNativeControlFailureScenario(
        const std::shared_ptr<FailingRestlsTransport> &Transport,
        const std::error_code Native) -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Restls::Detail::Conn<>>(Transport, "pw");
        const std::array<std::uint8_t, 32> ServerRandom{};
        const auto Handshake = co_await Connection->WriteHandshake(ServerRandom);
        EXPECT_TRUE(Handshake);
        if (!Handshake) co_return;

        const std::array<std::byte, 1> Payload{std::byte{0x41}};
        const auto Written = co_await Connection->WriteSome(Payload);
        EXPECT_EQ(Written.Failure.Native, Native);
        const auto Shutdown = co_await Connection->WriteShutdown();
        EXPECT_FALSE(Shutdown);
        if (!Shutdown) EXPECT_EQ(Shutdown.error().Native, Native);

        const auto Retired = co_await Restls::Detail::TransportRetirement::RetireAndDrain(Connection);
        EXPECT_TRUE(Retired);
    }

    auto RunNativePartialWriteScenario(
        const std::shared_ptr<FailingRestlsTransport> &Transport,
        const std::error_code Native) -> Net::awaitable<void>
    {
        Transport->SetWriteProgress(3);
        const std::array<std::uint8_t, 8> Payload{};
        const auto Written = co_await Restls::Detail::SendAllWire(
            Transport, std::span<const std::uint8_t>(Payload));
        EXPECT_FALSE(Written);
        if (!Written)
        {
            EXPECT_EQ(Written.error().Code, Error::IoError);
            EXPECT_EQ(Written.error().Native, Native);
            EXPECT_EQ(Written.error().Bytes, 3U);
        }

        const auto Retired = co_await Restls::Detail::TransportRetirement::RetireAndDrain(Transport);
        EXPECT_TRUE(Retired);
    }

    /// 构造 32 字节服务端随机数（固定模式）
    auto MakeServerRandom() -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> Random{};
        for (std::size_t Index = 0; Index < Random.size(); ++Index)
        {
            Random[Index] = static_cast<std::uint8_t>(Index * 5 + 1);
        }
        return Random;
    }

    TEST(RestlsConnSession, HandshakeClientServerEcho)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto ServerRandom = MakeServerRandom();
        const std::string Payload = "restls echo payload";

        RunCoro(IoContext, RunRestlsEchoClient(RestlsEchoClientRequest{
            std::move(ClientMemory), std::move(ServerMemory), ServerRandom, Payload}));
    }

    TEST(RestlsConnSession, RespondsToResponseCommand)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto ServerRandom = MakeServerRandom();
        const std::vector<std::uint8_t> ClientFinished{0x17, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03};

        RunCoro(IoContext, RunRestlsResponseScenario(RestlsResponseRequest{
            std::move(ClientMemory), std::move(ServerMemory), ServerRandom, ClientFinished}));
    }

    TEST(RestlsConnSession, BadLengthRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        RunCoro(IoContext, RunRestlsBadLengthScenario(
            std::move(ClientMemory), std::move(ServerMemory)));
    }

    TEST(RestlsConnSession, NotOpenRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        RunCoro(IoContext, RunRestlsNotOpenScenario(std::move(ClientMemory)));
    }

    TEST(RestlsConnSession, PreservesNativeWriteAndShutdownFailures)
    {
        Net::io_context IoContext;
        const auto Native = std::make_error_code(std::errc::no_buffer_space);
        auto Transport = std::make_shared<FailingRestlsTransport>(
            IoContext.get_executor(), Native);
        RunCoro(IoContext, RunNativeControlFailureScenario(Transport, Native));
    }

    TEST(RestlsConnSession, PreservesNativeWriteProgress)
    {
        Net::io_context IoContext;
        const auto Native = std::make_error_code(std::errc::no_buffer_space);
        auto Transport = std::make_shared<FailingRestlsTransport>(
            IoContext.get_executor(), Native);
        RunCoro(IoContext, RunNativePartialWriteScenario(Transport, Native));
    }

} // namespace
