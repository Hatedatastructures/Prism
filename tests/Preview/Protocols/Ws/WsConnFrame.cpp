/**
 * @file WsConnFrame.cpp
 * @brief 验证 WebSocket 数据帧编解码、协议拒绝与 Ping/Pong 关闭链。
 */
#include "WsFactorySupport.hpp"
#include "WsConnSessionSupport.hpp"
#include <boost/asio/io_context.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Ws/Detail/Codec.hpp>
#include <Preview/Protocols/Ws/Ws.hpp>
#include <gtest/gtest.h>
namespace
{
    namespace Net = boost::asio;
    namespace Ws = Preview::Ws;
    namespace TestSupport = Preview::Tests::WsConnSessionSupport;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using TestSupport::CloseAndWait;
    using TestSupport::WaitThenClose;
    using TestSupport::EagerTask;
    using TestSupport::MaskedFrameRequest;
    using TestSupport::PairCompletion;
    using TestSupport::RunCoro;
    using TestSupport::SpawnEager;
    using TestSupport::StreamPairRequest;
    using TestSupport::TestKey;

    /**
     * @brief 按 wire 长度读取完整帧，允许头与载荷经不同 partial I/O 交付。
     * @param Transport 借用原 executor 上的内存端点至本协程返回。
     * @param Buffer 借用调用方帧缓冲；容量不足保留明确失败，不截断输入。
     * @return 已接收字节数与首个原生失败；不改变端点关闭责任。
     */
    [[nodiscard]] auto ReadWireFrame(MemoryStream &Transport, std::span<std::byte> Buffer)
        -> Net::awaitable<Preview::IoResult>
    {
        if (Buffer.size() < 2)
        {
            co_return Preview::IoResult{0, {Preview::Fault::Code::InvalidArgument}};
        }
        auto Result = co_await Transport.ReadExact(Buffer.first(2));
        if (Result.Failure.Failed())
        {
            co_return Result;
        }
        const auto LengthCode = std::to_integer<std::uint8_t>(Buffer[1]) & 0x7FU;
        std::size_t HeaderSize = 2;
        if (LengthCode == 126U)
        {
            HeaderSize += 2;
        }
        else if (LengthCode == 127U)
        {
            HeaderSize += 8;
        }
        if ((std::to_integer<std::uint8_t>(Buffer[1]) & 0x80U) != 0)
        {
            HeaderSize += 4;
        }
        if (HeaderSize > Buffer.size())
        {
            Result.Failure = Preview::Fault::FromNative(Preview::make_error_code(Error::BadLength));
            co_return Result;
        }
        const auto HeaderTail = co_await Transport.ReadExact(Buffer.subspan(2, HeaderSize - 2));
        Result.Bytes += HeaderTail.Bytes;
        if (HeaderTail.Failure.Failed())
        {
            Result.Failure = HeaderTail.Failure;
            co_return Result;
        }
        Ws::Detail::FrameHeader Header;
        if (!Ws::Detail::ParseFrameHeader(Buffer.first(HeaderSize), Header))
        {
            Result.Failure = Preview::Fault::FromNative(Preview::make_error_code(Error::BadMessage));
            co_return Result;
        }
        if (Header.PayloadLen > Buffer.size() - HeaderSize)
        {
            Result.Failure = Preview::Fault::FromNative(Preview::make_error_code(Error::BadLength));
            co_return Result;
        }
        const auto Payload = co_await Transport.ReadExact(
            Buffer.subspan(HeaderSize, static_cast<std::size_t>(Header.PayloadLen)));
        Result.Bytes += Payload.Bytes;
        Result.Failure = Payload.Failure;
        co_return Result;
    }
    /** @brief 服务端完成 Upgrade 后解码 masked binary frame。 */
    auto RunMaskedBinaryServer(std::shared_ptr<MemoryStream> Server,
                               std::string Payload,
                               std::shared_ptr<bool> Result)
        -> Net::awaitable<void>
    {
        auto Accepted = co_await Preview::Ws::Accept(
            Preview::Tests::WsFactorySupport::MakeAcceptOptionsForTest(
                Server, Ws::ServerOptions{}));
        EXPECT_TRUE(Accepted);
        if (!Accepted)
        {
            co_return;
        }
        EXPECT_EQ(Accepted->Key, TestKey);
        auto Connection = std::move(Accepted->Connection);
        std::array<std::byte, 128> Buffer{};
        std::error_code ErrorCode;
        const auto Read = co_await Connection->ReadSome(Buffer);
        ErrorCode = Preview::Fault::ToNative(Read.Failure);
        const auto Count = Read.Bytes;
        *Result = !ErrorCode && Count == Payload.size() &&
                  std::memcmp(Buffer.data(), Payload.data(), Payload.size()) == 0;
        const auto CloseResult = Connection->Close();
        EXPECT_TRUE(CloseResult);
        const auto DrainResult = co_await Connection->Activity()->Drain();
        EXPECT_TRUE(DrainResult);
    }
    /** @brief 发送 masked binary frame 并等待服务端结果。 */
    auto RunServerDecodesMaskedBinaryFrame(MaskedFrameRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Pair.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Pair.Server));
        auto ServerTask = SpawnEager(
            Server->Executor(), RunMaskedBinaryServer(Server, Request.Payload,
                                                       Request.Result));
        bool InputComplete = false;
        std::exception_ptr ParentFailure;
        try
        {
            const std::string Upgrade =
                "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\nSec-WebSocket-Key: " +
                std::string(TestKey) + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
            std::error_code ErrorCode;
            const auto Write = co_await Client->WriteSome(AsBytes(AsU8Span(Upgrade)));
            ErrorCode = Preview::Fault::ToNative(Write.Failure);
            EXPECT_FALSE(ErrorCode);
            std::array<std::byte, 256> Response{};
            const auto Read = co_await Client->ReadSome(Response);
            ErrorCode = Preview::Fault::ToNative(Read.Failure);
            const auto ResponseSize = Read.Bytes;
            EXPECT_FALSE(ErrorCode);
            EXPECT_GT(ResponseSize, 0U);
            if (!ErrorCode && ResponseSize > 0)
            {
                std::vector<std::byte> Frame;
                Frame.reserve(2 + 4 + Request.Payload.size());
                Frame.push_back(std::byte{0x82});
                Frame.push_back(static_cast<std::byte>(0x80U | Request.Payload.size()));
                const std::array<std::uint8_t, 4> Mask{0x01, 0x02, 0x03, 0x04};
                for (const auto Byte : Mask)
                {
                    Frame.push_back(static_cast<std::byte>(Byte));
                }
                for (std::size_t Index = 0; Index < Request.Payload.size(); ++Index)
                {
                    Frame.push_back(static_cast<std::byte>(
                        static_cast<std::uint8_t>(Request.Payload[Index]) ^
                        Mask[Index % Mask.size()]));
                }
                const auto FrameWrite = co_await Client->WriteSome(Frame);
                ErrorCode = Preview::Fault::ToNative(FrameWrite.Failure);
                EXPECT_FALSE(ErrorCode);
                InputComplete = !ErrorCode && FrameWrite.Bytes == Frame.size();
            }
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        if (InputComplete)
        {
            co_await WaitThenClose(PairCompletion{Client, Server, std::move(ServerTask)});
        }
        else
        {
            co_await CloseAndWait(PairCompletion{Client, Server, std::move(ServerTask)});
        }
        EXPECT_TRUE(*Request.Result);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    /** @brief 原始服务端回复 Upgrade 并核对 client 发出的 mask。 */
    auto RunMaskedFrameServer(std::shared_ptr<MemoryStream> Server,
                              std::string Payload,
                              std::shared_ptr<bool> Result)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 1024> Request{};
        std::error_code ErrorCode;
        const auto Read = co_await Server->ReadSome(Request);
        ErrorCode = Preview::Fault::ToNative(Read.Failure);
        const auto RequestSize = Read.Bytes;
        if (ErrorCode || RequestSize == 0)
        {
            co_return;
        }
        const auto Accept = Ws::Detail::ComputeAccept(TestKey);
        const std::string Response =
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Accept: " + Accept + "\r\n\r\n";
        const auto ResponseWrite = co_await Server->WriteSome(AsBytes(AsU8Span(Response)));
        ErrorCode = Preview::Fault::ToNative(ResponseWrite.Failure);
        if (ErrorCode)
        {
            co_return;
        }
        std::array<std::byte, 1024> Wire{};
        const auto WireRead = co_await ReadWireFrame(*Server, Wire);
        ErrorCode = Preview::Fault::ToNative(WireRead.Failure);
        const auto WireSize = WireRead.Bytes;
        Ws::Detail::FrameHeader Header;
        if (!ErrorCode && Ws::Detail::ParseFrameHeader(
                               std::span<const std::byte>(Wire.data(), WireSize), Header) &&
            Header.Masked && Header.Fin &&
            Header.Opcode == static_cast<std::uint8_t>(Ws::Detail::Opcode::Binary) &&
            Header.HeaderLen + Header.PayloadLen <= WireSize &&
            Header.PayloadLen == Payload.size())
        {
            std::vector<std::byte> Decoded(
                Wire.begin() + static_cast<std::ptrdiff_t>(Header.HeaderLen),
                Wire.begin() + static_cast<std::ptrdiff_t>(Header.HeaderLen + Header.PayloadLen));
            Ws::Detail::ApplyMask(Decoded, Header.MaskKey);
            *Result = std::memcmp(Decoded.data(), Payload.data(), Payload.size()) == 0;
        }
    }
    /** @brief 驱动 Ws::Connect 并验证客户端自动 mask。 */
    auto RunClientWritesMaskedBinaryFrame(MaskedFrameRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Pair.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Pair.Server));
        auto ServerTask = SpawnEager(
            Server->Executor(), RunMaskedFrameServer(Server, Request.Payload,
                                                      Request.Result));
        bool InputComplete = false;
        std::exception_ptr ParentFailure;
        std::shared_ptr<Ws::StreamTransport> Connection;
        try
        {
            const Ws::ClientOptions Config{"example.com", TestKey};
            auto Connected = co_await Preview::Ws::Connect(
                Preview::Tests::WsFactorySupport::MakeConnectOptionsForTest(
                    Client, Config));
            EXPECT_TRUE(Connected);
            if (Connected)
            {
                Connection = std::move(Connected->Connection);
            }
            if (Connection)
            {
                std::error_code ErrorCode;
                const auto Write = co_await Connection->WriteSome(AsBytes(AsU8Span(Request.Payload)));
                ErrorCode = Preview::Fault::ToNative(Write.Failure);
                EXPECT_FALSE(ErrorCode);
                InputComplete = !ErrorCode && Write.Bytes == Request.Payload.size();
            }
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        if (InputComplete)
        {
            co_await WaitThenClose(PairCompletion{Client, Server, std::move(ServerTask)});
        }
        else
        {
            co_await CloseAndWait(PairCompletion{Client, Server, std::move(ServerTask)});
        }
        if (Connection)
        {
            const auto CloseResult = Connection->Close();
            EXPECT_TRUE(CloseResult);
            const auto DrainResult = co_await Connection->Activity()->Drain();
            EXPECT_TRUE(DrainResult);
        }
        EXPECT_TRUE(*Request.Result);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    /** @brief 服务端接收一帧并把协议错误映射到 Error。 */
    auto RunUnmaskedServer(std::shared_ptr<MemoryStream> Server,
                           std::shared_ptr<Preview::Fault::Code> Result)
        -> Net::awaitable<void>
    {
        auto Accepted = co_await Preview::Ws::Accept(
            Preview::Tests::WsFactorySupport::MakeAcceptOptionsForTest(
                Server, Ws::ServerOptions{}));
        if (!Accepted)
        {
            *Result = Accepted.error().Code;
            co_return;
        }
        auto Connection = std::move(Accepted->Connection);
        std::array<std::byte, 64> Buffer{};
        std::error_code ErrorCode;
        const auto Read = co_await Connection->ReadSome(Buffer);
        ErrorCode = Preview::Fault::ToNative(Read.Failure);
        if (ErrorCode)
        {
            *Result = Read.Failure.Code;
        }
        const auto CloseResult = Connection->Close();
        EXPECT_TRUE(CloseResult);
        const auto DrainResult = co_await Connection->Activity()->Drain();
        EXPECT_TRUE(DrainResult);
    }
    /** @brief 发送未掩码客户端帧并等待服务端 BadMessage。 */
    auto RunServerRejectsUnmaskedClientFrame(
        StreamPairRequest Request) -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto Result = std::make_shared<Preview::Fault::Code>(
            Preview::Fault::Code::Success);
        auto ServerTask = SpawnEager(Server->Executor(),
                                     RunUnmaskedServer(Server, Result));
        bool InputComplete = false;
        std::exception_ptr ParentFailure;
        try
        {
            const std::string Upgrade =
                "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\nSec-WebSocket-Key: " +
                std::string(TestKey) + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
            std::error_code ErrorCode;
            const auto UpgradeWrite = co_await Client->WriteSome(AsBytes(AsU8Span(Upgrade)));
            ErrorCode = Preview::Fault::ToNative(UpgradeWrite.Failure);
            EXPECT_FALSE(ErrorCode);
            std::array<std::byte, 256> Response{};
            const auto Read = co_await Client->ReadSome(Response);
            ErrorCode = Preview::Fault::ToNative(Read.Failure);
            EXPECT_FALSE(ErrorCode);
            const std::array<std::byte, 3> UnmaskedFrame{
                std::byte{0x82}, std::byte{0x01}, std::byte{'x'}};
            const auto FrameWrite = co_await Client->WriteSome(UnmaskedFrame);
            ErrorCode = Preview::Fault::ToNative(FrameWrite.Failure);
            EXPECT_FALSE(ErrorCode);
            InputComplete = !ErrorCode && FrameWrite.Bytes == UnmaskedFrame.size();
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        if (InputComplete)
        {
            co_await WaitThenClose(PairCompletion{Client, Server, std::move(ServerTask)});
        }
        else
        {
            co_await CloseAndWait(PairCompletion{Client, Server, std::move(ServerTask)});
        }
        EXPECT_EQ(*Result, Preview::Fault::Code::BadMessage);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    /** @brief 服务端接受 Upgrade 后读取 ping，触发协议 Pong。 */
    auto RunPingServer(std::shared_ptr<MemoryStream> Server) -> Net::awaitable<void>
    {
        auto Accepted = co_await Preview::Ws::Accept(
            Preview::Tests::WsFactorySupport::MakeAcceptOptionsForTest(
                Server, Ws::ServerOptions{}));
        if (!Accepted)
        {
            co_return;
        }
        auto Connection = std::move(Accepted->Connection);
        std::array<std::byte, 64> Buffer{};
        std::error_code ErrorCode;
        const auto Read = co_await Connection->ReadSome(Buffer);
        ErrorCode = Preview::Fault::ToNative(Read.Failure);
        const auto CloseResult = Connection->Close();
        EXPECT_TRUE(CloseResult);
        const auto DrainResult = co_await Connection->Activity()->Drain();
        EXPECT_TRUE(DrainResult);
    }
    /** @brief 发送 masked ping、校验 pong 并完成真实 close。 */
    auto RunServerRepliesToMaskedPing(StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = SpawnEager(Server->Executor(), RunPingServer(Server));
        const std::string PingPayload = "ping";
        bool PongOk = false;
        std::exception_ptr ParentFailure;
        try
        {
            const std::string Upgrade =
                "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\nSec-WebSocket-Key: " +
                std::string(TestKey) + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
            std::error_code ErrorCode;
            const auto UpgradeWrite = co_await Client->WriteSome(AsBytes(AsU8Span(Upgrade)));
            ErrorCode = Preview::Fault::ToNative(UpgradeWrite.Failure);
            EXPECT_FALSE(ErrorCode);
            std::array<std::byte, 256> Response{};
            const auto ResponseRead = co_await Client->ReadSome(Response);
            ErrorCode = Preview::Fault::ToNative(ResponseRead.Failure);
            EXPECT_FALSE(ErrorCode);

            const std::array<std::uint8_t, 4> Mask{0xA1, 0xB2, 0xC3, 0xD4};
            std::vector<std::byte> PingFrame{
                std::byte{0x89}, static_cast<std::byte>(0x80U | PingPayload.size())};
            PingFrame.insert(PingFrame.end(),
                             reinterpret_cast<const std::byte *>(Mask.data()),
                             reinterpret_cast<const std::byte *>(Mask.data() + Mask.size()));
            for (std::size_t Index = 0; Index < PingPayload.size(); ++Index)
            {
                PingFrame.push_back(static_cast<std::byte>(
                    static_cast<std::uint8_t>(PingPayload[Index]) ^ Mask[Index % Mask.size()]));
            }
            const auto PingWrite = co_await Client->WriteSome(PingFrame);
            ErrorCode = Preview::Fault::ToNative(PingWrite.Failure);
            EXPECT_FALSE(ErrorCode);

            std::array<std::byte, 64> PongFrame{};
            const auto PongRead = co_await ReadWireFrame(*Client, PongFrame);
            ErrorCode = Preview::Fault::ToNative(PongRead.Failure);
            const auto PongSize = PongRead.Bytes;
            Ws::Detail::FrameHeader Header;
            if (!ErrorCode && Ws::Detail::ParseFrameHeader(
                                   std::span<const std::byte>(PongFrame.data(), PongSize), Header) &&
                !Header.Masked && Header.Fin &&
                Header.Opcode == static_cast<std::uint8_t>(Ws::Detail::Opcode::Pong) &&
                Header.HeaderLen + Header.PayloadLen <= PongSize &&
                Header.PayloadLen == PingPayload.size())
            {
                PongOk = std::memcmp(PongFrame.data() + Header.HeaderLen,
                                     PingPayload.data(), PingPayload.size()) == 0;
            }
            const std::array<std::byte, 6> CloseFrame{
                std::byte{0x88}, std::byte{0x80}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}};
            const auto CloseWrite = co_await Client->WriteSome(CloseFrame);
            ErrorCode = Preview::Fault::ToNative(CloseWrite.Failure);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        co_await CloseAndWait(PairCompletion{Client, Server, std::move(ServerTask)});
        EXPECT_TRUE(PongOk);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    TEST(WsConnSession, ServerDecodesMaskedBinaryFrame)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunServerDecodesMaskedBinaryFrame(MaskedFrameRequest{
                               {std::move(Client), std::move(Server)},
                               "masked websocket payload",
                               std::make_shared<bool>(false)}));
    }

    TEST(WsConnSession, ClientWritesMaskedBinaryFrame)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunClientWritesMaskedBinaryFrame(MaskedFrameRequest{
                               {std::move(Client), std::move(Server)},
                               "client mask wire payload",
                               std::make_shared<bool>(false)}));
    }

    TEST(WsConnSession, ServerRejectsUnmaskedClientFrame)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunServerRejectsUnmaskedClientFrame(
                               StreamPairRequest{std::move(Client), std::move(Server)}));
    }

    TEST(WsConnSession, ServerRepliesToMaskedPing)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunServerRepliesToMaskedPing(
                               StreamPairRequest{std::move(Client), std::move(Server)}));
    }

}
