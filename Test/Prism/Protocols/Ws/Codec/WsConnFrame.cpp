/**
 * @file WsConnFrame.cpp
 * @brief 验证 WebSocket 数据帧编解码、协议拒绝与 Ping/Pong 关闭链。
 */
#include "../Admission/WsFactorySupport.hpp"
#include "../Connection/WsConnSessionSupport.hpp"
#include <boost/asio/io_context.hpp>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Ws/Detail/ConnClose.hpp>
#include <Prism/Protocols/Ws/Detail/ConnFrame.hpp>
#include <Prism/Protocols/Ws/Detail/ConnSession.hpp>
#include <Prism/Protocols/Ws/Detail/ConnTransport.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <algorithm>
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
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Ws/Detail/Codec.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>
#include <gtest/gtest.h>
namespace
{
    namespace Net = boost::asio;
    namespace Ws = Prism::Ws;
    namespace TestSupport = Prism::Tests::WsConnSessionSupport;
    using Prism::AsBytes;
    using Prism::AsU8Span;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using TestSupport::CloseAndWait;
    using TestSupport::WaitThenClose;
    using TestSupport::EagerTask;
    using TestSupport::MaskedFrameRequest;
    using TestSupport::PairCompletion;
    using TestSupport::RunCoro;
    using TestSupport::SpawnEager;
    using TestSupport::StreamPairRequest;
    using TestSupport::TestKey;

    using WsFrameMemory = Prism::Memory::SessionResource<>;

    struct WsFrameReadOutcome final
    {
        bool FirstDelivered{false};
        std::vector<std::byte> FirstPayload;
        std::error_code FirstError;
        bool SecondDelivered{false};
        std::error_code SecondError;
        std::size_t ReadCount{0};
    };

    class WsFrameTerminalTransmission final : public Prism::Transmission
    {
    public:
        WsFrameTerminalTransmission(
            ExecutorType Executor,
            std::vector<std::byte> Input,
            Prism::Fault::Failure Terminal)
            : Transmission(std::move(Executor)), Input_(std::move(Input)),
              Terminal_(Terminal)
        {
        }

        [[nodiscard]] auto ReadCount() const noexcept -> std::size_t
        {
            return ReadCount_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCount_;
            const auto Count = (std::min)(Buffer.size(), Input_.size() - Offset_);
            std::copy_n(Input_.begin() + static_cast<std::ptrdiff_t>(Offset_), Count, Buffer.begin());
            Offset_ += Count;
            const auto Failure = Offset_ == Input_.size() ? Terminal_ : Prism::Fault::Failure{};
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Count, Failure});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        std::vector<std::byte> Input_;
        Prism::Fault::Failure Terminal_;
        std::size_t Offset_{0};
        std::size_t ReadCount_{0};
    };

    [[nodiscard]] auto MakeMaskedBinaryFrame(std::string_view Payload)
        -> std::vector<std::byte>
    {
        constexpr std::array<std::uint8_t, 4> Mask{0x01U, 0x02U, 0x03U, 0x04U};
        std::vector<std::byte> Wire{
            std::byte{0x82U}, static_cast<std::byte>(0x80U | Payload.size())};
        for (const auto Byte : Mask)
        {
            Wire.push_back(static_cast<std::byte>(Byte));
        }
        for (std::size_t Index = 0; Index < Payload.size(); ++Index)
        {
            Wire.push_back(static_cast<std::byte>(
                static_cast<std::uint8_t>(Payload[Index]) ^ Mask[Index % Mask.size()]));
        }
        return Wire;
    }

    [[nodiscard]] auto ReadFrameBeforeTerminal(
        std::vector<std::byte> Wire,
        Prism::Fault::Failure Terminal) -> WsFrameReadOutcome
    {
        Net::io_context IoContext;
        auto Upstream = std::make_shared<WsFrameTerminalTransmission>(
            IoContext.get_executor(), std::move(Wire), Terminal);
        Prism::Ws::Detail::ConnSession<WsFrameMemory> Session(
            Upstream, Prism::Tests::WsFactorySupport::WebSocketTestBytes(), false);
        Session.MarkHandshaken({});
        Prism::Ws::Detail::ConnTransport<WsFrameMemory> Transport(Session);
        Prism::Ws::Detail::ConnClose<WsFrameMemory> Close(Session, *Upstream);
        Prism::Ws::Detail::ConnFrame<WsFrameMemory> Frame(Session, Transport, Close);
        WsFrameReadOutcome Outcome;
        RunCoro(IoContext, [&]() -> Net::awaitable<void>
        {
            Outcome.FirstDelivered = co_await Frame.ReadNextDataFrame(
                Outcome.FirstPayload, Outcome.FirstError);
            std::vector<std::byte> NextPayload;
            Outcome.SecondDelivered = co_await Frame.ReadNextDataFrame(
                NextPayload, Outcome.SecondError);
        }());
        Outcome.ReadCount = Upstream->ReadCount();
        return Outcome;
    }

    /**
     * @brief 按 wire 长度读取完整帧，允许头与载荷经不同 partial I/O 交付。
     * @param Transport 借用原 executor 上的内存端点至本协程返回。
     * @param Buffer 借用调用方帧缓冲；容量不足保留明确失败，不截断输入。
     * @return 已接收字节数与首个原生失败；不改变端点关闭责任。
     */
    [[nodiscard]] auto ReadWireFrame(MemoryStream &Transport, std::span<std::byte> Buffer)
        -> Net::awaitable<Prism::IoResult>
    {
        if (Buffer.size() < 2)
        {
            co_return Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}};
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
            Result.Failure = Prism::Fault::FromNative(Prism::make_error_code(Error::BadLength));
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
            Result.Failure = Prism::Fault::FromNative(Prism::make_error_code(Error::BadMessage));
            co_return Result;
        }
        if (Header.PayloadLen > Buffer.size() - HeaderSize)
        {
            Result.Failure = Prism::Fault::FromNative(Prism::make_error_code(Error::BadLength));
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
        auto Accepted = co_await Prism::Ws::Accept(
            Prism::Tests::WsFactorySupport::MakeAcceptOptionsForTest(
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
        ErrorCode = Prism::Fault::ToNative(Read.Failure);
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
            ErrorCode = Prism::Fault::ToNative(Write.Failure);
            EXPECT_FALSE(ErrorCode);
            std::array<std::byte, 256> Response{};
            const auto Read = co_await Client->ReadSome(Response);
            ErrorCode = Prism::Fault::ToNative(Read.Failure);
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
                ErrorCode = Prism::Fault::ToNative(FrameWrite.Failure);
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
        ErrorCode = Prism::Fault::ToNative(Read.Failure);
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
        ErrorCode = Prism::Fault::ToNative(ResponseWrite.Failure);
        if (ErrorCode)
        {
            co_return;
        }
        std::array<std::byte, 1024> Wire{};
        const auto WireRead = co_await ReadWireFrame(*Server, Wire);
        ErrorCode = Prism::Fault::ToNative(WireRead.Failure);
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
            auto Connected = co_await Prism::Ws::Connect(
                Prism::Tests::WsFactorySupport::MakeConnectOptionsForTest(
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
                ErrorCode = Prism::Fault::ToNative(Write.Failure);
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
                           std::shared_ptr<Prism::Fault::Code> Result)
        -> Net::awaitable<void>
    {
        auto Accepted = co_await Prism::Ws::Accept(
            Prism::Tests::WsFactorySupport::MakeAcceptOptionsForTest(
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
        ErrorCode = Prism::Fault::ToNative(Read.Failure);
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
        auto Result = std::make_shared<Prism::Fault::Code>(
            Prism::Fault::Code::Success);
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
            ErrorCode = Prism::Fault::ToNative(UpgradeWrite.Failure);
            EXPECT_FALSE(ErrorCode);
            std::array<std::byte, 256> Response{};
            const auto Read = co_await Client->ReadSome(Response);
            ErrorCode = Prism::Fault::ToNative(Read.Failure);
            EXPECT_FALSE(ErrorCode);
            const std::array<std::byte, 3> UnmaskedFrame{
                std::byte{0x82}, std::byte{0x01}, std::byte{'x'}};
            const auto FrameWrite = co_await Client->WriteSome(UnmaskedFrame);
            ErrorCode = Prism::Fault::ToNative(FrameWrite.Failure);
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
        EXPECT_EQ(*Result, Prism::Fault::Code::BadMessage);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    /** @brief 服务端接受 Upgrade 后读取 ping，触发协议 Pong。 */
    auto RunPingServer(std::shared_ptr<MemoryStream> Server) -> Net::awaitable<void>
    {
        auto Accepted = co_await Prism::Ws::Accept(
            Prism::Tests::WsFactorySupport::MakeAcceptOptionsForTest(
                Server, Ws::ServerOptions{}));
        if (!Accepted)
        {
            co_return;
        }
        auto Connection = std::move(Accepted->Connection);
        std::array<std::byte, 64> Buffer{};
        std::error_code ErrorCode;
        const auto Read = co_await Connection->ReadSome(Buffer);
        ErrorCode = Prism::Fault::ToNative(Read.Failure);
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
            ErrorCode = Prism::Fault::ToNative(UpgradeWrite.Failure);
            EXPECT_FALSE(ErrorCode);
            std::array<std::byte, 256> Response{};
            const auto ResponseRead = co_await Client->ReadSome(Response);
            ErrorCode = Prism::Fault::ToNative(ResponseRead.Failure);
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
            ErrorCode = Prism::Fault::ToNative(PingWrite.Failure);
            EXPECT_FALSE(ErrorCode);

            std::array<std::byte, 64> PongFrame{};
            const auto PongRead = co_await ReadWireFrame(*Client, PongFrame);
            ErrorCode = Prism::Fault::ToNative(PongRead.Failure);
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
            ErrorCode = Prism::Fault::ToNative(CloseWrite.Failure);
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

    TEST(WsConnSession, CompleteFramePrecedesEofAndKeepsTerminalSticky)
    {
        constexpr std::string_view Payload{"ws-frame-before-eof"};
        const auto Outcome = ReadFrameBeforeTerminal(
            MakeMaskedBinaryFrame(Payload),
            Prism::Fault::Failure{Prism::Fault::Code::Eof});

        ASSERT_TRUE(Outcome.FirstDelivered);
        EXPECT_EQ(std::string_view(
                      reinterpret_cast<const char *>(Outcome.FirstPayload.data()),
                      Outcome.FirstPayload.size()),
                  Payload);
        EXPECT_FALSE(Outcome.FirstError);
        EXPECT_FALSE(Outcome.SecondDelivered);
        EXPECT_EQ(Outcome.SecondError, Prism::Fault::ToNative(
            Prism::Fault::Failure{Prism::Fault::Code::Eof}));
        EXPECT_EQ(Outcome.ReadCount, 3U);
    }

    TEST(WsConnSession, TerminalCloseClearsHandshakeState)
    {
        Net::io_context IoContext;
        auto Upstream = std::make_shared<WsFrameTerminalTransmission>(
            IoContext.get_executor(), std::vector<std::byte>{}, Prism::Fault::Failure{});
        Prism::Ws::Detail::ConnSession<WsFrameMemory> Session(
            Upstream, Prism::Tests::WsFactorySupport::WebSocketTestBytes(), false);
        Session.MarkHandshaken({});
        Prism::Ws::Detail::ConnClose<WsFrameMemory> Close(Session, *Upstream);

        const auto Closed = Close.Terminate();

        ASSERT_TRUE(Closed);
        EXPECT_TRUE(Session.IsClosed());
        EXPECT_FALSE(Session.IsHandshaken());
    }

    TEST(WsConnSession, CompleteFramePrecedesNativeResetAndKeepsTerminalSticky)
    {
        constexpr std::string_view Payload{"ws-frame-before-reset"};
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const auto Outcome = ReadFrameBeforeTerminal(
            MakeMaskedBinaryFrame(Payload), Prism::Fault::FromNative(Native));

        ASSERT_TRUE(Outcome.FirstDelivered);
        EXPECT_EQ(std::string_view(
                      reinterpret_cast<const char *>(Outcome.FirstPayload.data()),
                      Outcome.FirstPayload.size()),
                  Payload);
        EXPECT_FALSE(Outcome.FirstError);
        EXPECT_FALSE(Outcome.SecondDelivered);
        EXPECT_EQ(Outcome.SecondError, Native);
        EXPECT_EQ(Outcome.ReadCount, 3U);
    }

    TEST(WsConnSession, PartialFrameBeforeEofIsNotDeliveredAndTerminalSticks)
    {
        auto PartialWire = MakeMaskedBinaryFrame("partial-ws-frame");
        PartialWire.resize(4U);
        const auto Terminal = Prism::Fault::Failure{Prism::Fault::Code::Eof};
        const auto Outcome = ReadFrameBeforeTerminal(std::move(PartialWire), Terminal);

        EXPECT_FALSE(Outcome.FirstDelivered);
        EXPECT_EQ(Outcome.FirstError, Prism::Fault::ToNative(Terminal));
        EXPECT_FALSE(Outcome.SecondDelivered);
        EXPECT_EQ(Outcome.SecondError, Prism::Fault::ToNative(Terminal));
        EXPECT_EQ(Outcome.ReadCount, 2U);
    }

    TEST(WsConnSession, PartialFrameBeforeNativeResetIsNotDeliveredAndTerminalSticks)
    {
        auto PartialWire = MakeMaskedBinaryFrame("partial-ws-frame");
        PartialWire.resize(4U);
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const auto Terminal = Prism::Fault::FromNative(Native);
        const auto Outcome = ReadFrameBeforeTerminal(std::move(PartialWire), Terminal);

        EXPECT_FALSE(Outcome.FirstDelivered);
        EXPECT_EQ(Outcome.FirstError, Native);
        EXPECT_FALSE(Outcome.SecondDelivered);
        EXPECT_EQ(Outcome.SecondError, Native);
        EXPECT_EQ(Outcome.ReadCount, 2U);
    }

}
