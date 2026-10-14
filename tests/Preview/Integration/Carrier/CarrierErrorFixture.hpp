#pragma once

/**
 * @file CarrierErrorFixture.hpp
 * @brief 共享 stealth Conn 与 VMess Conn 错误路径测试辅助。
 * @details 针对测试库 Conn 装饰器的握手错误路径与数据面错误分支：
 * 1. stealth 各方案（anytls / shadowtls / restls /
 *    trusttunnel / gun / ws）ReadHandshake / WriteHandshake
 *    错误路径：底层 EOF、校验失败（bad_auth）、魔数不匹配
 *    （bad_magic）、密钥派生失败（kdf_error）、发送失败（io_error）
 * 2. vmess Conn 数据面错误分支：未握手读写（not_open）、
 *    chunk 解密失败（bad_auth）、EOF（unexpected_eof）、
 *    结束块（Finish）→ 流结束（0 且无错误）
 * @note 使用 MakeOwnedMemoryPair 构造共享拥有的内存传输对，手动注入合法/非法
 *       字节流触发各错误分支；全部采用 co_spawn + io_context.run() 模式。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <span>
#include <utility>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include "../../Transport/TransportResources.hpp"
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <Preview/Protocols/Vmess/Codec.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <Preview/Protocols/Anytls/Codec.hpp>
#include <Preview/Protocols/Anytls/Conn.hpp>
#include <Preview/Protocols/Gun/Conn.hpp>
#include <Preview/Protocols/Restls/Detail/Session.hpp>
#include <Preview/Protocols/Shadowtls/Detail/Session.hpp>
#include <Preview/Protocols/Trusttunnel/Codec.hpp>
#include <Preview/Protocols/Trusttunnel/Conn.hpp>
#include <Preview/Protocols/Trusttunnel/Detail/Conn.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace PreviewApi = ::Preview;
    namespace Anytls = PreviewApi::Anytls;
    namespace Shadowtls = PreviewApi::Shadowtls;
    namespace Restls = PreviewApi::Restls;
    namespace Trusttunnel = PreviewApi::Trusttunnel;
    namespace Gun = PreviewApi::Gun;
    namespace Ws = PreviewApi::Ws;
    namespace Vmess = PreviewApi::Vmess;

    using PreviewApi::AsBytes;
    using PreviewApi::AsU8Span;
    using PreviewApi::Error;
    using PreviewApi::PreviewMockTransport;
    using IoResult = PreviewApi::IoResult;
    using SharedTransmission = PreviewApi::SharedTransmission;
    using ControlResult = PreviewApi::Transmission::ControlResult;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct MemoryPair final
    {
        SharedTransmission Client;
        SharedTransmission Server;
    };

    struct TaskState final
    {
        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Exception;
        std::shared_ptr<bool> CompletionAccepted;
    };

    struct TransmissionCloseResult final
    {
        ControlResult Cancel;
        ControlResult Close;
        ControlResult Drain;
    };

    template <typename Awaitable>
    auto SpawnTask(Net::any_io_executor Executor, Awaitable Operation) -> TaskState
    {
        TaskState State;
        State.Done = std::make_shared<CompletionChannel>(Executor, 1);
        State.Exception = std::make_shared<std::exception_ptr>();
        State.CompletionAccepted = std::make_shared<bool>(false);
        auto Completion = [State](std::exception_ptr ErrorValue) -> void
        {
            *State.Exception = ErrorValue;
            *State.CompletionAccepted =
                static_cast<bool>(State.Done->try_send(boost::system::error_code{}));
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
            const auto Failure = PreviewApi::Fault::FromNative(
                static_cast<std::error_code>(WaitError));
            ADD_FAILURE() << "任务完成通道失败："
                          << PreviewApi::Fault::ToNative(Failure).message();
            co_return;
        }
        EXPECT_TRUE(*State.CompletionAccepted)
            << "任务完成通知未成功入队";
        if (*State.Exception)
        {
            std::rethrow_exception(*State.Exception);
        }
        co_return;
    }

    /** @brief 驱动根协程自然完成，并在所有已排队工作退栈后返回。 */
    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &Context, Awaitable Operation) -> void
    {
        std::exception_ptr Fatal;
        auto Completion = [&Fatal](std::exception_ptr ErrorValue) -> void
        {
            Fatal = std::move(ErrorValue);
        };
        Net::co_spawn(Context, std::move(Operation), std::move(Completion));
        Context.run();
        if (Fatal)
        {
            std::rethrow_exception(Fatal);
        }
    }

    /** @brief 创建两个均由 shared_ptr 持有的测试 MemoryStream。 */
    auto MakeOwnedMemoryPair(Net::any_io_executor Executor) -> MemoryPair
    {
        auto Pair = PreviewApi::Testing::MakeOwnedTransportPair(std::move(Executor));
        return {Pair.FirstOwner, Pair.SecondOwner};
    }

    /** @brief 关闭单个真实传输 owner 并等待其 Activity 完全退栈。 */
    auto CloseTransmission(SharedTransmission Transport)
        -> Net::awaitable<TransmissionCloseResult>
    {
        if (!Transport)
        {
            const PreviewApi::Fault::Failure Failure{
                PreviewApi::Fault::Code::InvalidArgument};
            co_return TransmissionCloseResult{
                std::unexpected(Failure), std::unexpected(Failure), std::unexpected(Failure)};
        }
        const auto CancelResult = Transport->Cancel();
        const auto CloseResult = Transport->Close();
        const auto DrainResult = co_await Transport->Activity()->Drain();
        co_return TransmissionCloseResult{
            CancelResult, CloseResult, DrainResult};
    }

    /** @brief 将每个控制命令拒绝和 drain 失败保留为测试失败。 */
    auto CheckTransmissionClose(const TransmissionCloseResult &Result) -> void
    {
        if (!Result.Cancel)
        {
            ADD_FAILURE() << "Cancel 被拒绝："
                          << PreviewApi::Fault::ToNative(Result.Cancel.error()).message();
        }
        if (!Result.Close)
        {
            ADD_FAILURE() << "Close 被拒绝："
                          << PreviewApi::Fault::ToNative(Result.Close.error()).message();
        }
        if (!Result.Drain)
        {
            ADD_FAILURE() << "Activity Drain 失败："
                          << PreviewApi::Fault::ToNative(Result.Drain.error()).message();
        }
    }

    /** @brief 在当前 io_context 上完整运行一次关闭与 Drain。 */
    auto DriveCloseTransmission(
        Net::io_context &Context,
        SharedTransmission Transport) -> TransmissionCloseResult
    {
        if (Context.stopped())
        {
            Context.restart();
        }
        std::exception_ptr Fatal;
        bool Completed = false;
        TransmissionCloseResult Result;
        auto Completion = [&Fatal, &Completed, &Result](
                              std::exception_ptr ErrorValue,
                              TransmissionCloseResult Value) -> void
        {
            Fatal = std::move(ErrorValue);
            Result = std::move(Value);
            Completed = true;
        };
        Net::co_spawn(
            Context, CloseTransmission(std::move(Transport)), std::move(Completion));
        Context.run();
        if (Fatal)
        {
            std::rethrow_exception(Fatal);
        }
        EXPECT_TRUE(Completed) << "关闭协程没有完成";
        return Result;
    }

    /** @brief 运行测试协程，并在返回或致命异常后关闭和排空两个内存端点。 */
    template <typename Awaitable>
    auto RunMemoryCase(
        Net::io_context &Context,
        const MemoryPair &Pair,
        Awaitable Operation) -> void
    {
        std::exception_ptr Fatal;
        try
        {
            RunCoroutine(Context, std::move(Operation));
        }
        catch (...)
        {
            Fatal = std::current_exception();
        }
        std::exception_ptr CleanupFatal;
        try
        {
            CheckTransmissionClose(DriveCloseTransmission(Context, Pair.Client));
        }
        catch (...)
        {
            CleanupFatal = std::current_exception();
        }
        try
        {
            CheckTransmissionClose(DriveCloseTransmission(Context, Pair.Server));
        }
        catch (...)
        {
            if (!CleanupFatal)
            {
                CleanupFatal = std::current_exception();
            }
        }
        if (Fatal)
        {
            std::rethrow_exception(Fatal);
        }
        if (CleanupFatal)
        {
            std::rethrow_exception(CleanupFatal);
        }
    }

    /** @brief 构造固定模式测试字节。 */
    auto MakeRandom(std::uint8_t Seed, std::size_t Length) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result(Length);
        for (std::size_t Index = 0; Index < Length; ++Index)
        {
            Result[Index] = static_cast<std::uint8_t>(Index * 7 + Seed);
        }
        return Result;
    }

    /** @brief 断言 typed 写入完整交付预期字节且无失败。 */
    auto ExpectFullWrite(const IoResult &Result, const std::size_t ExpectedBytes) -> void
    {
        EXPECT_LE(Result.Bytes, ExpectedBytes);
        EXPECT_EQ(Result.Bytes, ExpectedBytes);
        EXPECT_TRUE(Result.Failure.Succeeded());
    }

    /**
     * @brief 将测试输入完整写入内存传输并返回 typed completion。
     * @details 逐次累计真实完成字节，再处理同次失败；零进度成功映射为 WouldBlock，避免忙等。
     */
    auto WriteRaw(SharedTransmission Stream, std::string_view Data) -> Net::awaitable<IoResult>
    {
        const auto DataBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Data.data()), Data.size());
        IoResult Result;
        while (Result.Bytes < DataBytes.size())
        {
            const auto Part = co_await Stream->WriteSome(DataBytes.subspan(Result.Bytes));
            if (Part.Bytes > DataBytes.size() - Result.Bytes)
            {
                Result.Failure = {PreviewApi::Fault::Code::InvalidArgument, Part.Failure.Native};
                break;
            }
            Result.Bytes += Part.Bytes;
            Result.Failure = Part.Failure;
            if (Result.Failure.Failed())
            {
                break;
            }
            if (Part.Bytes == 0)
            {
                Result.Failure = {PreviewApi::Fault::Code::WouldBlock};
                break;
            }
        }
        ExpectFullWrite(Result, DataBytes.size());
        co_return Result;
    }

    /** @brief 断言未握手连接的读写仍返回 NotOpen，并排空连接自身。 */
    template <typename ConnectionType>
    auto CheckNotOpenReadWrite(const std::shared_ptr<ConnectionType> &Connection)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 64> Buffer{};
        const auto Read = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0u);
        EXPECT_EQ(PreviewApi::Fault::ToNative(Read.Failure), make_error_code(Error::NotOpen));
        const auto WriteBuffer = std::span<const std::byte>(Buffer.data(), 4);
        const auto Write = co_await Connection->WriteSome(WriteBuffer);
        EXPECT_EQ(Write.Bytes, 0u);
        EXPECT_EQ(PreviewApi::Fault::ToNative(Write.Failure), make_error_code(Error::NotOpen));
        CheckTransmissionClose(co_await CloseTransmission(Connection));
        co_return;
    }

    /** @brief 关闭并排空协议连接，逐项断言控制与活动结果。 */
    template <typename ConnectionType>
    auto ExpectCloseTransmission(const std::shared_ptr<ConnectionType> &Transport)
        -> Net::awaitable<void>
    {
        CheckTransmissionClose(co_await CloseTransmission(Transport));
        co_return;
    }

    /** @brief 唯一 VMess 服务端入口的 stream 场景投影，错分支仍完整关闭。 */
    auto AcceptVmessStream(SharedTransmission Server, Vmess::ServerConfig Config)
        -> Net::awaitable<std::expected<Vmess::AcceptedConnection, PreviewApi::Fault::Failure>>
    {
        auto Result = co_await Vmess::AcceptSession(std::move(Server), Config);
        if (!Result) co_return std::unexpected(Result.error());
        if (auto *Stream = std::get_if<Vmess::AcceptedConnection>(&*Result))
            co_return std::move(*Stream);
        auto Datagram = std::move(std::get<Vmess::AcceptedDatagram>(*Result).Connection);
        if (Datagram)
        {
            auto Underlying = Datagram->Stream();
            co_await ExpectCloseTransmission(Datagram);
            co_await ExpectCloseTransmission(Underlying);
        }
        co_return std::unexpected(
            PreviewApi::Fault::Failure{PreviewApi::Fault::Code::BadMessage});
    }

    auto RunWsBadStatusServer(SharedTransmission Server) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 512> RequestBuffer{};
        const auto RequestBytes = AsBytes(std::span<std::uint8_t>(RequestBuffer));
        const auto Read = co_await Server->ReadSome(RequestBytes);
        const auto BytesRead = Read.Bytes;
        EXPECT_GT(BytesRead, 0U);
        EXPECT_TRUE(Read.Failure.Succeeded());
        const std::string Response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        const auto ResponseBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Response.data()), Response.size());
        const auto Write = co_await Server->WriteSome(ResponseBytes);
        ExpectFullWrite(Write, Response.size());
        co_await ExpectCloseTransmission(Server);
        co_return;
    }

    auto RunWsBadAcceptServer(SharedTransmission Server) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 512> RequestBuffer{};
        const auto RequestBytes = AsBytes(std::span<std::uint8_t>(RequestBuffer));
        const auto Read = co_await Server->ReadSome(RequestBytes);
        const auto BytesRead = Read.Bytes;
        EXPECT_GT(BytesRead, 0U);
        EXPECT_TRUE(Read.Failure.Succeeded());
        const std::string Response =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: wrong-Accept-value\r\n\r\n";
        const auto ResponseBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Response.data()), Response.size());
        const auto Write = co_await Server->WriteSome(ResponseBytes);
        ExpectFullWrite(Write, Response.size());
        co_await ExpectCloseTransmission(Server);
        co_return;
    }

    auto RunWsCloseServer(SharedTransmission Server) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 512> RequestBuffer{};
        const auto RequestBytes = AsBytes(std::span<std::uint8_t>(RequestBuffer));
        const auto Read = co_await Server->ReadSome(RequestBytes);
        const auto BytesRead = Read.Bytes;
        EXPECT_GT(BytesRead, 0U);
        EXPECT_TRUE(Read.Failure.Succeeded());
        co_await ExpectCloseTransmission(Server);
        co_return;
    }

    auto RunVmessGarbageServer(SharedTransmission Server) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 18> Garbage{};
        Garbage.fill(0xFF);
        const auto GarbageBytes = AsBytes(std::span<const std::uint8_t>(Garbage));
        const auto Write = co_await Server->WriteSome(GarbageBytes);
        ExpectFullWrite(Write, GarbageBytes.size());
        co_return;
    }

    auto RunVmessBadChunkServer(
        SharedTransmission Server,
        std::array<std::uint8_t, 16> Uuid) -> Net::awaitable<void>
    {
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        auto AcceptResult = co_await AcceptVmessStream(Server, Config);
        if (!AcceptResult)
        {
            ADD_FAILURE() << "Accept Failed: " << static_cast<int>(AcceptResult.error().Code);
            co_return;
        }
        if (!AcceptResult->Connection)
        {
            ADD_FAILURE() << "Accept succeeded without a VMess connection owner";
            co_return;
        }
        auto Request = std::move(AcceptResult->Request);
        auto Connection = std::move(AcceptResult->Connection);
        const auto ResponseBodyKey = Vmess::detail::Sha256(Request.RequestKey);
        const auto ResponseBodyIv = Vmess::detail::Sha256(Request.RequestNonce);
        std::array<std::uint8_t, 16> ResponseKey{};
        std::array<std::uint8_t, 16> ResponseNonce{};
        std::memcpy(ResponseKey.data(), ResponseBodyKey.data(), ResponseKey.size());
        std::memcpy(ResponseNonce.data(), ResponseBodyIv.data(), ResponseNonce.size());
        Vmess::ChunkEncryptor Encoder(
            std::span<const std::uint8_t, 16>(ResponseKey),
            std::span<const std::uint8_t, 16>(ResponseNonce),
            Request.Option);
        std::array<std::uint8_t, 64> Garbage{};
        const std::array<std::uint8_t, 1> Payload{0xA5};
        const auto FrameSize = Encoder.Seal(Payload, Garbage);
        Garbage[FrameSize - 1] ^= 0xFF;
        const auto GarbageBytes = AsBytes(
            std::span<const std::uint8_t>(Garbage).first(FrameSize));
        const auto Write = co_await Connection->NextLayer()->WriteSome(GarbageBytes);
        ExpectFullWrite(Write, GarbageBytes.size());
        co_await ExpectCloseTransmission(Connection);
        co_return;
    }

    auto RunVmessCloseServer(
        SharedTransmission Server,
        std::array<std::uint8_t, 16> Uuid) -> Net::awaitable<void>
    {
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        auto AcceptResult = co_await AcceptVmessStream(Server, Config);
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (AcceptResult && AcceptResult->Connection)
        {
            co_await ExpectCloseTransmission(AcceptResult->Connection);
        }
        co_return;
    }

    auto RunVmessFinishServer(
        SharedTransmission Server,
        std::array<std::uint8_t, 16> Uuid) -> Net::awaitable<void>
    {
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        auto AcceptResult = co_await AcceptVmessStream(Server, Config);
        if (!AcceptResult)
        {
            ADD_FAILURE() << "Accept Failed: " << static_cast<int>(AcceptResult.error().Code);
            co_return;
        }
        if (!AcceptResult->Connection)
        {
            ADD_FAILURE() << "Accept succeeded without a VMess connection owner";
            co_return;
        }
        auto Request = std::move(AcceptResult->Request);
        auto Connection = std::move(AcceptResult->Connection);
        const auto ResponseBodyKey = Vmess::detail::Sha256(Request.RequestKey);
        const auto ResponseBodyIv = Vmess::detail::Sha256(Request.RequestNonce);
        std::array<std::uint8_t, 16> ResponseKey{};
        std::array<std::uint8_t, 16> ResponseNonce{};
        std::memcpy(ResponseKey.data(), ResponseBodyKey.data(), ResponseKey.size());
        std::memcpy(ResponseNonce.data(), ResponseBodyIv.data(), ResponseNonce.size());
        Vmess::ChunkEncryptor Encoder(
            std::span<const std::uint8_t, 16>(ResponseKey),
            std::span<const std::uint8_t, 16>(ResponseNonce),
            Request.Option);
        std::array<std::uint8_t, 34> EndBlock{};
        const auto EndBlockSize = Encoder.Finish(EndBlock);
        const auto EndBlockBytes = AsBytes(
            std::span<const std::uint8_t>(EndBlock).first(EndBlockSize));
        const auto Write = co_await Connection->NextLayer()->WriteSome(EndBlockBytes);
        ExpectFullWrite(Write, EndBlockBytes.size());
        co_await ExpectCloseTransmission(Connection);
        co_return;
    }

    // =========================================================================
    // AnyTLS Conn 错误路径
    // =========================================================================

} // namespace

