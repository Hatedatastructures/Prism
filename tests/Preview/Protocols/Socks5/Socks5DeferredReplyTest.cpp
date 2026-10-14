/**
 * @file Socks5DeferredReplyTest.cpp
 * @brief SOCKS5 延迟 CONNECT 应答的协议边界测试
 * @details 通过 MemoryStream 与受控取消传输验证错误映射、实际 wire 字节、
 *          连接保留，以及失败、写失败和写入中取消后的关闭行为。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Protocols/Socks5/Reply.hpp>
#include <Preview/Protocols/Socks5/UdpAssocRetirement.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Preview::Socks5;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    /// 只允许一条写入挂起，Cancel/Close 通过同一 executor 取消该写。
    class CancelableWriteTransport final : public Preview::Transmission
    {
    public:
        explicit CancelableWriteTransport(
            Net::any_io_executor Executor,
            const std::size_t InitialProgress = 0)
            : Preview::Transmission(Executor), Executor_(std::move(Executor)),
              WriteStarted_(Executor_, 1), WriteTimer_(Executor_),
              InitialProgress_(InitialProgress)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override { return Executor_; }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ReadWork>(
                ReadInput{std::static_pointer_cast<CancelableWriteTransport>(
                              Preview::Transmission::shared_from_this()),
                          Buffer},
                std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(
                WriteInput{std::static_pointer_cast<CancelableWriteTransport>(
                               Preview::Transmission::shared_from_this()),
                           Buffer},
                std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
                Executor_, std::move(Handler), Preview::IoResult{0, {}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            WriteTimer_.cancel();
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            CancelRequested_ = true;
            WriteTimer_.cancel();
            return {};
        }

        [[nodiscard]] auto IsOpen() const -> bool override { return !Closed_; }

        [[nodiscard]] auto WaitForWriteStart() -> Net::awaitable<void>
        {
            (void)co_await WriteStarted_.async_receive(Net::use_awaitable);
        }

        [[nodiscard]] auto WritePending() const -> bool { return WritePending_; }
        [[nodiscard]] auto WriteCanceled() const -> bool { return WriteCanceled_; }
        [[nodiscard]] auto CancelRequested() const -> bool { return CancelRequested_; }

    private:
        struct ReadInput final
        {
            std::shared_ptr<CancelableWriteTransport> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<CancelableWriteTransport> Owner;
            std::span<const std::byte> Buffer;
        };
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(Work{}, Executor()),
                Handler, std::move(Value));
        }
        [[nodiscard]] auto ReadPartial(std::span<std::byte>)
            -> Net::awaitable<Preview::IoResult>
        {
            co_return Preview::IoResult{
                0, Preview::Fault::FromNative(std::make_error_code(std::errc::operation_canceled))};
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            if (InitialProgress_ != 0 && !InitialProgressSent_)
            {
                InitialProgressSent_ = true;
                co_return Preview::IoResult{std::min(InitialProgress_, Buffer.size()), {}};
            }
            WritePending_ = true;
            (void)WriteStarted_.try_send(boost::system::error_code{});
            if (CancelRequested_ || Closed_)
            {
                WritePending_ = false;
                WriteCanceled_ = CancelRequested_;
                co_return Preview::IoResult{
                    0, Preview::Fault::FromNative(std::make_error_code(std::errc::operation_canceled))};
            }

            WriteTimer_.expires_after(std::chrono::seconds{5});
            boost::system::error_code WaitError;
            co_await WriteTimer_.async_wait(
                Net::redirect_error(Net::use_awaitable, WaitError));
            WritePending_ = false;
            if (CancelRequested_ || WaitError || Closed_)
            {
                WriteCanceled_ = CancelRequested_;
                co_return Preview::IoResult{
                    0, Preview::Fault::FromNative(std::make_error_code(std::errc::operation_canceled))};
            }
            co_return Preview::IoResult{Buffer.size(), {}};
        }

        Net::any_io_executor Executor_;
        Net::experimental::channel<void(boost::system::error_code)> WriteStarted_;
        Net::steady_timer WriteTimer_;
        std::size_t InitialProgress_{0};
        bool InitialProgressSent_{false};
        bool WritePending_{false};
        bool WriteCanceled_{false};
        bool CancelRequested_{false};
        bool Closed_{false};
    };

    constexpr auto ReplySize = std::size_t{10};
    constexpr auto ReadTimeout = std::chrono::milliseconds{100};

    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto ReadReply(std::shared_ptr<MemoryStream> Stream,
                   std::span<std::byte> Buffer) -> Net::awaitable<std::size_t>
    {
        std::size_t Received = 0;
        while (Received < Buffer.size())
        {
            const auto Result = co_await Stream->ReadSome(Buffer.subspan(Received));
            if (Result.Failure.Failed() || Result.Bytes == 0)
            {
                break;
            }
            Received += Result.Bytes;
        }
        co_return Received;
    }

    auto ExpectReply(std::span<const std::byte> Wire,
                     Socks5::ReplyCode Code) -> void
    {
        ASSERT_EQ(Wire.size(), ReplySize);
        if (Wire.size() != ReplySize)
        {
            return;
        }
        EXPECT_EQ(std::to_integer<std::uint8_t>(Wire[0]), Socks5::Version);
        EXPECT_EQ(std::to_integer<std::uint8_t>(Wire[1]),
                  static_cast<std::uint8_t>(Code));
        EXPECT_EQ(std::to_integer<std::uint8_t>(Wire[2]), 0x00);
        EXPECT_EQ(std::to_integer<std::uint8_t>(Wire[3]),
                  static_cast<std::uint8_t>(Socks5::AddressType::Ipv4));
        EXPECT_EQ(std::to_integer<std::uint8_t>(Wire[4]), 0x00);
        EXPECT_EQ(std::to_integer<std::uint8_t>(Wire[5]), 0x00);
        EXPECT_EQ(std::to_integer<std::uint8_t>(Wire[6]), 0x00);
        EXPECT_EQ(std::to_integer<std::uint8_t>(Wire[7]), 0x00);
        EXPECT_EQ(std::to_integer<std::uint8_t>(Wire[8]), 0x00);
        EXPECT_EQ(std::to_integer<std::uint8_t>(Wire[9]), 0x00);
    }

    auto MakeConnection(Net::io_context &IoContext,
                         std::shared_ptr<MemoryStream> &Client) -> std::shared_ptr<Socks5::Conn<>>
    {
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(IoContext.get_executor());
        Client = std::make_shared<MemoryStream>(std::move(ClientEndpoint));
        Client->SetTimeout(ReadTimeout);
        auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
        return std::make_shared<Socks5::Conn<>>(std::move(Server));
    }

    struct ReplyConnectionRequest final
    {
        std::shared_ptr<Socks5::Conn<>> Connection;
        std::shared_ptr<MemoryStream> Client;
    };

    /** @brief 验证成功 deferred reply 的 wire 与连接保留。 */
    auto RunSuccessReply(ReplyConnectionRequest Request)
        -> Net::awaitable<void>
    {
        const auto ReplyError = co_await Socks5::SendConnectDeferredReply(
            Request.Connection, Preview::Diagnose::ContextState::Empty(), Preview::Fault::Code::Success);
        EXPECT_EQ(ReplyError, Error::None);
        std::array<std::byte, ReplySize> Wire{};
        const auto Received =
            co_await ReadReply(Request.Client, std::span<std::byte>(Wire));
        EXPECT_EQ(Received, ReplySize);
        if (Received == ReplySize)
        {
            ExpectReply(std::span<const std::byte>(Wire),
                        Socks5::ReplyCode::Success);
        }
        const auto Underlying = Request.Connection->Underlying();
        EXPECT_TRUE(Underlying);
        if (Underlying)
        {
            EXPECT_TRUE(Underlying->IsOpen());
        }
        const auto CloseResult = Request.Connection->Close();
        EXPECT_TRUE(CloseResult);
        const auto ConnectionDrain = co_await Request.Connection->Activity()->Drain();
        EXPECT_TRUE(ConnectionDrain);
        if (Underlying)
        {
            const auto UnderlyingDrain = co_await Underlying->Activity()->Drain();
            EXPECT_TRUE(UnderlyingDrain);
        }
        if (Underlying)
        {
            EXPECT_FALSE(Underlying->IsOpen());
        }
    }

    /** @brief 验证失败 deferred reply 的 wire 与自动关闭。 */
    auto RunFailureReply(ReplyConnectionRequest Request)
        -> Net::awaitable<void>
    {
        const auto ReplyError = co_await Socks5::SendConnectDeferredReply(
            Request.Connection, Preview::Diagnose::ContextState::Empty(), Preview::Fault::Code::ConnectionRefused);
        EXPECT_EQ(ReplyError, Error::None);
        std::array<std::byte, ReplySize> Wire{};
        const auto Received =
            co_await ReadReply(Request.Client, std::span<std::byte>(Wire));
        EXPECT_EQ(Received, ReplySize);
        if (Received == ReplySize)
        {
            ExpectReply(std::span<const std::byte>(Wire),
                        Socks5::ReplyCode::ConnectionRefused);
        }
        const auto Underlying = Request.Connection->Underlying();
        const auto ConnectionDrain = co_await Request.Connection->Activity()->Drain();
        EXPECT_TRUE(ConnectionDrain);
        EXPECT_TRUE(Underlying);
        if (Underlying)
        {
            const auto UnderlyingDrain = co_await Underlying->Activity()->Drain();
            EXPECT_TRUE(UnderlyingDrain);
            EXPECT_FALSE(Underlying->IsOpen());
        }
    }

    /** @brief 验证响应写失败时连接关闭并返回错误。 */
    auto RunWriteFailure(ReplyConnectionRequest Request) -> Net::awaitable<void>
    {
        const auto ClientClose = Request.Client->Close();
        EXPECT_TRUE(ClientClose);
        const auto ClientDrain = co_await Request.Client->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
        const auto ReplyError = co_await Socks5::SendConnectDeferredReply(
            Request.Connection, Preview::Diagnose::ContextState::Empty(), Preview::Fault::Code::Success);
        EXPECT_NE(ReplyError, Error::None);
        const auto Underlying = Request.Connection->Underlying();
        const auto ConnectionDrain = co_await Request.Connection->Activity()->Drain();
        EXPECT_TRUE(ConnectionDrain);
        EXPECT_TRUE(Underlying);
        if (Underlying)
        {
            const auto UnderlyingDrain = co_await Underlying->Activity()->Drain();
            EXPECT_TRUE(UnderlyingDrain);
            EXPECT_FALSE(Underlying->IsOpen());
        }
    }

    /** @brief 验证 canceled fault 写失败响应并关闭连接。 */
    auto RunCanceledStatus(ReplyConnectionRequest Request)
        -> Net::awaitable<void>
    {
        const auto CancelResult = Request.Connection->Cancel();
        EXPECT_TRUE(CancelResult);
        const auto ReplyError = co_await Socks5::SendConnectDeferredReply(
            Request.Connection, Preview::Diagnose::ContextState::Empty(), Preview::Fault::Code::Canceled);
        EXPECT_EQ(ReplyError, Error::None);
        std::array<std::byte, ReplySize> Wire{};
        const auto Received =
            co_await ReadReply(Request.Client, std::span<std::byte>(Wire));
        EXPECT_EQ(Received, ReplySize);
        if (Received == ReplySize)
        {
            ExpectReply(std::span<const std::byte>(Wire),
                        Socks5::ReplyCode::GeneralFailure);
        }
        const auto Underlying = Request.Connection->Underlying();
        const auto ConnectionDrain = co_await Request.Connection->Activity()->Drain();
        EXPECT_TRUE(ConnectionDrain);
        EXPECT_TRUE(Underlying);
        if (Underlying)
        {
            const auto UnderlyingDrain = co_await Underlying->Activity()->Drain();
            EXPECT_TRUE(UnderlyingDrain);
            EXPECT_FALSE(Underlying->IsOpen());
        }
    }

    struct PendingWriteRequest final
    {
        Net::io_context &IoContext;
        std::shared_ptr<CancelableWriteTransport> Stream;
        std::shared_ptr<Socks5::Conn<>> Connection;
    };

    /** @brief 验证挂起写入被 Cancel 唤醒并完整回收。 */
    auto RunCanceledPendingWrite(PendingWriteRequest Request)
        -> Net::awaitable<void>
    {
        Error ReplyError = Error::None;
        std::exception_ptr ChildException;
        Net::experimental::channel<void(boost::system::error_code)> Completed(
            Request.IoContext.get_executor(), 1);
        Net::co_spawn(
            Request.IoContext,
            [Connection = Request.Connection, &ReplyError]()
                -> Net::awaitable<void>
            {
                ReplyError = co_await Socks5::SendConnectDeferredReply(
                    Connection, Preview::Diagnose::ContextState::Empty(), Preview::Fault::Code::Success);
            },
            [&ChildException, &Completed](std::exception_ptr ErrorValue)
            {
                ChildException = ErrorValue;
                (void)Completed.try_send(boost::system::error_code{});
            });

        using boost::asio::experimental::awaitable_operators::operator||;
        Net::steady_timer StartDeadline(Request.IoContext.get_executor());
        StartDeadline.expires_after(std::chrono::milliseconds{100});
        const auto StartResult = co_await (
            Request.Stream->WaitForWriteStart() ||
            StartDeadline.async_wait(Net::use_awaitable));
        const auto WriteStarted = StartResult.index() == 0U;
        EXPECT_TRUE(WriteStarted);
        if (WriteStarted)
        {
            EXPECT_TRUE(Request.Stream->WritePending());
        }
        const auto CancelResult = Request.Connection->Cancel();
        EXPECT_TRUE(CancelResult);

        Net::steady_timer CompletionDeadline(Request.IoContext.get_executor());
        CompletionDeadline.expires_after(std::chrono::milliseconds{100});
        const auto CompletionResult = co_await (
            Completed.async_receive(Net::use_awaitable) ||
            CompletionDeadline.async_wait(Net::use_awaitable));
        const auto CompletedInTime = CompletionResult.index() == 0U;
        EXPECT_TRUE(CompletedInTime);
        if (!CompletedInTime)
        {
            const auto CloseResult = Request.Connection->Close();
            EXPECT_TRUE(CloseResult);
            (void)co_await Completed.async_receive(Net::use_awaitable);
        }

        const auto ConnectionDrain = co_await Request.Connection->Activity()->Drain();
        EXPECT_TRUE(ConnectionDrain);
        EXPECT_FALSE(ChildException);
        EXPECT_TRUE(Request.Stream->CancelRequested());
        EXPECT_TRUE(Request.Stream->WriteCanceled());
        EXPECT_FALSE(Request.Stream->WritePending());
        EXPECT_NE(ReplyError, Error::None);
        const auto Underlying = Request.Connection->Underlying();
        EXPECT_TRUE(Underlying);
        if (Underlying)
        {
            const auto UnderlyingDrain = co_await Underlying->Activity()->Drain();
            EXPECT_TRUE(UnderlyingDrain);
            EXPECT_FALSE(Underlying->IsOpen());
        }
        EXPECT_FALSE(Request.Stream->IsOpen());
    }

    struct PendingAssociateWriteRequest final
    {
        Net::io_context &IoContext;
        std::shared_ptr<CancelableWriteTransport> Stream;
        std::shared_ptr<Socks5::Conn<>> Connection;
        std::size_t ExpectedBytes{0};
    };

    /** @brief 检查 BND 取消结果保留 Native 与已提交字节数。 */
    auto ExpectCanceledFailure(
        const Socks5::ReplyResult<std::size_t> &Result,
        const std::size_t ExpectedBytes) -> void
    {
        ASSERT_FALSE(Result);
        if (Result) return;
        EXPECT_EQ(Result.error().Protocol, Error::IoError);
        EXPECT_EQ(Result.error().Bytes, ExpectedBytes);
        EXPECT_EQ(Result.error().Transport.Code, Preview::Fault::Code::Canceled);
        EXPECT_EQ(Result.error().Transport.Native,
                  std::make_error_code(std::errc::operation_canceled));
    }

    /** @brief 驱动真实 SOCKS5 BND writer 到 partial write 后取消。 */
    auto RunCanceledPendingAssociateWrite(PendingAssociateWriteRequest Request)
        -> Net::awaitable<void>
    {
        Socks5::ReplyResult<std::size_t> ReplyResult{std::size_t{0}};
        std::exception_ptr ChildException;
        Net::experimental::channel<void(boost::system::error_code)> Completed(
            Request.IoContext.get_executor(), 1);
        Net::co_spawn(
            Request.IoContext,
            [Connection = Request.Connection, &ReplyResult]() -> Net::awaitable<void>
            {
                ReplyResult = co_await Connection->SendAssocReply(
                    Socks5::ReplyCode::Success,
                    Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", 1080});
            },
            [&ChildException, &Completed](std::exception_ptr ErrorValue)
            {
                ChildException = ErrorValue;
                (void)Completed.try_send(boost::system::error_code{});
            });

        using boost::asio::experimental::awaitable_operators::operator||;
        Net::steady_timer StartDeadline(Request.IoContext.get_executor());
        StartDeadline.expires_after(std::chrono::milliseconds{100});
        const auto StartResult = co_await (
            Request.Stream->WaitForWriteStart() ||
            StartDeadline.async_wait(Net::use_awaitable));
        const auto WriteStarted = StartResult.index() == 0U;
        EXPECT_TRUE(WriteStarted);
        if (WriteStarted) EXPECT_TRUE(Request.Stream->WritePending());

        const auto CancelResult = Request.Connection->Cancel();
        EXPECT_TRUE(CancelResult);
        Net::steady_timer CompletionDeadline(Request.IoContext.get_executor());
        CompletionDeadline.expires_after(std::chrono::milliseconds{100});
        const auto CompletionResult = co_await (
            Completed.async_receive(Net::use_awaitable) ||
            CompletionDeadline.async_wait(Net::use_awaitable));
        const auto CompletedInTime = CompletionResult.index() == 0U;
        EXPECT_TRUE(CompletedInTime);
        if (!CompletedInTime)
        {
            EXPECT_TRUE(Request.Connection->Close());
            (void)co_await Completed.async_receive(Net::use_awaitable);
        }

        EXPECT_FALSE(ChildException);
        EXPECT_TRUE(Request.Stream->CancelRequested());
        EXPECT_TRUE(Request.Stream->WriteCanceled());
        EXPECT_FALSE(Request.Stream->WritePending());
        ExpectCanceledFailure(ReplyResult, Request.ExpectedBytes);
        EXPECT_TRUE(Request.Connection->Close());
        const auto ConnectionDrain = co_await Request.Connection->Activity()->Drain();
        EXPECT_TRUE(ConnectionDrain);
        const auto Underlying = Request.Connection->Underlying();
        EXPECT_TRUE(Underlying);
        if (Underlying)
        {
            const auto UnderlyingDrain = co_await Underlying->Activity()->Drain();
            EXPECT_TRUE(UnderlyingDrain);
            EXPECT_FALSE(Underlying->IsOpen());
        }
        EXPECT_FALSE(Request.Stream->IsOpen());
    }

    /** @brief 验证关联 retirement 保留 system/Boost Native 首因并可真实退休。 */
    auto RunAssocExceptionMapping(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(IoContext.get_executor());
        auto Client = std::make_shared<MemoryStream>(std::move(ClientEndpoint));
        auto Upstream = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
        auto Connection = std::make_shared<Socks5::Conn<>>(Upstream);
        auto Retirement = std::make_shared<Socks5::UdpAssocRetirement>(
            IoContext.get_executor(), std::move(Connection));

        const auto Native = std::make_error_code(std::errc::permission_denied);
        const auto SystemFailure = Retirement->RecordException(
            std::make_exception_ptr(std::system_error(Native)));
        EXPECT_EQ(SystemFailure.Code, Preview::Fault::ToCode(Native));
        EXPECT_EQ(SystemFailure.Native, Native);

        const auto BoostNative = boost::system::errc::make_error_code(
            boost::system::errc::permission_denied);
        const auto BoostFailure = Retirement->RecordException(
            std::make_exception_ptr(boost::system::system_error(BoostNative)));
        EXPECT_EQ(BoostFailure.Code,
                  Preview::Fault::ToCode(static_cast<std::error_code>(BoostNative)));
        EXPECT_EQ(BoostFailure.Native, static_cast<std::error_code>(BoostNative));

        const auto UnknownFailure = Retirement->RecordException(
            std::make_exception_ptr(std::runtime_error("unexpected association failure")));
        EXPECT_EQ(UnknownFailure.Code, Preview::Fault::Code::IoError);
        EXPECT_FALSE(UnknownFailure.Native);

        const auto Drain = co_await Retirement->Drain();
        ASSERT_FALSE(Drain);
        EXPECT_EQ(Drain.error().Native, Native);
        Net::steady_timer Watchdog(IoContext.get_executor());
        const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
        while (!Retirement->IsRetired() && std::chrono::steady_clock::now() < Deadline)
        {
            Watchdog.expires_after(std::chrono::milliseconds(5));
            co_await Watchdog.async_wait(Net::use_awaitable);
        }
        EXPECT_TRUE(Retirement->IsRetired());
        EXPECT_TRUE(Client->Close());
        const auto ClientDrain = co_await Client->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
    }

    TEST(Socks5DeferredReply, MapsFaultCodes)
    {
        EXPECT_EQ(Socks5::ToReplyCode(Preview::Fault::Code::Success),
                  Socks5::ReplyCode::Success);
        EXPECT_EQ(Socks5::ToReplyCode(Preview::Fault::Code::ConnectionRefused),
                  Socks5::ReplyCode::ConnectionRefused);
        EXPECT_EQ(Socks5::ToReplyCode(Preview::Fault::Code::Unreachable),
                  Socks5::ReplyCode::NetworkUnreachable);
        EXPECT_EQ(Socks5::ToReplyCode(Preview::Fault::Code::NetNoreply),
                  Socks5::ReplyCode::NetworkUnreachable);
        EXPECT_EQ(Socks5::ToReplyCode(Preview::Fault::Code::HostNoreply),
                  Socks5::ReplyCode::HostUnreachable);
        EXPECT_EQ(Socks5::ToReplyCode(Preview::Fault::Code::Canceled),
                  Socks5::ReplyCode::GeneralFailure);
    }

    TEST(Socks5DeferredReply, SuccessWritesWireAndKeepsConnection)
    {
        Net::io_context IoContext;
        std::shared_ptr<MemoryStream> Client;
        auto Connection = MakeConnection(IoContext, Client);

        RunCoroutine(IoContext, RunSuccessReply(
                                   ReplyConnectionRequest{Connection, Client}));
    }

    TEST(Socks5DeferredReply, FailureWritesWireAndClosesConnection)
    {
        Net::io_context IoContext;
        std::shared_ptr<MemoryStream> Client;
        auto Connection = MakeConnection(IoContext, Client);

        RunCoroutine(IoContext, RunFailureReply(
                                   ReplyConnectionRequest{Connection, Client}));
    }

    TEST(Socks5DeferredReply, WriteFailureClosesConnection)
    {
        Net::io_context IoContext;
        std::shared_ptr<MemoryStream> Client;
        auto Connection = MakeConnection(IoContext, Client);

        RunCoroutine(IoContext, RunWriteFailure(
                                   ReplyConnectionRequest{Connection, Client}));
    }

    TEST(Socks5DeferredReply, CanceledStatusWritesFailureAndCloses)
    {
        Net::io_context IoContext;
        std::shared_ptr<MemoryStream> Client;
        auto Connection = MakeConnection(IoContext, Client);

        RunCoroutine(IoContext, RunCanceledStatus(
                                   ReplyConnectionRequest{Connection, Client}));
    }

    TEST(Socks5DeferredReply, CanceledPendingWriteClosesConnection)
    {
        Net::io_context IoContext;
        auto Stream = std::make_shared<CancelableWriteTransport>(IoContext.get_executor());
        auto Connection = std::make_shared<Socks5::Conn<>>(Stream);

        RunCoroutine(IoContext, RunCanceledPendingWrite(
                                   PendingWriteRequest{IoContext, Stream, Connection}));
    }

    TEST(Socks5DeferredReply, CanceledPendingPartialAssociateWritePreservesFailure)
    {
        Net::io_context IoContext;
        auto Stream = std::make_shared<CancelableWriteTransport>(IoContext.get_executor(), 3);
        auto Connection = std::make_shared<Socks5::Conn<>>(Stream);

        RunCoroutine(IoContext, RunCanceledPendingAssociateWrite(
            PendingAssociateWriteRequest{IoContext, Stream, Connection, 3}));
    }

    TEST(Socks5DeferredReply, AssociationExceptionReturnsMappedNativeFailure)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunAssocExceptionMapping(IoContext));
    }

} // namespace
