/** @file SessionTestSupport.hpp @brief 多个 Mux session 用例共用的真实异步 owner。 */
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstddef>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <utility>

#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <Prism/Protocols/Mux/Stream.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <gtest/gtest.h>

namespace Prism::Testing::MuxSession
{
    namespace Net = boost::asio;

    inline auto ExpectIoSuccess(
        const Prism::IoResult &Result,
        const std::size_t ExpectedBytes) -> void
    {
        EXPECT_EQ(Result.Bytes, ExpectedBytes);
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::Success);
        EXPECT_FALSE(Result.Failure.Native);
    }

    /** @brief 驱动协程直至所有被测 owner 自行退出，不用停止事件循环掩盖遗留任务。 */
    template <typename Awaitable, typename Finalizer>
    auto RunAndFinalize(Awaitable Operation, Finalizer Finalize)
        -> Net::awaitable<void>
    {
        std::exception_ptr Failure;
        try
        {
            co_await std::move(Operation);
        }
        catch (...)
        {
            Failure = std::current_exception();
        }
        try
        {
            co_await Finalize();
        }
        catch (...)
        {
            if (!Failure) Failure = std::current_exception();
            else ADD_FAILURE() << "cleanup also threw after the primary coroutine failure";
        }
        if (Failure) std::rethrow_exception(Failure);
    }

    template <typename Awaitable, typename Finalizer>
    auto RunJoinedCoro(
        Net::io_context &Ioc, Awaitable Operation, Finalizer Finalize) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc,
            RunAndFinalize(std::move(Operation), std::move(Finalize)),
            [&Exception](std::exception_ptr ErrorValue)
            { Exception = ErrorValue; });
        Ioc.run();
        if (Exception) std::rethrow_exception(Exception);
    }
    template <typename SessionType>
    auto CloseSessionOwner(
        std::shared_ptr<SessionType> Owner,
        std::exception_ptr &Failure) -> Net::awaitable<void>;

    template <typename SessionType>
    auto CloseAndDrainStream(
        Prism::SharedTransmission Stream,
        std::shared_ptr<SessionType> Session)
        -> Net::awaitable<Prism::Transmission::ControlResult>
    {
        using ControlResult = Prism::Transmission::ControlResult;
        ControlResult Closed;
        std::exception_ptr Exception;
        bool ForceSessionClose = false;
        bool SessionClosed = false;
        if (!Stream)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        try
        {
            Closed = Stream->Close();
            ForceSessionClose = !Closed;
        }
        catch (...)
        {
            Exception = std::current_exception();
            ForceSessionClose = true;
        }
        const auto Owner = std::dynamic_pointer_cast<Prism::Mux::StreamTransmission>(Stream);
        if (!Owner && Closed)
        {
            Closed = std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            ForceSessionClose = true;
        }
        if (ForceSessionClose && Session)
        {
            co_await CloseSessionOwner(Session, Exception);
            SessionClosed = true;
        }
        if (Owner)
        {
            try
            {
                const auto Terminations = co_await Owner->DrainTerminations();
                if (!Terminations)
                {
                    if (Closed) Closed = std::unexpected(Terminations.error());
                    ForceSessionClose = true;
                }
            }
            catch (...)
            {
                if (!Exception) Exception = std::current_exception();
                else ADD_FAILURE() << "termination drain also threw during stream cleanup";
                ForceSessionClose = true;
            }
        }
        if (ForceSessionClose && !SessionClosed && Session)
        {
            co_await CloseSessionOwner(Session, Exception);
            SessionClosed = true;
        }

        const auto Activity = Stream->Activity();
        if (!Activity)
        {
            if (Closed)
                Closed = std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        else
        {
            Activity->Seal();
            try
            {
                const auto Drained = co_await Activity->Drain();
                if (!Drained)
                {
                    if (Closed) Closed = std::unexpected(Drained.error());
                    ForceSessionClose = true;
                }
            }
            catch (...)
            {
                if (!Exception) Exception = std::current_exception();
                else ADD_FAILURE() << "stream activity drain also threw during cleanup";
                ForceSessionClose = true;
            }
            if ((!Activity->IsRetired() || ForceSessionClose) &&
                !SessionClosed && Session)
            {
                co_await CloseSessionOwner(Session, Exception);
                SessionClosed = true;
            }
            if (!Activity->IsRetired())
            {
                try
                {
                    const auto Retry = co_await Activity->Drain();
                    if (!Retry && Closed) Closed = std::unexpected(Retry.error());
                }
                catch (...)
                {
                    if (!Exception) Exception = std::current_exception();
                    else ADD_FAILURE() << "stream activity retry also threw during cleanup";
                }
            }
            if (!Activity->IsRetired() && Closed)
            {
                Closed = std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
        }
        if (Exception) std::rethrow_exception(Exception);
        co_return Closed;
    }

    template <typename SessionType>
    auto CloseSessionOwner(
        std::shared_ptr<SessionType> Owner,
        std::exception_ptr &Failure) -> Net::awaitable<void>
    {
        if (!Owner) co_return;
        try
        {
            co_await Owner->Close();
        }
        catch (...)
        {
            if (!Failure) Failure = std::current_exception();
            else ADD_FAILURE() << "another session close threw during joined cleanup";
        }
        const auto Tasks = Owner->Tasks();
        if (!Tasks) co_return;
        try
        {
            const auto Drained = co_await Tasks->Drain();
            EXPECT_TRUE(Drained);
        }
        catch (...)
        {
            if (!Failure) Failure = std::current_exception();
            else ADD_FAILURE() << "task drain also threw during joined cleanup";
        }
    }

    inline auto DrainRawOwner(
        const Prism::SharedTransmission &Owner,
        std::exception_ptr &Failure) -> Net::awaitable<void>
    {
        if (!Owner) co_return;
        try
        {
            const auto Canceled = Owner->Cancel();
            EXPECT_TRUE(Canceled);
            const auto Closed = Owner->Close();
            EXPECT_TRUE(Closed);
            const auto Activity = Owner->Activity();
            EXPECT_TRUE(Activity);
            if (Activity)
            {
                Activity->Seal();
                const auto Drained = co_await Activity->Drain();
                EXPECT_TRUE(Drained);
                EXPECT_TRUE(Activity->IsRetired());
            }
        }
        catch (...)
        {
            if (!Failure) Failure = std::current_exception();
            else ADD_FAILURE() << "raw transport drain also threw during joined cleanup";
        }
    }


    template <typename SessionType>
    auto CloseSessionAndPeer(
        std::shared_ptr<SessionType> Session,
        Prism::SharedTransmission Peer) -> Net::awaitable<void>
    {
        std::exception_ptr Failure;
        co_await CloseSessionOwner(Session, Failure);
        co_await DrainRawOwner(Peer, Failure);
        if (Failure) std::rethrow_exception(Failure);
    }
    template <typename ClientType, typename ServerType>
    struct SessionRequest final
    {
        Net::io_context &Ioc;
        ClientType &Client;
        ServerType &Server;
        std::size_t PayloadSize;
        std::size_t Received{0};
        Prism::SharedTransmission ClientRaw{};
        Prism::SharedTransmission ServerRaw{};
    };

    /** @brief 等待两端 session 与底层 MemoryStream 的真实活动关闭。 */
    template <typename ClientType, typename ServerType>
    auto CloseSessionPair(SessionRequest<ClientType, ServerType> &Request)
        -> Net::awaitable<void>
    {
        std::exception_ptr Failure;
        co_await CloseSessionOwner(Request.Client.Session(), Failure);
        co_await CloseSessionOwner(Request.Server.Session(), Failure);
        co_await DrainRawOwner(Request.ClientRaw, Failure);
        co_await DrainRawOwner(Request.ServerRaw, Failure);
        if (Failure) std::rethrow_exception(Failure);
    }

    template <typename ClientType, typename ServerType>
    auto RunEchoServer(SessionRequest<ClientType, ServerType> &Request)
        -> Net::awaitable<void>
    {
        auto Stream = co_await Request.Server.AcceptStream();
        if (!Stream)
        {
            EXPECT_TRUE(false) << "Accept Failed";
            co_await Request.Server.Session()->Close();
            co_return;
        }
        std::array<std::byte, 64 * 1024> Buffer{};
        while (true)
        {
            const auto Read = co_await Stream->ReadSome(std::span<std::byte>(Buffer));
            if (Read.Failure.Failed()) EXPECT_EQ(Read.Failure.Code, Prism::Fault::Code::Eof);
            if (Read.Failure.Failed() || Read.Bytes == 0)
            {
                break;
            }
            Request.Received += Read.Bytes;
            const auto Write = co_await Stream->WriteExact(
                std::span<const std::byte>(Buffer.data(), Read.Bytes));
            ExpectIoSuccess(Write, Read.Bytes);
            if (Write.Failure.Failed() || Write.Bytes != Read.Bytes)
            {
                co_await Request.Server.Session()->Close();
                break;
            }
        }
        const auto CloseResult = co_await CloseAndDrainStream(
            std::move(Stream), Request.Server.Session());
        EXPECT_TRUE(CloseResult);
    }

    template <typename ClientType, typename ServerType>
    auto RunEchoClient(SessionRequest<ClientType, ServerType> &Request)
        -> Net::awaitable<void>
    {
        auto Stream = co_await Request.Client.OpenStream();
        if (!Stream)
        {
            EXPECT_TRUE(false) << "Open Failed";
            co_await Request.Client.Session()->Close();
            co_return;
        }
        const std::string Payload(Request.PayloadSize, 'M');
        const auto Write = co_await Stream->WriteExact(std::as_bytes(std::span(Payload)));
        ExpectIoSuccess(Write, Payload.size());
        if (Write.Failure.Failed() || Write.Bytes != Payload.size())
        {
            co_await Request.Client.Session()->Close();
            co_return;
        }
        std::string Echoed;
        std::array<std::byte, 64 * 1024> Buffer{};
        while (Echoed.size() < Payload.size())
        {
            const auto Read = co_await Stream->ReadSome(std::span<std::byte>(Buffer));
            if (Read.Failure.Failed() || Read.Bytes == 0)
            {
                break;
            }
            Echoed.append(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes);
        }
        EXPECT_EQ(Echoed, Payload);
        const auto CloseResult = co_await CloseAndDrainStream(
            std::move(Stream), Request.Client.Session());
        EXPECT_TRUE(CloseResult);
    }

    template <typename ClientType, typename ServerType>
    auto RunSessionBody(SessionRequest<ClientType, ServerType> &Request)
        -> Net::awaitable<void>
    {
        using Net::experimental::awaitable_operators::operator&&;
        co_await (RunEchoServer(Request) && RunEchoClient(Request));
        EXPECT_EQ(Request.Received, Request.PayloadSize);
    }

    template <typename Codec>
    struct SessionFixture final
    {
        std::shared_ptr<Prism::Mux::Session<Codec>> Session;
        std::shared_ptr<Prism::MemoryStream> Raw;
        std::shared_ptr<Prism::MemoryStream> Peer;
    };

    /** @brief 等待协议错误已经发起的底层关闭及其真实 I/O 退栈。 */
    template <typename Codec>
    auto DrainClosedSessionActivity(SessionFixture<Codec> &Fixture)
        -> Net::awaitable<void>
    {
        const auto Activity = Fixture.Raw->Activity();
        Activity->Seal();
        const auto Drained = co_await Activity->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_TRUE(Activity->IsRetired());
    }

    template <typename Codec>
    auto DrainSessionFixture(SessionFixture<Codec> &Fixture) -> Net::awaitable<void>
    {
        std::exception_ptr Failure;
        co_await CloseSessionOwner(Fixture.Session, Failure);
        co_await DrainRawOwner(Fixture.Raw, Failure);
        co_await DrainRawOwner(Fixture.Peer, Failure);
        if (Failure) std::rethrow_exception(Failure);
    }

    auto RunSmuxReceiver(Prism::Mux::Smux::Server<> &Server,
                         const std::size_t StreamCount,
                         const std::size_t PayloadSize) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        for (std::size_t Index = 0; Index < StreamCount; ++Index)
        {
            auto Stream = co_await Server.AcceptStream();
            if (!Stream)
            {
                continue;
            }
            std::size_t Received = 0;
            while (Received < PayloadSize)
            {
                const auto Read = co_await Stream->ReadSome(std::span<std::byte>(Buffer));
                if (Read.Failure.Failed() || Read.Bytes == 0)
                {
                    break;
                }
                Received += Read.Bytes;
            }
            EXPECT_EQ(Received, PayloadSize);
            const auto CloseResult = co_await CloseAndDrainStream(
                std::move(Stream), Server.Session());
            EXPECT_TRUE(CloseResult);
        }
    }

    auto RunSmuxSender(SessionRequest<Prism::Mux::Smux::Client<>,
                                      Prism::Mux::Smux::Server<>> &Request)
        -> Net::awaitable<void>
    {
        constexpr std::size_t StreamCount = 8;
        constexpr std::size_t PayloadSize = 64 * 1024;
        const std::string Payload(PayloadSize, 'C');
        for (std::size_t Index = 0; Index < StreamCount; ++Index)
        {
            auto Stream = co_await Request.Client.OpenStream();
            if (!Stream)
            {
                continue;
            }
            const auto Write = co_await Stream->WriteExact(std::as_bytes(std::span(Payload)));
            ExpectIoSuccess(Write, Payload.size());
            const auto CloseResult = co_await CloseAndDrainStream(
                std::move(Stream), Request.Client.Session());
            EXPECT_TRUE(CloseResult);
        }
    }

    /** @brief Smux 8路完整载荷的双端回环和退休 owner。 */
    auto RunSmuxMultiStream(
        SessionRequest<Prism::Mux::Smux::Client<>,
                       Prism::Mux::Smux::Server<>> &Request) -> Net::awaitable<void>
    {
        constexpr std::size_t StreamCount = 8;
        constexpr std::size_t PayloadSize = 64 * 1024;
        using Net::experimental::awaitable_operators::operator&&;
        co_await (RunSmuxReceiver(Request.Server, StreamCount, PayloadSize) &&
                  RunSmuxSender(Request));
    }

    auto RunFactoryReceiver(Prism::Mux::Smux::Server<> &Server)
        -> Net::awaitable<void>
    {
        auto Stream = co_await Server.AcceptStream();
        if (!Stream)
        {
            co_return;
        }
        std::array<std::byte, 4096> Buffer{};
        while (true)
        {
            const auto Read = co_await Stream->ReadSome(std::span<std::byte>(Buffer));
            if (Read.Failure.Failed()) EXPECT_EQ(Read.Failure.Code, Prism::Fault::Code::Eof);
            if (Read.Failure.Failed() || Read.Bytes == 0)
            {
                break;
            }
        }
        const auto CloseResult = co_await CloseAndDrainStream(
            std::move(Stream), Server.Session());
        EXPECT_TRUE(CloseResult);
    }

    auto RunFactorySender(
        SessionRequest<Prism::Mux::Smux::Client<>,
                       Prism::Mux::Smux::Server<>> &Request) -> Net::awaitable<void>
    {
        auto Stream = co_await Request.Client.OpenStream();
        if (!Stream)
        {
            co_await Request.Client.Session()->Close();
            co_return;
        }
        const std::string Payload = "factory smux";
        const auto Write = co_await Stream->WriteExact(std::as_bytes(std::span(Payload)));
        ExpectIoSuccess(Write, Payload.size());
        const auto CloseResult = co_await CloseAndDrainStream(
            std::move(Stream), Request.Client.Session());
        EXPECT_TRUE(CloseResult);
    }

    auto RunFactorySmux(
        SessionRequest<Prism::Mux::Smux::Client<>,
                       Prism::Mux::Smux::Server<>> &Request) -> Net::awaitable<void>
    {
        using Net::experimental::awaitable_operators::operator&&;
        co_await (RunFactoryReceiver(Request.Server) && RunFactorySender(Request));
    }
}
