/**
 * @file ForwardRequestTest.cpp
 * @brief HTTP/1.1 首请求 Upgrade 门控与关闭行为测试。
 */

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Protocols/Http1/Conn.hpp>
#include <Prism/Protocols/Http1/IngressFactory.hpp>
#include <Prism/Protocols/Http1/Forward/Request.hpp>
#include <Prism/Protocols/Http1/Parser.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <TestSupport/Prism/MockTransport.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <system_error>

#include "HttpTestSupport.hpp"
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using Prism::Error;
    using Prism::SharedTransmission;
    using Prism::Testing::Http11::CheckTransmissionClose;
    using Prism::Testing::Http11::CloseTransmission;
    using Prism::Testing::Http11::InspectControl;
    using Prism::Testing::Http11::InspectExactWrite;
    using Prism::Testing::Http11::MakeBytePool;
    using Prism::Testing::Http11::ReadUntilEof;
    using Prism::Testing::Http11::RunMemoryCase;
    using Prism::Testing::Http11::RunCoroutine;
    using Prism::Testing::Http11::SpawnTask;
    using Prism::Testing::Http11::WaitForTask;

    [[nodiscard]] auto IsProtocolFailure(
        const Prism::Fault::Failure &Failure,
        const Prism::Error Expected) -> bool
    {
        const auto Native = static_cast<std::error_code>(Prism::make_error_code(Expected));
        return Failure.Code == Prism::Fault::ToCode(Native) && Failure.Native == Native;
    }

    struct UpgradeForwardRequest final
    {
        SharedTransmission Client;
        SharedTransmission ServerTransport;
        std::string Header;
        std::string Followup;
        std::string *ForwardedHeader;
        std::string *ForwardedFollowup;
        Prism::Fault::Failure *ReadError;
    };

    /**
     * @brief 等待 101 后放行升级请求的后续 payload。
     * @param Request 升级 wire、传输和结果输出。
     */
    auto RunUpgradeForward(UpgradeForwardRequest Request) -> Net::awaitable<void>
    {
        Prism::Http11::ServerConn Server(Request.ServerTransport, MakeBytePool());
        std::error_code Error;
        const auto Write = co_await Request.Client->WriteExact(
            Prism::AsBytesSpan(Request.Header + Request.Followup));
        Error = InspectExactWrite(Write, Request.Header.size() + Request.Followup.size()).Error;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        const auto Shutdown = co_await Request.Client->WriteShutdown();
        Error = InspectControl(Shutdown);
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        Prism::Http11::HttpRequest HttpRequest;
        const auto RequestRead = co_await Server.ReadRequest(HttpRequest);
        if (RequestRead.Failed())
        {
            ADD_FAILURE() << "HTTP request read failed";
            co_return;
        }
        auto Forwarded = Server.ReleaseForward();
        if (!Forwarded)
        {
            ADD_FAILURE() << "HTTP forward transport was not produced";
            co_return;
        }
        std::array<std::byte, 256> Buffer{};
        const auto HeaderRead = co_await Forwarded->ReadSome(Buffer);
        const auto HeaderCount = HeaderRead.Bytes;
        if (HeaderCount <= Buffer.size())
        {
            Request.ForwardedHeader->assign(
                reinterpret_cast<const char *>(Buffer.data()), HeaderCount);
        }
        else
        {
            *Request.ReadError = Prism::Fault::FromNative(
                std::make_error_code(std::errc::protocol_error));
        }
        if (Request.ReadError->Succeeded())
        {
            *Request.ReadError = HeaderRead.Failure;
        }
        if (Request.ReadError->Failed())
        {
            ADD_FAILURE() << Prism::Fault::ToNative(*Request.ReadError).message();
            CheckTransmissionClose(co_await CloseTransmission(std::move(Forwarded)));
            co_return;
        }
        constexpr std::string_view Response =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "\r\n";
        const auto ResponseWrite = co_await Forwarded->WriteExact(Prism::AsBytesSpan(Response));
        Error = InspectExactWrite(ResponseWrite, Response.size()).Error;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            CheckTransmissionClose(co_await CloseTransmission(std::move(Forwarded)));
            co_return;
        }
        const auto FollowupRead = co_await Forwarded->ReadSome(Buffer);
        const auto FollowupCount = FollowupRead.Bytes;
        if (FollowupCount <= Buffer.size())
        {
            Request.ForwardedFollowup->assign(
                reinterpret_cast<const char *>(Buffer.data()), FollowupCount);
        }
        else
        {
            *Request.ReadError = Prism::Fault::FromNative(
                std::make_error_code(std::errc::protocol_error));
        }
        if (Request.ReadError->Succeeded())
        {
            *Request.ReadError = FollowupRead.Failure;
        }
        if (Request.ReadError->Succeeded() && FollowupCount == Request.Followup.size())
        {
            const auto TerminalRead = co_await Forwarded->ReadSome(Buffer);
            EXPECT_EQ(TerminalRead.Bytes, 0U);
            *Request.ReadError = TerminalRead.Failure;
        }
        const auto CompletedFollowup = FollowupCount == Request.Followup.size() &&
            Request.ReadError->Code == Prism::Fault::Code::Eof && !Request.ReadError->Native;
        if (Request.ReadError->Failed() && !CompletedFollowup)
        {
            ADD_FAILURE() << Prism::Fault::ToNative(*Request.ReadError).message();
        }
        CheckTransmissionClose(co_await CloseTransmission(std::move(Forwarded)));
    }

    struct UpgradeRejectRequest final
    {
        SharedTransmission Client;
        SharedTransmission ServerTransport;
        std::string Header;
        std::string Followup;
        std::string Response;
        std::string *ForwardedHeader;
        std::size_t *FollowupCount;
        Prism::Fault::Failure *ReadError;
    };

    /**
     * @brief 验证未收到 101 时不放行客户端后续 payload。
     * @param Request 升级输入、响应和结果输出。
     */
    auto RunUpgradeReject(UpgradeRejectRequest Request) -> Net::awaitable<void>
    {
        Prism::Http11::ServerConn Server(Request.ServerTransport, MakeBytePool());
        std::error_code Error;
        const auto Write = co_await Request.Client->WriteExact(
            Prism::AsBytesSpan(Request.Header + Request.Followup));
        Error = InspectExactWrite(Write, Request.Header.size() + Request.Followup.size()).Error;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        const auto Shutdown = co_await Request.Client->WriteShutdown();
        Error = InspectControl(Shutdown);
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        Prism::Http11::HttpRequest HttpRequest;
        const auto RequestRead = co_await Server.ReadRequest(HttpRequest);
        if (RequestRead.Failed())
        {
            ADD_FAILURE() << "HTTP request read failed";
            co_return;
        }
        auto Forwarded = Server.ReleaseForward();
        if (!Forwarded)
        {
            ADD_FAILURE() << "HTTP forward transport was not produced";
            co_return;
        }
        std::array<std::byte, 256> Buffer{};
        const auto HeaderRead = co_await Forwarded->ReadSome(Buffer);
        const auto HeaderCount = HeaderRead.Bytes;
        if (HeaderCount <= Buffer.size())
        {
            Request.ForwardedHeader->assign(
                reinterpret_cast<const char *>(Buffer.data()), HeaderCount);
        }
        else
        {
            *Request.ReadError = Prism::Fault::FromNative(
                std::make_error_code(std::errc::protocol_error));
        }
        if (Request.ReadError->Succeeded())
        {
            *Request.ReadError = HeaderRead.Failure;
        }
        if (Request.ReadError->Failed())
        {
            ADD_FAILURE() << Prism::Fault::ToNative(*Request.ReadError).message();
            CheckTransmissionClose(co_await CloseTransmission(std::move(Forwarded)));
            co_return;
        }
        const auto ResponseWrite = co_await Forwarded->WriteExact(
            Prism::AsBytesSpan(Request.Response));
        Error = InspectExactWrite(ResponseWrite, Request.Response.size()).Error;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            CheckTransmissionClose(co_await CloseTransmission(std::move(Forwarded)));
            co_return;
        }
        const auto FollowupRead = co_await Forwarded->ReadSome(Buffer);
        *Request.FollowupCount = FollowupRead.Bytes;
        if (FollowupRead.Bytes > Buffer.size())
        {
            *Request.ReadError = Prism::Fault::FromNative(
                std::make_error_code(std::errc::protocol_error));
        }
        else if (Request.ReadError->Succeeded())
        {
            *Request.ReadError = FollowupRead.Failure;
        }
        CheckTransmissionClose(co_await CloseTransmission(std::move(Forwarded)));
    }

    struct UpgradeWatchdogRequest final
    {
        std::shared_ptr<Net::steady_timer> Watchdog;
        SharedTransmission Forwarded;
        std::shared_ptr<std::atomic_bool> TimedOut;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Done;
    };

    /**
     * @brief 在 origin 迟迟不响应时关闭升级转发。
     * @param Request watchdog 状态和转发 owner。
     */
    auto RunUpgradeWatchdog(UpgradeWatchdogRequest Request) -> Net::awaitable<void>
    {
        boost::system::error_code Error;
        co_await Request.Watchdog->async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (!Error)
        {
            Request.TimedOut->store(true);
            CheckTransmissionClose(co_await CloseTransmission(Request.Forwarded));
        }
        EXPECT_TRUE(Request.Done->try_send(boost::system::error_code{}));
    }

    struct UpgradeGateRequest final
    {
        SharedTransmission Forwarded;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Done;
        std::shared_ptr<Prism::Fault::Failure> Error;
        std::shared_ptr<std::size_t> Count;
    };

    /**
     * @brief 等待 origin 在升级前关闭的转发读取。
     * @param Request gate 状态和转发 owner。
     */
    auto RunUpgradeGate(UpgradeGateRequest Request) -> Net::awaitable<void>
    {
        std::array<std::byte, 256> Buffer{};
        const auto Read = co_await Request.Forwarded->ReadSome(Buffer);
        *Request.Count = Read.Bytes;
        if (Read.Bytes > Buffer.size())
        {
            *Request.Error = Prism::Fault::FromNative(
                std::make_error_code(std::errc::protocol_error));
        }
        else
        {
            *Request.Error = Read.Failure;
        }
        EXPECT_TRUE(Request.Done->try_send(boost::system::error_code{}));
    }

    struct OriginCloseRequest final
    {
        SharedTransmission Client;
        SharedTransmission ServerTransport;
        std::string Header;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> GateDone;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> WatchdogDone;
        std::shared_ptr<Prism::Fault::Failure> GateError;
        std::shared_ptr<std::size_t> GateCount;
        std::shared_ptr<std::atomic_bool> TimedOut;
    };

    /**
     * @brief 验证 origin 在 101 前关闭时的升级 gate 和 watchdog 回收。
     * @param Request 升级输入和两个异步完成信号。
     */
    auto RunOriginClose(OriginCloseRequest Request) -> Net::awaitable<void>
    {
        Prism::Http11::ServerConn Server(Request.ServerTransport, MakeBytePool());
        std::error_code Error;
        const auto Write = co_await Request.Client->WriteExact(Prism::AsBytesSpan(Request.Header));
        Error = InspectExactWrite(Write, Request.Header.size()).Error;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        const auto Shutdown = co_await Request.Client->WriteShutdown();
        Error = InspectControl(Shutdown);
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        Prism::Http11::HttpRequest HttpRequest;
        const auto RequestRead = co_await Server.ReadRequest(HttpRequest);
        if (RequestRead.Failed())
        {
            ADD_FAILURE() << "HTTP request read failed";
            co_return;
        }
        auto Forwarded = Server.ReleaseForward();
        if (!Forwarded)
        {
            ADD_FAILURE() << "HTTP forward transport was not produced";
            co_return;
        }
        std::array<std::byte, 256> HeaderBuffer{};
        std::error_code HeaderError;
        const auto HeaderRead = co_await Forwarded->ReadSome(HeaderBuffer);
        const auto HeaderCount = HeaderRead.Bytes;
        if (HeaderCount > HeaderBuffer.size())
        {
            HeaderError = std::make_error_code(std::errc::protocol_error);
        }
        else
        {
            HeaderError = Prism::Fault::ToNative(HeaderRead.Failure);
        }
        if (HeaderError || HeaderCount == 0U)
        {
            ADD_FAILURE() << "HTTP upgrade request header was not forwarded";
            CheckTransmissionClose(co_await CloseTransmission(std::move(Forwarded)));
            co_return;
        }

        const auto Executor = Request.Client->Executor();
        auto Watchdog = std::make_shared<Net::steady_timer>(Executor);
        Watchdog->expires_after(std::chrono::milliseconds(250));
        auto WatchdogTask = SpawnTask(Executor, RunUpgradeWatchdog(UpgradeWatchdogRequest{
            Watchdog, Forwarded, Request.TimedOut, Request.WatchdogDone}));
        auto GateTask = SpawnTask(Executor, RunUpgradeGate(UpgradeGateRequest{
            Forwarded, Request.GateDone, Request.GateError, Request.GateCount}));

        Net::steady_timer CloseTimer(Executor);
        CloseTimer.expires_after(std::chrono::milliseconds(10));
        boost::system::error_code CloseError;
        co_await CloseTimer.async_wait(Net::redirect_error(Net::use_awaitable, CloseError));
        if (CloseError)
        {
            ADD_FAILURE() << "origin close timer failed: " << CloseError.message();
            CheckTransmissionClose(co_await CloseTransmission(Forwarded));
        }
        else
        {
            const auto ShutdownResult = co_await Forwarded->WriteShutdown();
            EXPECT_FALSE(InspectControl(ShutdownResult));
        }

        boost::system::error_code DoneError;
        co_await Request.GateDone->async_receive(Net::redirect_error(Net::use_awaitable, DoneError));
        if (DoneError)
        {
            ADD_FAILURE() << "upgrade gate completion failed: " << DoneError.message();
        }
        CheckTransmissionClose(co_await CloseTransmission(Forwarded));
        co_await WaitForTask(std::move(GateTask));

        Watchdog->cancel();
        boost::system::error_code WatchdogDoneError;
        co_await Request.WatchdogDone->async_receive(
            Net::redirect_error(Net::use_awaitable, WatchdogDoneError));
        if (WatchdogDoneError)
        {
            ADD_FAILURE() << "upgrade watchdog completion failed: "
                          << WatchdogDoneError.message();
        }
        co_await WaitForTask(std::move(WatchdogTask));
    }
}

TEST(Http11Connect, ReleaseForwardGatesUpgradePayloadUntil101)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerEnd));
    const std::string Header = "GET /events HTTP/1.1\r\n"
                               "Host: example.com\r\n"
                               "Connection: Upgrade\r\n"
                               "Upgrade: websocket\r\n"
                               "\r\n";
    const std::string Followup = "after-101";
    std::string ForwardedHeader;
    std::string ForwardedFollowup;
    Prism::Fault::Failure ReadError;

    RunMemoryCase(Io, {Client, ServerTransport}, RunUpgradeForward(UpgradeForwardRequest{
        Client, ServerTransport, Header, Followup,
        &ForwardedHeader, &ForwardedFollowup, &ReadError}));

    EXPECT_EQ(ReadError.Code, Prism::Fault::Code::Eof);
    EXPECT_FALSE(ReadError.Native);
    EXPECT_EQ(ForwardedHeader, Header);
    EXPECT_EQ(ForwardedFollowup, Followup);
}

TEST(Http11Connect, ReleaseForwardRejectsUpgradeWithout101BeforeClientFollowup)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerEnd));
    const std::string Header = "GET /events HTTP/1.1\r\n"
                               "Host: example.com\r\n"
                               "Connection: Upgrade\r\n"
                               "Upgrade: websocket\r\n"
                               "\r\n";
    const std::string Followup = "client-followup";
    constexpr std::string_view Response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    std::string ForwardedHeader;
    std::size_t FollowupCount = 0;
    Prism::Fault::Failure ReadError;

    RunMemoryCase(Io, {Client, ServerTransport}, RunUpgradeReject(UpgradeRejectRequest{
        Client, ServerTransport, Header, Followup, std::string(Response),
        &ForwardedHeader, &FollowupCount, &ReadError}));

    EXPECT_EQ(ReadError.Code, Prism::Fault::Code::Eof);
    EXPECT_FALSE(ReadError.Native);
    EXPECT_EQ(ForwardedHeader, Header);
    EXPECT_EQ(FollowupCount, 0U);
}

TEST(Http11Connect, ReleaseForwardRejectsUpgradeWhenOriginClosesBefore101)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerEnd));
    const std::string Header = "GET /events HTTP/1.1\r\n"
                               "Host: example.com\r\n"
                               "Connection: Upgrade\r\n"
                               "Upgrade: websocket\r\n"
                               "\r\n";
    auto GateDone =
        std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Io.get_executor(), 1);
    auto WatchdogDone =
        std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Io.get_executor(), 1);
    auto GateError = std::make_shared<Prism::Fault::Failure>();
    auto GateCount = std::make_shared<std::size_t>(0);
    auto TimedOut = std::make_shared<std::atomic_bool>(false);

    RunMemoryCase(Io, {Client, ServerTransport}, RunOriginClose(OriginCloseRequest{
        Client, ServerTransport, Header, GateDone, WatchdogDone,
        GateError, GateCount, TimedOut}));

    EXPECT_FALSE(TimedOut->load()) << "upgrade close watchdog expired";
    EXPECT_EQ(*GateCount, 0U);
    EXPECT_TRUE(IsProtocolFailure(*GateError, Prism::Error::UnexpectedEof));
}
