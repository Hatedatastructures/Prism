/**
 * @file Http11ConnectTest.cpp
 * @brief HTTP/1.1 CONNECT 认证、握手与隧道行为测试。
 */

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Protocols/Http1/Conn.hpp>
#include <Prism/Protocols/Http1/IngressFactory.hpp>
#include <Prism/Protocols/Http1/ForwardRequest.hpp>
#include <Prism/Protocols/Http1/Parser.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include "../Core/HttpTestSupport.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>
#include <TestSupport/Prism/ProviderBindings.hpp>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using Prism::SharedTransmission;
    using Prism::Testing::Http11::CheckTransmissionClose;
    using Prism::Testing::Http11::CloseTransmission;
    using Prism::Testing::Http11::DriveCloseTransmission;
    using Prism::Testing::Http11::MakeBytePool;
    using Prism::Testing::Http11::RunCoroutine;
    using Prism::Testing::Http11::RunMemoryCase;
    using Prism::Testing::Http11::SpawnTask;
    using Prism::Testing::Http11::WaitForTask;

    auto AcceptTransport(Tcp::acceptor &Acceptor) -> Net::awaitable<SharedTransmission>
    {
        boost::system::error_code Error;
        auto Socket = co_await Acceptor.async_accept(Net::redirect_error(Net::use_awaitable, Error));
        if (Error) { ADD_FAILURE() << Error.message(); co_return SharedTransmission{}; }
        co_return Prism::Transport::MakeReliable(std::move(Socket));
    }

    struct LoopbackConnectRequest final
    {
        Net::any_io_executor Executor;
        Tcp::acceptor *Acceptor;
        std::uint16_t Port;
        SharedTransmission *Client;
        std::error_code *Error;
        Prism::Testing::Http11::TaskState *ServerTask;
    };

    auto ConnectAndStore(LoopbackConnectRequest Request) -> Net::awaitable<bool>
    {
        const auto Host = *Prism::Network::ParseHost("127.0.0.1");
        Prism::Network::Dialer::Dialer Dialer(std::move(Request.Executor));
        auto Dialed = co_await Dialer.Connect({Host, Request.Port});
        if (!Dialed)
        {
            *Request.Error = Prism::Fault::ToNative(Dialed.error());
            boost::system::error_code CloseError;
            Request.Acceptor->close(CloseError);
            EXPECT_FALSE(CloseError);
            co_await WaitForTask(std::move(*Request.ServerTask));
            co_return false;
        }
        *Request.Client = std::move(*Dialed);
        co_return true;
    }

    struct HandshakeServerRequest final
    {
        Tcp::acceptor *Acceptor;
    };

    auto RunHandshakeServer(HandshakeServerRequest Request) -> Net::awaitable<void>
    {
        auto Transport = co_await AcceptTransport(*Request.Acceptor);
        if (!Transport)
        {
            co_return;
        }
        Prism::Http11::ServerConn Server(Transport, MakeBytePool());
        Prism::Http11::HttpRequest HttpRequest;
        const auto ReadRequestResult = co_await Server.ReadRequest(HttpRequest);
        if (ReadRequestResult.Succeeded() && HttpRequest.Method == "CONNECT")
        {
            const auto Reply = co_await Server.SendResponse(Prism::Http11::Status::Ok);
            EXPECT_TRUE(Reply.Succeeded());
        }
        CheckTransmissionClose(co_await CloseTransmission(std::move(Transport)));
    }

    struct HandshakeRequest final
    {
        Tcp::acceptor *Acceptor;
        std::uint16_t Port;
        SharedTransmission *Client;
        std::error_code *Error;
        int *Status;
    };

    auto RunHandshake(HandshakeRequest Request) -> Net::awaitable<void>
    {
        auto ServerTask = SpawnTask(Request.Acceptor->get_executor(),
            RunHandshakeServer(HandshakeServerRequest{Request.Acceptor}));
        if (!(co_await ConnectAndStore(LoopbackConnectRequest{
                Request.Acceptor->get_executor(), Request.Acceptor, Request.Port,
                Request.Client, Request.Error, &ServerTask})))
        {
            co_return;
        }
        const auto Sent = co_await Prism::Http11::SendConnect(*Request.Client, "example.com", 443);
        if (Sent != Prism::Fault::Code::Success)
        {
            *Request.Error = Prism::Fault::ToNative(Prism::Fault::Failure{Sent});
        }
        else
        {
            *Request.Status = co_await Prism::Http11::ReadResponse(
                *Request.Client, *Request.Error, MakeBytePool());
        }
        co_await WaitForTask(std::move(ServerTask));
    }

    struct AuthServerRequest final
    {
        Tcp::acceptor *Acceptor;
        std::shared_ptr<Prism::Http11::IngressFactory> Factory;
    };

    auto RunAuthServer(AuthServerRequest Request) -> Net::awaitable<void>
    {
        for (int Round = 0; Round < 2; ++Round)
        {
            auto Transport = co_await AcceptTransport(*Request.Acceptor);
            if (!Transport)
            {
                co_return;
            }
            auto Outcome = co_await Request.Factory->Accept(
                Prism::Contract::StreamAcceptInput{Transport, {}, MakeBytePool()});
            if (Outcome && Outcome->PostDial)
            {
                const auto PostDial = co_await Outcome->PostDial(Prism::Fault::Failure{});
                EXPECT_TRUE(PostDial.Succeeded());
                if (const auto Carrier = Outcome->Transport())
                {
                    CheckTransmissionClose(co_await CloseTransmission(Carrier));
                }
            }
            else
            {
                CheckTransmissionClose(co_await CloseTransmission(std::move(Transport)));
            }
        }
    }

    struct AuthRequest final
    {
        Tcp::acceptor *Acceptor;
        std::uint16_t Port;
        std::shared_ptr<Prism::Http11::IngressFactory> Factory;
        SharedTransmission *Client;
        std::error_code *Error;
        int *StatusNoAuth;
        int *StatusOk;
    };

    auto RunAuth(AuthRequest Request) -> Net::awaitable<void>
    {
        auto ServerTask = SpawnTask(Request.Acceptor->get_executor(),
            RunAuthServer(AuthServerRequest{Request.Acceptor, Request.Factory}));

        if (!(co_await ConnectAndStore(LoopbackConnectRequest{
                Request.Acceptor->get_executor(), Request.Acceptor, Request.Port,
                Request.Client, Request.Error, &ServerTask})))
        {
            co_return;
        }
        const auto FirstSend = co_await Prism::Http11::SendConnect(*Request.Client, "example.com", 443);
        if (FirstSend != Prism::Fault::Code::Success)
        {
            *Request.Error = Prism::Fault::ToNative(Prism::Fault::Failure{FirstSend});
        }
        else
        {
            *Request.StatusNoAuth = co_await Prism::Http11::ReadResponse(
                *Request.Client, *Request.Error, MakeBytePool());
        }
        CheckTransmissionClose(co_await CloseTransmission(*Request.Client));

        if (!(co_await ConnectAndStore(LoopbackConnectRequest{
                Request.Acceptor->get_executor(), Request.Acceptor, Request.Port,
                Request.Client, Request.Error, &ServerTask})))
        {
            co_return;
        }
        const auto SecondSend = co_await Prism::Http11::SendConnect(
            {*Request.Client, "example.com", 443, "Basic dXNlcjpwYXNz"});
        if (SecondSend != Prism::Fault::Code::Success)
        {
            *Request.Error = Prism::Fault::ToNative(Prism::Fault::Failure{SecondSend});
        }
        else
        {
            *Request.StatusOk = co_await Prism::Http11::ReadResponse(
                *Request.Client, *Request.Error, MakeBytePool());
        }
        co_await WaitForTask(std::move(ServerTask));
    }

    struct BadRequestServerRequest final
    {
        Tcp::acceptor *Acceptor;
    };

    auto RunBadRequestServer(BadRequestServerRequest Request) -> Net::awaitable<void>
    {
        auto Transport = co_await AcceptTransport(*Request.Acceptor);
        if (!Transport)
        {
            co_return;
        }
        Prism::Http11::ServerConn Server(Transport, MakeBytePool());
        Prism::Http11::HttpRequest HttpRequest;
        const auto ReadRequestResult = co_await Server.ReadRequest(HttpRequest);
        const auto Status = ReadRequestResult.Succeeded()
                                ? Prism::Http11::Status::Ok
                                : Prism::Http11::Status::BadRequest;
        const auto Reply = co_await Server.SendResponse(Status);
        EXPECT_TRUE(Reply.Succeeded());
        CheckTransmissionClose(co_await CloseTransmission(std::move(Transport)));
    }

    struct BadRequestClientRequest final
    {
        Tcp::acceptor *Acceptor;
        std::uint16_t Port;
        SharedTransmission *Client;
        std::error_code *Error;
        std::string *Reply;
    };

    auto RunBadRequestClient(BadRequestClientRequest Request) -> Net::awaitable<void>
    {
        auto ServerTask = SpawnTask(Request.Acceptor->get_executor(),
            RunBadRequestServer(BadRequestServerRequest{Request.Acceptor}));
        if (!(co_await ConnectAndStore(LoopbackConnectRequest{
                Request.Acceptor->get_executor(), Request.Acceptor, Request.Port,
                Request.Client, Request.Error, &ServerTask})))
        {
            co_return;
        }
        {
            const std::string BadRequest = "\r\n\r\n";
            const auto BadRequestSpan = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(BadRequest.data()), BadRequest.size());
            const auto BadRequestWrite = co_await (*Request.Client)->WriteExact(BadRequestSpan);
            *Request.Error = Prism::Testing::Http11::InspectExactWrite(
                BadRequestWrite, BadRequestSpan.size()).Error;
            if (!*Request.Error)
            {
                std::array<std::byte, 64> Buffer{};
                const auto Read = co_await (*Request.Client)->ReadSome(Buffer);
                const auto Checked = Prism::Testing::Http11::AppendRead(
                    *Request.Reply, Read, Buffer);
                *Request.Error = Checked.Error;
            }
            else
            {
                ADD_FAILURE() << Request.Error->message();
            }
        }
        co_await WaitForTask(std::move(ServerTask));
        if (*Request.Client)
        {
            CheckTransmissionClose(co_await CloseTransmission(*Request.Client));
        }
    }

    struct TunnelServerRequest final
    {
        Tcp::acceptor *Acceptor;
    };

    auto RunTunnelServer(TunnelServerRequest Request) -> Net::awaitable<void>
    {
        auto Transport = co_await AcceptTransport(*Request.Acceptor);
        if (!Transport)
        {
            co_return;
        }
        Prism::Http11::ServerConn Server(Transport, MakeBytePool());
        Prism::Http11::HttpRequest HttpRequest;
        const auto ReadRequestResult = co_await Server.ReadRequest(HttpRequest);
        if (ReadRequestResult.Succeeded())
        {
            const auto Reply = co_await Server.SendResponse(Prism::Http11::Status::Ok);
            EXPECT_TRUE(Reply.Succeeded());
            std::array<std::byte, 128> Buffer{};
            std::error_code Error;
            const auto Read = co_await Transport->ReadSome(Buffer);
            const auto Count = Read.Bytes;
            if (Count > Buffer.size())
            {
                Error = std::make_error_code(std::errc::protocol_error);
            }
            else if (Count > 0U)
            {
                const auto Write = co_await Transport->WriteExact(
                    std::span<const std::byte>(Buffer.data(), Count));
                const auto CheckedWrite = Prism::Testing::Http11::InspectExactWrite(
                    Write, Count);
                if (!Error && CheckedWrite.Error)
                {
                    Error = CheckedWrite.Error;
                }
            }
            if (!Error)
            {
                Error = Prism::Fault::ToNative(Read.Failure);
            }
            EXPECT_FALSE(Error);
        }
        CheckTransmissionClose(co_await CloseTransmission(std::move(Transport)));
    }

    struct TunnelRequest final
    {
        Tcp::acceptor *Acceptor;
        std::uint16_t Port;
        SharedTransmission *Client;
        std::error_code *Error;
        int *Status;
        std::string *Echo;
    };

    auto RunTunnel(TunnelRequest Request) -> Net::awaitable<void>
    {
        auto ServerTask = SpawnTask(Request.Acceptor->get_executor(),
            RunTunnelServer(TunnelServerRequest{Request.Acceptor}));
        if (!(co_await ConnectAndStore(LoopbackConnectRequest{
                Request.Acceptor->get_executor(), Request.Acceptor, Request.Port,
                Request.Client, Request.Error, &ServerTask})))
        {
            co_return;
        }
        const auto Sent = co_await Prism::Http11::SendConnect(*Request.Client, "example.com", 443);
        if (Sent != Prism::Fault::Code::Success)
        {
            *Request.Error = Prism::Fault::ToNative(Prism::Fault::Failure{Sent});
        }
        else
        {
            *Request.Status = co_await Prism::Http11::ReadResponse(
                *Request.Client, *Request.Error, MakeBytePool());
        }
        if (!*Request.Error)
        {
            const std::string Message = "tunnel-echo";
            const auto MessageSpan = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Message.data()), Message.size());
            const auto Write = co_await (*Request.Client)->WriteExact(MessageSpan);
            *Request.Error = Prism::Testing::Http11::InspectExactWrite(
                Write, MessageSpan.size()).Error;
            if (!*Request.Error)
            {
                std::array<std::byte, 128> Buffer{};
                const auto Read = co_await (*Request.Client)->ReadSome(Buffer);
                const auto Captured = Prism::Testing::Http11::AppendRead(
                    *Request.Echo, Read, Buffer);
                *Request.Error = Captured.Error;
            }
        }
        co_await WaitForTask(std::move(ServerTask));
    }

    struct CoalescedRequest final
    {
        SharedTransmission Client;
        SharedTransmission ServerTransport;
        std::string Wire;
        std::size_t PayloadSize;
        std::string *Received;
    };

    auto RunCoalescedRequest(CoalescedRequest Request) -> Net::awaitable<void>
    {
        Prism::Http11::ServerConn Server(Request.ServerTransport, MakeBytePool());
        std::error_code Error;
        const auto Write = co_await Request.Client->WriteExact(Prism::AsBytesSpan(Request.Wire));
        Error = Prism::Testing::Http11::InspectExactWrite(Write, Request.Wire.size()).Error;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        const auto Shutdown = co_await Request.Client->WriteShutdown();
        if (!Error)
        {
            Error = Prism::Testing::Http11::InspectControl(Shutdown);
        }
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        Prism::Http11::HttpRequest HttpRequest;
        const auto ReadRequestResult = co_await Server.ReadRequest(HttpRequest);
        EXPECT_TRUE(ReadRequestResult.Succeeded());
        auto Released = Server.Release();
        EXPECT_TRUE(Released != nullptr);
        if (!Released)
        {
            co_return;
        }
        std::vector<std::byte> Buffer(Request.PayloadSize);
        const auto Read = co_await Released->ReadExact(std::span<std::byte>(Buffer));
        const auto Captured = Prism::Testing::Http11::AppendRead(
            *Request.Received, Read, Buffer);
        if (!Error)
        {
            Error = Captured.Error;
        }
        EXPECT_FALSE(Error);
        CheckTransmissionClose(co_await CloseTransmission(std::move(Released)));
    }

    struct CoalescedResponse final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        std::string Wire;
        std::size_t PayloadSize;
        int *Status;
        std::string *Received;
    };

    auto RunCoalescedResponse(CoalescedResponse Request) -> Net::awaitable<void>
    {
        std::error_code Error;
        const auto Write = co_await Request.Server->WriteExact(Prism::AsBytesSpan(Request.Wire));
        Error = Prism::Testing::Http11::InspectExactWrite(Write, Request.Wire.size()).Error;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        const auto Shutdown = co_await Request.Server->WriteShutdown();
        if (!Error)
        {
            Error = Prism::Testing::Http11::InspectControl(Shutdown);
        }
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        *Request.Status = co_await Prism::Http11::ReadResponse(
            Request.Client, Error, MakeBytePool());
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            CheckTransmissionClose(co_await CloseTransmission(Request.Client));
            co_return;
        }
        std::vector<std::byte> Buffer(Request.PayloadSize);
        const auto Read = co_await Request.Client->ReadExact(std::span<std::byte>(Buffer));
        const auto Captured = Prism::Testing::Http11::AppendRead(
            *Request.Received, Read, Buffer);
        if (!Error)
        {
            Error = Captured.Error;
        }
        EXPECT_FALSE(Error);
        CheckTransmissionClose(co_await CloseTransmission(Request.Client));
        CheckTransmissionClose(co_await CloseTransmission(std::move(Request.Server)));
    }
} // namespace

TEST(Http11Connect, HandshakeOkE2E)
{
    Net::io_context Io;
    Tcp::acceptor Acceptor(Io, Tcp::endpoint(Tcp::v4(), 0));
    const auto Port = Acceptor.local_endpoint().port();

    std::error_code Error;
    SharedTransmission Client;
    int Status = 0;
    RunCoroutine(Io, RunHandshake(HandshakeRequest{
        &Acceptor, Port, &Client, &Error, &Status}));
    EXPECT_FALSE(Error);
    EXPECT_EQ(Status, 200);
    if (Client)
    {
        CheckTransmissionClose(DriveCloseTransmission(Io, Client));
    }
}

TEST(Http11Connect, AuthRequired407)
{
    Net::io_context Io;
    Tcp::acceptor Acceptor(Io, Tcp::endpoint(Tcp::v4(), 0));
    const auto Port = Acceptor.local_endpoint().port();

    auto Authenticator = Prism::Testing::ProviderAccount(Prism::Testing::ProviderAccountInput{Prism::AccountId{1U}, Prism::Account::Credential::Password("pass"), "user", "user", {}})->Authenticator;
    auto Factory = std::make_shared<Prism::Http11::IngressFactory>(
        Prism::Http11::IngressOptions{true, Authenticator});
    std::error_code Error;
    SharedTransmission Client;
    int StatusNoAuth = 0;
    int StatusOk = 0;
    RunCoroutine(Io, RunAuth(AuthRequest{
        &Acceptor, Port, Factory, &Client, &Error, &StatusNoAuth, &StatusOk}));
    EXPECT_EQ(StatusNoAuth, 407);
    EXPECT_EQ(StatusOk, 200);
    if (Client)
    {
        CheckTransmissionClose(DriveCloseTransmission(Io, Client));
    }
}

TEST(Http11Connect, BadRequest400)
{
    Net::io_context Io;
    Tcp::acceptor Acceptor(Io, Tcp::endpoint(Tcp::v4(), 0));
    const auto Port = Acceptor.local_endpoint().port();

    std::error_code Error;
    SharedTransmission Client;
    std::string Reply;
    RunCoroutine(Io, RunBadRequestClient(BadRequestClientRequest{
        &Acceptor, Port, &Client, &Error, &Reply}));
    EXPECT_TRUE(Reply.starts_with("HTTP/1.1 400"));
    if (Client)
    {
        CheckTransmissionClose(DriveCloseTransmission(Io, Client));
    }
}

TEST(Http11Connect, TunnelBidirectional)
{
    Net::io_context Io;
    Tcp::acceptor Acceptor(Io, Tcp::endpoint(Tcp::v4(), 0));
    const auto Port = Acceptor.local_endpoint().port();

    std::error_code Error;
    SharedTransmission Client;
    int Status = 0;
    std::string EchoBack;
    RunCoroutine(Io, RunTunnel(TunnelRequest{
        &Acceptor, Port, &Client, &Error, &Status, &EchoBack}));
    EXPECT_EQ(Status, 200);
    EXPECT_EQ(EchoBack, "tunnel-echo");
    if (Client)
    {
        CheckTransmissionClose(DriveCloseTransmission(Io, Client));
    }
}

TEST(Http11Connect, ServerPreservesCoalescedTunnelPayload)
{
    Net::io_context Io;
    const auto Pair = Prism::Testing::Http11::MakeOwnedMemoryPair(Io.get_executor());
    SharedTransmission Client = Pair.First;
    SharedTransmission ServerTransport = Pair.Second;
    const std::string Payload = "first-tunnel-bytes";
    const std::string Wire = "CONNECT example.com:443 HTTP/1.1\r\n"
                             "Host: example.com:443\r\n"
                             "\r\n" +
                             Payload;
    std::string Received;
    RunMemoryCase(Io, Pair, RunCoalescedRequest(CoalescedRequest{
        Client, ServerTransport, Wire, Payload.size(), &Received}));
    EXPECT_EQ(Received, Payload);
}

TEST(Http11Connect, ClientPreservesCoalescedResponsePayload)
{
    Net::io_context Io;
    const auto Pair = Prism::Testing::Http11::MakeOwnedMemoryPair(Io.get_executor());
    SharedTransmission Client = Pair.First;
    SharedTransmission Server = Pair.Second;
    const std::string Payload = "response-tunnel-bytes";
    const std::string Wire = "HTTP/1.1 200 Connection Established\r\n\r\n" + Payload;
    int Status = 0;
    std::string Received;
    RunMemoryCase(Io, Pair, RunCoalescedResponse(CoalescedResponse{
        Client, Server, Wire, Payload.size(), &Status, &Received}));
    EXPECT_EQ(Status, 200);
    EXPECT_EQ(Received, Payload);
}
