/**
 * @file Session.cpp
 * @brief SOCKS5 Conn 认证与握手会话测试。
 * @details 覆盖无认证、用户认证、版本/方法错误和客户端响应校验。
 */

#include <gtest/gtest.h>
#include <TestSupport/Prism/ProviderBindings.hpp>

#include <array>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include "SessionSupport.hpp"

namespace
{
    namespace TestSupport = Prism::Socks5ConnTestSupport;
    namespace Net = TestSupport::Net;
    namespace Socks5 = TestSupport::Socks5;
    using Prism::AsBytes;
    using Prism::MakeMemoryPair;
    using MemoryStream = TestSupport::MemoryStream;
    using TestSupport::CloseAndWait;
    using TestSupport::MakeAddress;
    using TestSupport::RunCoroutine;
    using TestSupport::SpawnEager;

    /** @brief 服务端完成无认证连接并回显预读载荷。 */
    auto RunNoAuthServer(std::shared_ptr<MemoryStream> Server,
                         std::string Payload) -> Net::awaitable<void>
    {
        auto Accepted = co_await Socks5::Accept(Server, Socks5::ServerConfig{});
        if (!Accepted || !Accepted->Connection)
        {
            EXPECT_TRUE(false) << "Accept Failed";
            co_return;
        }
        const auto &Request = Accepted->RequestValue;
        const auto Conn = Accepted->Connection;
        EXPECT_EQ(Request.Cmd, Socks5::Command::Connect);
        EXPECT_EQ(Request.Target.Host, "example.com");
        EXPECT_EQ(Request.Target.Port, 443u);
        EXPECT_EQ(Conn->Parsed().Target.Host, "example.com");

        std::array<std::byte, 1024> Buffer{};
        std::error_code ErrorCode;
        const auto Read = co_await Conn->ReadSome(Buffer);
        ErrorCode = Prism::Fault::ToNative(Read.Failure);
        const auto BytesRead = Read.Bytes;
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), BytesRead),
                  Payload);
        const auto Write = co_await Conn->WriteSome(
            std::span<const std::byte>(Buffer.data(), BytesRead));
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        EXPECT_FALSE(ErrorCode);
        (void)Conn->Close();
    }

    /** @brief 驱动无认证原始 wire 握手、预读路径和回显。 */
    auto RunNoAuthHandshakeEcho(TestSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        const std::string Payload = "socks5 echo payload";
        auto ServerTask = SpawnEager(Server->Executor(),
                                     RunNoAuthServer(Server, Payload));
        std::exception_ptr ParentFailure;
        try
        {
            std::vector<std::uint8_t> Wire{0x05, 0x01, 0x00};
            const std::string Host = "example.com";
            Wire.insert(Wire.end(), {0x05, 0x01, 0x00, 0x03,
                                     static_cast<std::uint8_t>(Host.size())});
            Wire.insert(Wire.end(), Host.begin(), Host.end());
            Wire.push_back(0x01);
            Wire.push_back(0xBB);
            Wire.insert(Wire.end(), Payload.begin(), Payload.end());
            std::error_code ErrorCode;
            const auto Write = co_await Client->WriteSome(
                AsBytes(std::span<const std::uint8_t>(Wire)));
            ErrorCode = Prism::Fault::ToNative(Write.Failure);

            std::array<std::uint8_t, 12> Response{};
            std::size_t Received = 0;
            while (Received < Response.size())
            {
                const auto Read = co_await Client->ReadSome(
                    AsBytes(std::span<std::uint8_t>(Response).subspan(Received)));
                ErrorCode = Prism::Fault::ToNative(Read.Failure);
                const auto BytesRead = Read.Bytes;
                if (ErrorCode || BytesRead == 0)
                {
                    break;
                }
                Received += BytesRead;
            }
            EXPECT_EQ(Received, 12u);
            EXPECT_EQ(Response[0], Socks5::Version);
            EXPECT_EQ(Response[1], 0x00);
            EXPECT_EQ(Response[3], 0x00);

            std::array<std::byte, 1024> Echo{};
            Received = 0;
            while (Received < Payload.size())
            {
                const auto Read = co_await Client->ReadSome(
                    std::span<std::byte>(Echo.data() + Received,
                                         Echo.size() - Received));
                ErrorCode = Prism::Fault::ToNative(Read.Failure);
                const auto BytesRead = Read.Bytes;
                if (ErrorCode || BytesRead == 0)
                {
                    break;
                }
                Received += BytesRead;
            }
            EXPECT_EQ(std::string(reinterpret_cast<const char *>(Echo.data()), Received),
                      Payload);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        EXPECT_TRUE(co_await CloseAndWait(Client, Server, std::move(ServerTask)));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    /** @brief 服务端使用工厂握手并回显客户端数据。 */
    auto RunFactoryServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        auto Accepted = co_await Socks5::Accept(Server, Socks5::ServerConfig{});
        if (!Accepted || !Accepted->Connection)
        {
            co_return;
        }
        const auto &Request = Accepted->RequestValue;
        const auto Conn = Accepted->Connection;
        EXPECT_EQ(Request.Target.Host, "1.2.3.4");
        std::array<std::byte, 256> Buffer{};
        std::error_code ErrorCode;
        const auto Read = co_await Conn->ReadSome(Buffer);
        ErrorCode = Prism::Fault::ToNative(Read.Failure);
        const auto BytesRead = Read.Bytes;
        if (ErrorCode || BytesRead == 0)
        {
            co_return;
        }
        const auto Write = co_await Conn->WriteSome(
            std::span<const std::byte>(Buffer.data(), BytesRead));
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        (void)Conn->Close();
    }

    /** @brief 驱动 Connect/Accept factory 回显。 */
    auto RunFactoryConnectAcceptEcho(TestSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto ClientStream = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto ServerStream = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = SpawnEager(ServerStream->Executor(),
                                     RunFactoryServer(ServerStream));
        std::exception_ptr ParentFailure;
        try
        {
            auto Connected = co_await Socks5::Connect(Socks5::ConnectParameters{
                ClientStream, Socks5::ClientConfig{},
                MakeAddress(Socks5::AddressType::Ipv4, "1.2.3.4", 80)});
            EXPECT_TRUE(Connected);
            if (Connected && *Connected)
            {
                const auto Client = *Connected;
                EXPECT_EQ(Client->BindEndpoint().Host, "0.0.0.0");
                const std::string Payload = "factory echo";
                std::error_code ErrorCode;
                const auto Write = co_await Client->WriteSome(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Payload.data()),
                        Payload.size()));
                ErrorCode = Prism::Fault::ToNative(Write.Failure);
                std::array<std::byte, 256> Buffer{};
                const auto Read = co_await Client->ReadSome(Buffer);
                ErrorCode = Prism::Fault::ToNative(Read.Failure);
                const auto BytesRead = Read.Bytes;
                EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()),
                                      BytesRead),
                          Payload);
                (void)Client->Close();
            }
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        EXPECT_TRUE(co_await CloseAndWait(ClientStream, ServerStream, std::move(ServerTask)));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    /** @brief 服务端执行用户认证并核对 IPv4 CONNECT 请求。 */
    auto RunUserPassServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        Socks5::ServerConfig Config;
        Config.EnableAuth = true;
        Config.Authenticator = Prism::Testing::ProviderAccount(Prism::Testing::ProviderAccountInput{Prism::AccountId{1U}, Prism::Account::Credential::Password("Secret"), "alice", "alice", {}})->Authenticator;
        auto Accepted = co_await Socks5::Accept(Server, Config);
        if (!Accepted || !Accepted->Connection)
        {
            EXPECT_TRUE(false) << "Accept Failed";
            co_return;
        }
        const auto &Request = Accepted->RequestValue;
        const auto Conn = Accepted->Connection;
        EXPECT_EQ(Request.Cmd, Socks5::Command::Connect);
        EXPECT_EQ(Request.Target.Type, Socks5::AddressType::Ipv4);
        EXPECT_EQ(Request.Target.Host, "1.2.3.4");
        EXPECT_EQ(Request.Target.Port, 80u);
        (void)Conn->Close();
    }

    /** @brief 驱动正确的用户认证握手。 */
    auto RunUserPassAuthHandshake(TestSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto ClientStream = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto ServerStream = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = SpawnEager(ServerStream->Executor(),
                                     RunUserPassServer(ServerStream));
        std::exception_ptr ParentFailure;
        try
        {
            Socks5::ClientConfig Config;
            Config.EnableAuth = true;
            Config.Username = "alice";
            Config.Password = "Secret";
            auto Connected = co_await Socks5::Connect(Socks5::ConnectParameters{
                ClientStream, Config,
                MakeAddress(Socks5::AddressType::Ipv4, "1.2.3.4", 80)});
            EXPECT_TRUE(Connected);
            if (Connected && *Connected)
            {
                const auto Client = *Connected;
                (void)Client->Close();
            }
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        EXPECT_TRUE(co_await CloseAndWait(ClientStream, ServerStream, std::move(ServerTask)));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    /** @brief 服务端返回错误凭据对应的 BadAuth。 */
    auto RunWrongPasswordServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        Socks5::ServerConfig Config;
        Config.EnableAuth = true;
        Config.Authenticator = Prism::Testing::ProviderAccount(Prism::Testing::ProviderAccountInput{Prism::AccountId{1U}, Prism::Account::Credential::Password("Secret"), "alice", "alice", {}})->Authenticator;
        const auto Accepted = co_await Socks5::Accept(Server, Config);
        EXPECT_FALSE(Accepted);
        if (!Accepted)
            EXPECT_EQ(Accepted.error().Code, Prism::Fault::Code::AuthFailed);
    }

    /** @brief 驱动错误用户密码场景。 */
    auto RunUserPassWrongPassword(TestSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto ClientStream = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto ServerStream = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = SpawnEager(ServerStream->Executor(),
                                     RunWrongPasswordServer(ServerStream));
        std::exception_ptr ParentFailure;
        try
        {
            Socks5::ClientConfig Config;
            Config.EnableAuth = true;
            Config.Username = "alice";
            Config.Password = "wrong";
            const auto Connected = co_await Socks5::Connect(Socks5::ConnectParameters{
                ClientStream, Config,
                MakeAddress(Socks5::AddressType::Domain, "example.com", 443)});
            EXPECT_FALSE(Connected);
            if (!Connected)
                EXPECT_EQ(Connected.error().Code, Prism::Fault::Code::AuthFailed);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        EXPECT_TRUE(co_await CloseAndWait(ClientStream, ServerStream, std::move(ServerTask)));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    /** @brief 服务端验证非法 userpass 子协商版本。 */
    auto RunMalformedAuthServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        Socks5::ServerConfig Config;
        Config.EnableAuth = true;
        Config.Authenticator = Prism::Testing::ProviderAccount(Prism::Testing::ProviderAccountInput{Prism::AccountId{1U}, Prism::Account::Credential::Password("Secret"), "alice", "alice", {}})->Authenticator;
        const auto Accepted = co_await Socks5::Accept(Server, Config);
        EXPECT_FALSE(Accepted);
        if (!Accepted)
            EXPECT_EQ(Accepted.error().Code, Prism::Fault::Code::AuthFailed);
    }

    /** @brief 驱动非法 userpass 版本 raw wire 场景。 */
    auto RunUserPassMalformedVersion(TestSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = SpawnEager(Server->Executor(),
                                     RunMalformedAuthServer(Server));
        std::exception_ptr ParentFailure;
        try
        {
            std::error_code ErrorCode;
            const std::array<std::uint8_t, 4> Greeting{0x05, 0x01, 0x02};
            const auto GreetingWrite = co_await Client->WriteSome(
                AsBytes(std::span<const std::uint8_t>(Greeting)));
            ErrorCode = Prism::Fault::ToNative(GreetingWrite.Failure);
            std::array<std::uint8_t, 2> Selection{};
            const auto Read = co_await Client->ReadSome(
                AsBytes(std::span<std::uint8_t>(Selection)));
            ErrorCode = Prism::Fault::ToNative(Read.Failure);
            const auto BytesRead = Read.Bytes;
            EXPECT_EQ(BytesRead, 2u);
            EXPECT_EQ(Selection[1], 0x02);
            const std::array<std::uint8_t, 3> BadRequest{0x02, 0x01, 0x61};
            const auto RequestWrite = co_await Client->WriteSome(
                AsBytes(std::span<const std::uint8_t>(BadRequest)));
            ErrorCode = Prism::Fault::ToNative(RequestWrite.Failure);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        EXPECT_TRUE(co_await CloseAndWait(Client, Server, std::move(ServerTask)));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    /** @brief 服务端核对 SOCKS 版本错误。 */
    auto RunVersionMismatchServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        const auto Accepted =
            co_await Socks5::Accept(Server, Socks5::ServerConfig{});
        EXPECT_FALSE(Accepted);
        if (!Accepted)
            EXPECT_EQ(Accepted.error().Code, Prism::Fault::Code::BadMessage);
    }

    /** @brief 驱动版本错误握手。 */
    auto RunVersionMismatchRejected(TestSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = SpawnEager(Server->Executor(),
                                     RunVersionMismatchServer(Server));
        std::exception_ptr ParentFailure;
        try
        {
            const std::array<std::uint8_t, 3> BadGreeting{0x04, 0x01, 0x00};
            std::error_code ErrorCode;
            const auto Write = co_await Client->WriteSome(
                AsBytes(std::span<const std::uint8_t>(BadGreeting)));
            ErrorCode = Prism::Fault::ToNative(Write.Failure);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        EXPECT_TRUE(co_await CloseAndWait(Client, Server, std::move(ServerTask)));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    /** @brief 服务端要求认证且验证 no_auth 被拒绝。 */
    auto RunNoAcceptableMethodServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        Socks5::ServerConfig Config;
        Config.EnableAuth = true;
        Config.Authenticator = Prism::Testing::ProviderAccount(Prism::Testing::ProviderAccountInput{Prism::AccountId{1U}, Prism::Account::Credential::Password("Secret"), "alice", "alice", {}})->Authenticator;
        const auto Accepted = co_await Socks5::Accept(Server, Config);
        EXPECT_FALSE(Accepted);
        if (!Accepted)
            EXPECT_EQ(Accepted.error().Code, Prism::Fault::Code::NotSupported);
    }

    /** @brief 驱动无可接受认证方法。 */
    auto RunNoAcceptableMethod(TestSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = SpawnEager(Server->Executor(),
                                     RunNoAcceptableMethodServer(Server));
        std::exception_ptr ParentFailure;
        try
        {
            const auto Connected = co_await Socks5::Connect(Socks5::ConnectParameters{
                Client, Socks5::ClientConfig{},
                MakeAddress(Socks5::AddressType::Domain, "example.com", 443)});
            EXPECT_FALSE(Connected);
            if (!Connected)
                EXPECT_EQ(Connected.error().Code, Prism::Fault::Code::NotSupported);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        EXPECT_TRUE(co_await CloseAndWait(Client, Server, std::move(ServerTask)));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    /** @brief 原始服务端发送未请求的认证方法。 */
    auto RunUnexpectedMethodServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 4> Greeting{0x05, 0x01, 0x00};
        std::array<std::uint8_t, 2> Selection{0x05, 0x01};
        const auto GreetingWrite = co_await Server->WriteExact(
            AsBytes(std::span<const std::uint8_t>(Greeting)));
        EXPECT_FALSE(GreetingWrite.Failure.Failed());
        EXPECT_EQ(GreetingWrite.Bytes, Greeting.size());
        const auto SelectionWrite = co_await Server->WriteExact(
            AsBytes(std::span<const std::uint8_t>(Selection)));
        EXPECT_FALSE(SelectionWrite.Failure.Failed());
        EXPECT_EQ(SelectionWrite.Bytes, Selection.size());
    }

    /** @brief 驱动客户端拒绝未请求认证方法。 */
    auto RunClientRejectsUnexpectedMethod(TestSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = SpawnEager(Server->Executor(),
                                     RunUnexpectedMethodServer(Server));
        std::exception_ptr ParentFailure;
        try
        {
            const auto Connected = co_await Socks5::Connect(Socks5::ConnectParameters{
                Client, Socks5::ClientConfig{},
                MakeAddress(Socks5::AddressType::Domain, "example.com", 443)});
            EXPECT_FALSE(Connected);
            if (!Connected)
                EXPECT_EQ(Connected.error().Code, Prism::Fault::Code::NotSupported);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        EXPECT_TRUE(co_await CloseAndWait(Client, Server, std::move(ServerTask)));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    TEST(Socks5ConnSession, NoAuthHandshakeEcho)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunNoAuthHandshakeEcho(
                                     TestSupport::StreamPairRequest{
                                         std::move(ClientStream),
                                         std::move(ServerStream)}));
    }

    TEST(Socks5ConnSession, FactoryConnectAcceptEcho)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunFactoryConnectAcceptEcho(
                                     TestSupport::StreamPairRequest{
                                         std::move(ClientStream),
                                         std::move(ServerStream)}));
    }

    TEST(Socks5ConnSession, UserPassAuthHandshake)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunUserPassAuthHandshake(
                                     TestSupport::StreamPairRequest{
                                         std::move(ClientStream),
                                         std::move(ServerStream)}));
    }

    TEST(Socks5ConnSession, UserPassWrongPassword)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunUserPassWrongPassword(
                                     TestSupport::StreamPairRequest{
                                         std::move(ClientStream),
                                         std::move(ServerStream)}));
    }

    TEST(Socks5ConnSession, UserPassMalformedVersion)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunUserPassMalformedVersion(
                                     TestSupport::StreamPairRequest{
                                         std::move(ClientStream),
                                         std::move(ServerStream)}));
    }

    TEST(Socks5ConnSession, VersionMismatchRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunVersionMismatchRejected(
                                     TestSupport::StreamPairRequest{
                                         std::move(ClientStream),
                                         std::move(ServerStream)}));
    }

    TEST(Socks5ConnSession, NoAcceptableMethod)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunNoAcceptableMethod(
                                     TestSupport::StreamPairRequest{
                                         std::move(ClientStream),
                                         std::move(ServerStream)}));
    }

    TEST(Socks5ConnSession, ClientRejectsUnexpectedMethod)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunClientRejectsUnexpectedMethod(
                                     TestSupport::StreamPairRequest{
                                         std::move(ClientStream),
                                         std::move(ServerStream)}));
    }
}
