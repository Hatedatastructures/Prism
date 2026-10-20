/**
 * @file AuthenticatorProtocolIngressTest.cpp
 * @brief 认证器注入后的协议入口握手与关闭行为测试。
 */

#include <gtest/gtest.h>
#include <TestSupport/Prism/ProviderBindings.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

#include <Prism/Account/Account.hpp>
#include "AccountTestSupport.hpp"
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Hysteria2/Hysteria2.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Protocols/Vless/Vless.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Hysteria2 = Prism::Hysteria2;
    namespace Socks5 = Prism::Socks5;
    namespace Trojan = Prism::Trojan;
    namespace Vless = Prism::Vless;
    using Prism::ConstantTimeEqual;
    using Prism::AsBytes;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::RejectAuthenticator;

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct ServerWaitState
    {
        explicit ServerWaitState(Net::any_io_executor Executor)
            : Done(std::make_shared<CompletionChannel>(std::move(Executor), 1))
        {
        }

        std::shared_ptr<CompletionChannel> Done;
        std::exception_ptr Failure;
        Error ErrorCode{Error::IoError};
        std::optional<Prism::Fault::Failure> HandshakeFailure;
        bool HasConnection{false};
        std::shared_ptr<Prism::Transmission> ClientConnection;
        std::shared_ptr<Prism::Transmission> ServerConnection;
        std::optional<Prism::IoResult> ClientWriteResult;
        std::optional<Prism::Fault::Failure> CleanupFailure;
    };

    struct ServerWaitRequest
    {
        std::shared_ptr<ServerWaitState> State;
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
    };

    auto StartServer(Net::any_io_executor Executor, Net::awaitable<void> Server,
                     const std::shared_ptr<ServerWaitState> &State) -> void
    {
        auto Completion = [State](std::exception_ptr Failure) -> void
        {
            State->Failure = std::move(Failure);
            if (!State->Done->try_send(boost::system::error_code{}) && !State->CleanupFailure)
            {
                State->CleanupFailure = Prism::Fault::Failure{Prism::Fault::Code::Blocked};
            }
        };
        Net::co_spawn(Executor, std::move(Server), std::move(Completion));
    }

    /** @brief 记录一次控制命令或退栈失败的首个真实 typed cause。 */
    auto RecordCleanupFailure(const std::shared_ptr<ServerWaitState> &State,
                              const Prism::Fault::Failure Failure) -> void
    {
        if (!State->CleanupFailure)
        {
            State->CleanupFailure = Failure;
        }
    }

    /** @brief 保留关闭命令的失败，不把控制交付当作已忽略的成功。 */
    auto RecordCloseResult(const std::shared_ptr<ServerWaitState> &State,
                           const Prism::Transmission::ControlResult &Result) -> void
    {
        if (!Result)
        {
            RecordCleanupFailure(State, Result.error());
        }
    }

    /** @brief 先提交协议连接关闭，再等待它自己的真实 I/O completion 退栈。 */
    auto DrainConnection(const std::shared_ptr<ServerWaitState> &State,
                         const std::shared_ptr<Prism::Transmission> &Connection)
        -> Net::awaitable<void>
    {
        if (!Connection)
        {
            co_return;
        }
        const auto Closed = Connection->Close();
        RecordCloseResult(State, Closed);
        const auto Drained = co_await Connection->Activity()->Drain();
        if (!Drained)
        {
            RecordCleanupFailure(State, Drained.error());
        }
    }

    /** @brief 关闭一个底层 endpoint 并等待 MemoryStream 自身的控制与 I/O owner。 */
    auto DrainEndpoint(const std::shared_ptr<ServerWaitState> &State,
                       const std::shared_ptr<Prism::Transmission> &Connection,
                       const std::shared_ptr<MemoryStream> &Memory) -> Net::awaitable<void>
    {
        if (Connection)
        {
            co_await DrainConnection(State, Connection);
        }
        else
        {
            const auto Closed = Memory->Close();
            RecordCloseResult(State, Closed);
        }
        const auto Drained = co_await Memory->Activity()->Drain();
        if (!Drained)
        {
            RecordCleanupFailure(State, Drained.error());
        }
    }

    /** @brief 两端 protocol owner 与其底层 memory stream 都要真实退出。 */
    auto DrainServerWaitRequest(ServerWaitRequest Request) -> Net::awaitable<void>
    {
        co_await DrainEndpoint(Request.State, Request.State->ClientConnection, Request.Client);
        co_await DrainEndpoint(Request.State, Request.State->ServerConnection, Request.Server);
    }

    auto WaitForServer(ServerWaitRequest Request) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Watchdog(Executor);
        Watchdog.expires_after(std::chrono::seconds(5));
        auto Completion = co_await (Request.State->Done->async_receive(Net::use_awaitable) ||
                                    Watchdog.async_wait(Net::use_awaitable));
        if (Completion.index() == 0U)
        {
            co_await DrainServerWaitRequest(Request);
            EXPECT_FALSE(Request.State->CleanupFailure.has_value());
            co_return true;
        }

        const auto ClientClosed = Request.Client->Close();
        RecordCloseResult(Request.State, ClientClosed);
        const auto ServerClosed = Request.Server->Close();
        RecordCloseResult(Request.State, ServerClosed);
        Watchdog.expires_after(std::chrono::seconds(1));
        auto Grace = co_await (Request.State->Done->async_receive(Net::use_awaitable) ||
                               Watchdog.async_wait(Net::use_awaitable));
        co_await DrainServerWaitRequest(Request);
        EXPECT_FALSE(Request.State->CleanupFailure.has_value());
        co_return Grace.index() == 0U;
    }

    struct Socks5AcceptRequest final
    {
        std::shared_ptr<MemoryStream> Server;
        std::shared_ptr<ServerWaitState> State;
        std::shared_ptr<Socks5::ServerConfig> Config;
    };

    auto AcceptSocks5AndRecord(Socks5AcceptRequest Request) -> Net::awaitable<void>
    {
        const auto Accepted = co_await Socks5::Accept(Request.Server, *Request.Config);
        if (!Accepted)
        {
            Request.State->HandshakeFailure = Accepted.error();
            co_return;
        }
        Request.State->ErrorCode = Error::None;
        Request.State->HasConnection = Accepted->Connection != nullptr;
        Request.State->ServerConnection = std::move(Accepted->Connection);
    }

    auto RunSocks5InjectedAuth(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State) -> Net::awaitable<void>
    {
        auto Auth = Prism::Testing::ProviderAccount(Prism::Testing::ProviderAccountInput{Prism::AccountId{1U}, Prism::Account::Credential::Password("s3cret"), "alice", "alice", {}})->Authenticator;
        auto Config = std::make_shared<Socks5::ServerConfig>();
        Config->EnableAuth = true;
        Config->Authenticator = Auth;
        StartServer(Server->Executor(), AcceptSocks5AndRecord({Server, State, Config}), State);

        Socks5::ClientConfig ClientConfigValue;
        ClientConfigValue.EnableAuth = true;
        ClientConfigValue.Username = "alice";
        ClientConfigValue.Password = "s3cret";
        const auto Connected = co_await Socks5::Connect(Socks5::ConnectParameters{
            Client, ClientConfigValue,
            Socks5::Address{Socks5::AddressType::Domain, "t.internal", 443}});
        EXPECT_TRUE(Connected);
        if (Connected)
        {
            State->ClientConnection = *Connected;
            const auto Closed = (*Connected)->Close();
            RecordCloseResult(State, Closed);
        }
        const auto Completed = co_await WaitForServer({State, Client, Server});
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(State->Failure);
        EXPECT_EQ(State->ErrorCode, Error::None);
        EXPECT_FALSE(State->HandshakeFailure.has_value());
        EXPECT_TRUE(State->HasConnection);
    }

    auto RunSocks5RejectAuth(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State) -> Net::awaitable<void>
    {
        auto Auth = std::make_shared<RejectAuthenticator>();
        auto Config = std::make_shared<Socks5::ServerConfig>();
        Config->EnableAuth = true;
        Config->Authenticator = Auth;
        StartServer(Server->Executor(), AcceptSocks5AndRecord({Server, State, Config}), State);

        Socks5::ClientConfig ClientConfigValue;
        ClientConfigValue.EnableAuth = true;
        ClientConfigValue.Username = "alice";
        ClientConfigValue.Password = "s3cret";
        const auto Connected = co_await Socks5::Connect(Socks5::ConnectParameters{
            Client, ClientConfigValue,
            Socks5::Address{Socks5::AddressType::Domain, "t.internal", 443}});
        EXPECT_FALSE(Connected);
        if (Connected)
        {
            State->ClientConnection = *Connected;
            const auto Closed = (*Connected)->Close();
            RecordCloseResult(State, Closed);
        }
        const auto Completed = co_await WaitForServer({State, Client, Server});
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(State->Failure);
        EXPECT_TRUE(State->HandshakeFailure.has_value());
        if (State->HandshakeFailure)
        {
            EXPECT_EQ(State->HandshakeFailure->Code, Prism::Fault::Code::AuthFailed);
        }
        EXPECT_FALSE(State->HasConnection);
    }

    auto AcceptTrojanAndRecord(
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State,
        std::shared_ptr<Trojan::ServerConfig> Config) -> Net::awaitable<void>
    {
        auto Result = co_await Trojan::Accept(std::move(Server), *Config);
        if (!Result)
        {
            State->HandshakeFailure = Result.error();
            co_return;
        }
        if (!Result->Connection)
        {
            State->HandshakeFailure = Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument};
            co_return;
        }
        State->ErrorCode = Error::None;
        State->HasConnection = true;
        State->ServerConnection = std::move(Result->Connection);
    }

    auto RunTrojanInjectedAuth(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State) -> Net::awaitable<void>
    {
        auto Auth = Prism::Testing::ProviderAccount(Prism::Account::Credential::Token(Trojan::Credential("prism")), Prism::AccountId{1U}, {})->Authenticator;
        auto Config = std::make_shared<Trojan::ServerConfig>();
        Config->Password = "prism";
        Config->AuthenticatorOwner = Auth;
        StartServer(Server->Executor(), AcceptTrojanAndRecord(Server, State, Config), State);

        Trojan::ClientConfig ClientConfigValue;
        ClientConfigValue.Password = "prism";
        auto ConnectResult = co_await Trojan::Connect(Trojan::ConnectParameters{
            Client, ClientConfigValue,
            Trojan::Address{Trojan::AddressType::Domain, "t.internal", 443}});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        if (ConnectResult && *ConnectResult) State->ClientConnection = std::move(*ConnectResult);
        const auto Completed = co_await WaitForServer({State, Client, Server});
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(State->Failure);
        EXPECT_EQ(State->ErrorCode, Error::None);
        EXPECT_TRUE(State->HasConnection);
    }

    auto AcceptVlessAndRecord(
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State,
        std::shared_ptr<Vless::ServerConfig> Config) -> Net::awaitable<void>
    {
        auto Result = co_await Vless::Accept(std::move(Server), *Config);
        if (!Result)
        {
            State->HandshakeFailure = Result.error();
            co_return;
        }
        if (!Result->Connection)
        {
            State->HandshakeFailure = Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument};
            co_return;
        }
        State->ErrorCode = Error::None;
        State->HasConnection = true;
        State->ServerConnection = std::move(Result->Connection);
    }

    auto RunVlessInjectedAuth(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State) -> Net::awaitable<void>
    {
        const auto Uuid = std::array<std::uint8_t, 16>{1, 2, 3, 4, 5, 6, 7, 8,
                                                       9, 10, 11, 12, 13, 14, 15, 16};
        Prism::Account::UuidBytes CredentialBytes{};
        for (std::size_t Index = 0; Index < CredentialBytes.size(); ++Index)
        {
            CredentialBytes[Index] = static_cast<std::byte>(Uuid[Index]);
        }
        auto Auth = Prism::Testing::ProviderAccount(Prism::Account::Credential::Uuid(CredentialBytes), Prism::AccountId{1U}, {})->Authenticator;
        auto Config = std::make_shared<Vless::ServerConfig>();
        Config->uuid = Uuid;
        Config->AuthenticatorOwner = Auth;
        StartServer(Server->Executor(), AcceptVlessAndRecord(Server, State, Config), State);

        Vless::ClientConfig ClientConfigValue;
        ClientConfigValue.uuid = Uuid;
        auto ConnectResult = co_await Vless::Connect(Vless::ConnectParameters{
            Client, ClientConfigValue,
            Vless::Address{Vless::AddressType::Domain, "t.internal", 443}});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        if (ConnectResult && *ConnectResult) State->ClientConnection = std::move(*ConnectResult);
        const auto Completed = co_await WaitForServer({State, Client, Server});
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(State->Failure);
        EXPECT_EQ(State->ErrorCode, Error::None);
        EXPECT_TRUE(State->HasConnection);
    }

    auto RunHysteria2InjectedAuth(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State) -> Net::awaitable<void>
    {
        auto Auth = Prism::Testing::ProviderAccount(Prism::Account::Credential::Token("h2pass"), Prism::AccountId{1U}, {})->Authenticator;
        auto Config = std::make_shared<Hysteria2::ServerConfig>();
        Config->password = "h2pass";
        Config->AuthenticatorOwner = Auth;
        auto ServerCoroutine = [Server, State, Config]() -> Net::awaitable<void>
        {
            auto [ErrorCode, Request, Conn] = co_await Hysteria2::Accept(Server, *Config);
            State->ErrorCode = ErrorCode;
            State->HasConnection = Conn != nullptr;
            State->ServerConnection = std::move(Conn);
        };
        StartServer(Server->Executor(), ServerCoroutine(), State);

        Hysteria2::ClientConfig ClientConfigValue;
        ClientConfigValue.password = "h2pass";
        auto [ErrorCode, Conn] = co_await Hysteria2::Connect(
            Client, ClientConfigValue,
            Hysteria2::Address{Hysteria2::AddressType::Domain, "t.internal", 443});
        EXPECT_EQ(ErrorCode, Error::None);
        State->ClientConnection = Conn;
        const auto Completed = co_await WaitForServer({State, Client, Server});
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(State->Failure);
        EXPECT_EQ(State->ErrorCode, Error::None);
        EXPECT_TRUE(State->HasConnection);
    }

    auto RunHysteria2RejectAuth(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server,
        std::shared_ptr<ServerWaitState> State) -> Net::awaitable<void>
    {
        auto Auth = std::make_shared<RejectAuthenticator>();
        auto Config = std::make_shared<Hysteria2::ServerConfig>();
        Config->password = "h2pass";
        Config->AuthenticatorOwner = Auth;
        auto ServerCoroutine = [Server, State, Config]() -> Net::awaitable<void>
        {
            auto [ErrorCode, Request, Conn] = co_await Hysteria2::Accept(Server, *Config);
            State->ErrorCode = ErrorCode;
            State->HasConnection = Conn != nullptr;
            State->ServerConnection = std::move(Conn);
        };
        StartServer(Server->Executor(), ServerCoroutine(), State);

        const std::vector<std::uint8_t> Junk{0x01, 0x02, 0x03};
        State->ClientWriteResult = co_await Client->WriteSome(
            AsBytes(std::span<const std::uint8_t>(Junk)));
        const auto ClientClosed = Client->Close();
        RecordCloseResult(State, ClientClosed);
        const auto Completed = co_await WaitForServer({State, Client, Server});
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(State->Failure);
        EXPECT_NE(State->ErrorCode, Error::None);
        EXPECT_FALSE(State->HasConnection);
    }

    TEST(Authenticator, Socks5InjectedAuth)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto State = std::make_shared<ServerWaitState>(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(
            IoContext,
            RunSocks5InjectedAuth(Client, Server, State),
            [&](std::exception_ptr ExceptionValue)
            { Exception = ExceptionValue; });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(Authenticator, Socks5RejectAuth)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto State = std::make_shared<ServerWaitState>(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(
            IoContext,
            RunSocks5RejectAuth(Client, Server, State),
            [&](std::exception_ptr ExceptionValue)
            { Exception = ExceptionValue; });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(Authenticator, TrojanInjectedAuth)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto State = std::make_shared<ServerWaitState>(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(
            IoContext,
            RunTrojanInjectedAuth(Client, Server, State),
            [&](std::exception_ptr ExceptionValue)
            { Exception = ExceptionValue; });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(Authenticator, VlessInjectedAuth)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto State = std::make_shared<ServerWaitState>(IoContext.get_executor());
        std::exception_ptr Exception;
        const auto Uuid = std::array<std::uint8_t, 16>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        Net::co_spawn(
            IoContext,
            RunVlessInjectedAuth(Client, Server, State),
            [&](std::exception_ptr ExceptionValue)
            { Exception = ExceptionValue; });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(Authenticator, Hysteria2InjectedAuth)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto State = std::make_shared<ServerWaitState>(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(
            IoContext,
            RunHysteria2InjectedAuth(Client, Server, State),
            [&](std::exception_ptr ExceptionValue)
            { Exception = ExceptionValue; });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(Authenticator, Hysteria2RejectAuth)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto State = std::make_shared<ServerWaitState>(IoContext.get_executor());
        std::exception_ptr Exception;

        Net::co_spawn(
            IoContext,
            RunHysteria2RejectAuth(Client, Server, State),
            [&](std::exception_ptr ExceptionValue)
            { Exception = ExceptionValue; });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
        ASSERT_TRUE(State->ClientWriteResult.has_value());
        EXPECT_EQ(State->ClientWriteResult->Bytes, 3U);
        EXPECT_TRUE(State->ClientWriteResult->Failure.Succeeded());
    }

} // namespace
