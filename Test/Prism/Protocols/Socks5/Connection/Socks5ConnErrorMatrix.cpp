/**
 * @file Socks5ConnErrorMatrix.cpp
 * @brief SOCKS5 Conn 错误矩阵测试
 * @details 服务端握手错误路径全覆盖：
 * - 版本不匹配（Greeting/Request）
 * - 无可用认证方法
 * - 认证失败（错误凭据）
 * - 非法命令 / 非法地址类型
 * - 半包截断（Greeting/认证/请求各阶段）
 * - 意外 EOF
 * - 客户端握手错误（响应校验失败）
 */

#include <gtest/gtest.h>
#include <TestSupport/Prism/ProviderBindings.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include "Socks5ConnSessionSupport.hpp"

namespace
{
    namespace Prism = ::Prism;
    namespace Net = boost::asio;
    namespace Socks5 = Prism::Socks5;
    namespace ConnSupport = Prism::Socks5ConnTestSupport;
    using ConnSupport::MakeAddress;
    using Prism::AsBytes;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;

    struct ErrorScenario final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
        Socks5::ServerConfig Config;
        std::vector<std::uint8_t> Wire;
        Prism::Fault::Code Expected;
    };

    /** @brief 接收 SOCKS5 错误握手并保存 Expected error。 */
    auto RunErrorServer(ErrorScenario Request) -> Net::awaitable<void>
    {
        const auto Accepted = co_await Socks5::Accept(
            std::move(Request.Server), Request.Config);
        EXPECT_FALSE(Accepted);
        if (!Accepted)
            EXPECT_EQ(Accepted.error().Code, Request.Expected);
    }

    /** @brief eager 启动 server、发送 raw wire 并等待真实结束。 */
    auto RunErrorScenario(ErrorScenario Request) -> Net::awaitable<void>
    {
        auto ServerTask = ConnSupport::SpawnEager(
            Request.Server->Executor(), RunErrorServer(Request));
        std::exception_ptr ParentFailure;
        try
        {
            const auto Write = co_await Request.Client->WriteExact(
                AsBytes(std::span<const std::uint8_t>(Request.Wire)));
            EXPECT_FALSE(Write.Failure.Failed());
            EXPECT_EQ(Write.Bytes, Request.Wire.size());
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        const auto Closed = co_await ConnSupport::CloseAndWait(
            Request.Client, Request.Server, std::move(ServerTask));
        EXPECT_TRUE(Closed);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    auto SendBadReply(Prism::SharedTransmission Stream) -> Net::awaitable<void>
    {
        std::array<std::byte, 8> Buffer{};
        std::error_code ErrorCode;
        (void)co_await ConnSupport::ReadInto(*Stream, Buffer, ErrorCode);
        const std::array<std::byte, 2> Selection{std::byte{0x04}, std::byte{0x00}};
        (void)co_await ConnSupport::WriteInto(*Stream, Selection, ErrorCode);
    }

    auto SendBadReservedReply(Prism::SharedTransmission Stream) -> Net::awaitable<void>
    {
        std::array<std::byte, 3> Greeting{};
        std::array<std::byte, 2> Selection{std::byte{0x05}, std::byte{0x00}};
        std::array<std::byte, 10> Request{};
        std::array<std::byte, 10> Reply{
            std::byte{0x05}, std::byte{0x00}, std::byte{0x01}, std::byte{0x01},
            std::byte{127}, std::byte{0}, std::byte{0}, std::byte{1}, std::byte{0x01}, std::byte{0xBB}};
        std::error_code ErrorCode;
        if (co_await ConnSupport::ReadExactInto(*Stream, Greeting, ErrorCode) != Greeting.size() ||
            co_await ConnSupport::WriteInto(*Stream, Selection, ErrorCode) != Selection.size() ||
            co_await ConnSupport::ReadExactInto(*Stream, Request, ErrorCode) != Request.size())
        {
            co_return;
        }
        (void)co_await ConnSupport::WriteInto(*Stream, Reply, ErrorCode);
    }

    auto SendNoAuthDowngradeReply(Prism::SharedTransmission Stream) -> Net::awaitable<void>
    {
        std::array<std::byte, 3> Greeting{};
        const std::array<std::byte, 2> Selection{std::byte{0x05}, std::byte{0x00}};
        std::error_code ErrorCode;
        if (co_await ConnSupport::ReadExactInto(*Stream, Greeting, ErrorCode) != Greeting.size() ||
            co_await ConnSupport::WriteInto(*Stream, Selection, ErrorCode) != Selection.size())
        {
            co_return;
        }
        (void)Stream->Close();
    }

    enum class ClientReplyMode
    {
        BadReply,
        ReservedByte,
        NoAuthDowngrade
    };

    struct ClientReplyScenario final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
        Socks5::ClientConfig Config;
        Socks5::Address Target;
        Prism::Fault::Code Expected;
        ClientReplyMode Mode;
    };

    /** @brief 启动指定坏响应 server 并验证 client handshake 错误。 */
    auto RunClientReplyScenario(ClientReplyScenario Request) -> Net::awaitable<void>
    {
        Net::awaitable<void> ServerOperation;
        if (Request.Mode == ClientReplyMode::BadReply)
        {
            ServerOperation = SendBadReply(Request.Server);
        }
        else if (Request.Mode == ClientReplyMode::ReservedByte)
        {
            ServerOperation = SendBadReservedReply(Request.Server);
        }
        else
        {
            ServerOperation = SendNoAuthDowngradeReply(Request.Server);
        }
        auto ServerTask = ConnSupport::SpawnEager(Request.Server->Executor(), std::move(ServerOperation));
        std::exception_ptr ParentFailure;
        try
        {
            const auto Connected = co_await Socks5::Connect(Socks5::ConnectParameters{
                Request.Client, Request.Config, Request.Target});
            EXPECT_FALSE(Connected);
            if (!Connected)
                EXPECT_EQ(Connected.error().Code, Request.Expected);
            const auto Connection = Connected
                ? *Connected
                : Socks5::SharedConn{};
            if (Request.Mode != ClientReplyMode::BadReply)
            {
                EXPECT_FALSE(Connection);
            }
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        const auto Closed = co_await ConnSupport::CloseAndWait(
            Request.Client, Request.Server, std::move(ServerTask));
        EXPECT_TRUE(Closed);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    /** @brief 启用认证但只提供 no_auth，验证无可接受方法。 */
    auto RunNoAcceptableMethod(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server) -> Net::awaitable<void>
    {
        Socks5::ServerConfig Config;
        Config.EnableAuth = true;
        auto ServerTask = ConnSupport::SpawnEager(
            Server->Executor(),
            [Server, Config]() mutable -> Net::awaitable<void>
            {
                const auto Accepted = co_await Socks5::Accept(Server, Config);
                EXPECT_FALSE(Accepted);
                if (!Accepted)
                    EXPECT_EQ(Accepted.error().Code, Prism::Fault::Code::NotSupported);
            }());
        std::exception_ptr ParentFailure;
        try
        {
            const std::vector<std::uint8_t> Wire{0x05, 0x01, 0x00};
            std::error_code ErrorCode;
            co_await ConnSupport::WriteInto(*Client, AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            EXPECT_FALSE(ErrorCode);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        const auto Closed = co_await ConnSupport::CloseAndWait(
            Client, Server, std::move(ServerTask));
        EXPECT_TRUE(Closed);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    /** @brief 服务端关闭 TCP 命令后的拒绝结果。 */
    auto RunTcpDisabledServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        Socks5::ServerConfig Config;
        Config.EnableTcp = false;
        const auto Accepted = co_await Socks5::Accept(Server, Config);
        EXPECT_FALSE(Accepted);
        if (!Accepted)
            EXPECT_EQ(Accepted.error().Code, Prism::Fault::Code::NotSupported);
    }
    /** @brief 驱动 TCP 命令关闭场景。 */
    auto RunTcpDisabledRejected(ConnSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = ConnSupport::SpawnEager(
            Server->Executor(), RunTcpDisabledServer(Server));
        std::exception_ptr ParentFailure;
        try
        {
            const auto Connected = co_await Socks5::Connect(Socks5::ConnectParameters{
                Client, Socks5::ClientConfig{},
                MakeAddress(Socks5::AddressType::Domain, "example.com", 443)});
            EXPECT_FALSE(Connected);
            if (!Connected)
                EXPECT_EQ(Connected.error().Code, Prism::Fault::Code::UnsupportedCommand);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        co_await ConnSupport::CloseAndWait(Client, Server,
                                           std::move(ServerTask));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    /** @brief 服务端关闭 UDP 命令后的拒绝结果。 */
    auto RunUdpDisabledServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        Socks5::ServerConfig Config;
        Config.EnableUdp = false;
        const auto Accepted = co_await Socks5::Accept(Server, Config);
        EXPECT_FALSE(Accepted);
        if (!Accepted)
            EXPECT_EQ(Accepted.error().Code, Prism::Fault::Code::NotSupported);
    }
    /** @brief 驱动 UDP 命令关闭场景。 */
    auto RunUdpDisabledRejected(ConnSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = ConnSupport::SpawnEager(
            Server->Executor(), RunUdpDisabledServer(Server));
        std::exception_ptr ParentFailure;
        try
        {
            const Socks5::ConnectParameters Parameters{
                Client, Socks5::ClientConfig{},
                MakeAddress(Socks5::AddressType::Domain, "example.com", 443),
                Socks5::Command::UdpAssociate};
            const auto Connected = co_await Socks5::Connect(Parameters);
            EXPECT_FALSE(Connected);
            if (!Connected)
                EXPECT_EQ(Connected.error().Code, Prism::Fault::Code::UnsupportedCommand);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        co_await ConnSupport::CloseAndWait(Client, Server,
                                           std::move(ServerTask));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    /** @brief 服务端处理非法 command。 */
    auto RunBadCommandServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        const auto Accepted =
            co_await Socks5::Accept(Server, Socks5::ServerConfig{});
        EXPECT_FALSE(Accepted);
        if (!Accepted)
            EXPECT_EQ(Accepted.error().Code, Prism::Fault::Code::NotSupported);
    }
    /** @brief 驱动非法 command raw wire。 */
    auto RunBadCommandRejected(ConnSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = ConnSupport::SpawnEager(
            Server->Executor(), RunBadCommandServer(Server));
        std::exception_ptr ParentFailure;
        try
        {
            std::error_code ErrorCode;
            const std::array<std::uint8_t, 3> Greeting{0x05, 0x01, 0x00};
            co_await ConnSupport::WriteInto(*Client,
                AsBytes(std::span<const std::uint8_t>(Greeting)), ErrorCode);
            const std::array<std::uint8_t, 10> RequestWire{
                0x05, 0x09, 0x00, 0x03, 0x0B, 'e', 'x', 'a', 'm', 'p'};
            co_await ConnSupport::WriteInto(*Client,
                AsBytes(std::span<const std::uint8_t>(RequestWire)), ErrorCode);
            std::array<std::uint8_t, 2> Selection{};
            co_await ConnSupport::ReadInto(*Client,
                AsBytes(std::span<std::uint8_t>(Selection)), ErrorCode);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        co_await ConnSupport::CloseAndWait(Client, Server,
                                           std::move(ServerTask));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    /** @brief 服务端处理非法 ATYP。 */
    auto RunBadAtypServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        const auto Accepted =
            co_await Socks5::Accept(Server, Socks5::ServerConfig{});
        EXPECT_FALSE(Accepted);
        if (!Accepted)
            EXPECT_EQ(Accepted.error().Code, Prism::Fault::Code::BadMessage);
    }
    /** @brief 驱动非法 ATYP raw wire。 */
    auto RunBadAtypRejected(ConnSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = ConnSupport::SpawnEager(
            Server->Executor(), RunBadAtypServer(Server));
        std::exception_ptr ParentFailure;
        try
        {
            std::error_code ErrorCode;
            const std::array<std::uint8_t, 3> Greeting{0x05, 0x01, 0x00};
            co_await ConnSupport::WriteInto(*Client,
                AsBytes(std::span<const std::uint8_t>(Greeting)), ErrorCode);
            const std::array<std::uint8_t, 6> RequestWire{
                0x05, 0x01, 0x00, 0x99, 0x00, 0x50};
            co_await ConnSupport::WriteInto(*Client,
                AsBytes(std::span<const std::uint8_t>(RequestWire)), ErrorCode);
            std::array<std::uint8_t, 2> Selection{};
            co_await ConnSupport::ReadInto(*Client,
                AsBytes(std::span<std::uint8_t>(Selection)), ErrorCode);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        co_await ConnSupport::CloseAndWait(Client, Server,
                                           std::move(ServerTask));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    /** @brief 驱动已关闭对端的 client IO 错误。 */
    auto RunClientIoErrorOnClosedPeer(ConnSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        (void)Server->Close();
        const auto Connected = co_await Socks5::Connect(Socks5::ConnectParameters{
            Client, Socks5::ClientConfig{},
            MakeAddress(Socks5::AddressType::Domain, "example.com", 443)});
        EXPECT_FALSE(Connected);
        if (!Connected)
            EXPECT_EQ(Connected.error().Code, Prism::Fault::Code::ConnectionAborted);
        (void)Client->Close();
    }
    /** @brief 原始服务端读 greeting 后关闭，使 client 观察 EOF。 */
    auto RunGreetingEofServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 4> Greeting{};
        std::error_code ErrorCode;
        const auto BytesRead = co_await ConnSupport::ReadInto(
            *Server, AsBytes(std::span<std::uint8_t>(Greeting)), ErrorCode);
        EXPECT_GT(BytesRead, 0u);
        (void)Server->Close();
    }
    /** @brief 驱动 client greeting EOF 场景。 */
    auto RunClientGreetingEof(ConnSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = ConnSupport::SpawnEager(
            Server->Executor(), RunGreetingEofServer(Server));
        std::exception_ptr ParentFailure;
        try
        {
            const auto Connected = co_await Socks5::Connect(Socks5::ConnectParameters{
                Client, Socks5::ClientConfig{},
                MakeAddress(Socks5::AddressType::Domain, "example.com", 443)});
            EXPECT_FALSE(Connected);
            if (!Connected)
                EXPECT_EQ(Connected.error().Code, Prism::Fault::Code::Eof);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        co_await ConnSupport::CloseAndWait(Client, Server,
                                           std::move(ServerTask));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    /** @brief 验证 Conn 装饰器链、透传、ReadExact、Close/Cancel/Release。 */
    auto RunDecoratorChain(ConnSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto ClientStream =
            std::make_shared<MemoryStream>(std::move(Request.Client));
        auto ServerStream =
            std::make_shared<MemoryStream>(std::move(Request.Server));
        auto Connection = std::make_shared<Socks5::Conn<>>(ClientStream);
        EXPECT_TRUE(Connection->Executor());
        EXPECT_NE(Connection->NextLayer(), nullptr);
        EXPECT_NE(Connection->lowest_layer<MemoryStream>(), nullptr);

        const std::string Payload = "passthrough";
        std::error_code ErrorCode;
        co_await ConnSupport::WriteInto(*Connection,
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()),
                Payload.size()),
            ErrorCode);
        EXPECT_FALSE(ErrorCode);
        std::array<std::byte, 64> Buffer{};
        const auto BytesRead =
            co_await ConnSupport::ReadInto(*ServerStream, Buffer, ErrorCode);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()),
                              BytesRead),
                  Payload);
        std::array<std::byte, 4> Destination{};
        co_await ConnSupport::WriteInto(*ServerStream,
            std::span<const std::byte>(Buffer.data(), 4), ErrorCode);
        const auto Read = co_await Connection->ReadExact(std::span<std::byte>(Destination));
        EXPECT_EQ(Read.Bytes, Destination.size());
        EXPECT_FALSE(Read.Failure.Failed());
        (void)Connection->Close();
        (void)Connection->Cancel();
        const Socks5::Conn<> *ConnectionPointer = Connection.get();
        EXPECT_NE(ConnectionPointer->NextLayer(), nullptr);
        auto Released = Connection->Release();
        EXPECT_TRUE(Released);
        EXPECT_EQ(Connection->NextLayer(), nullptr);
    }
    /** @brief 完成握手后验证 Conn 的有效性和底层传输。 */
    auto RunValidAfterHandshakeServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        const auto Accepted =
            co_await Socks5::Accept(Server, Socks5::ServerConfig{});
        if (Accepted && Accepted->Connection)
        {
            const auto Conn = Accepted->Connection;
            EXPECT_TRUE(Conn->IsValid());
            EXPECT_TRUE(Conn->Underlying() != nullptr);
            (void)Conn->Close();
        }
    }
    /** @brief 驱动 Conn 有效性检查的完整握手。 */
    auto RunValidAfterHandshake(ConnSupport::StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ServerTask = ConnSupport::SpawnEager(
            Server->Executor(), RunValidAfterHandshakeServer(Server));
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
            std::error_code ErrorCode;
            co_await ConnSupport::WriteInto(*Client,
                AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            std::array<std::uint8_t, 12> Response{};
            co_await ConnSupport::ReadInto(*Client,
                AsBytes(std::span<std::uint8_t>(Response)), ErrorCode);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        co_await ConnSupport::CloseAndWait(Client, Server,
                                           std::move(ServerTask));
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    TEST(Socks5ConnErrorMatrix, BadVersionGreeting)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunErrorScenario(ErrorScenario{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory)),
             Socks5::ServerConfig{}, {0x04, 0x01, 0x00},
             Prism::Fault::Code::BadMessage}));
    }

    TEST(Socks5ConnErrorMatrix, GreetingTruncated)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunErrorScenario(ErrorScenario{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory)),
             Socks5::ServerConfig{}, {0x05, 0x02}, Prism::Fault::Code::Eof}));
    }

    TEST(Socks5ConnErrorMatrix, AuthFailure)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        Socks5::ServerConfig Config;
        Config.EnableAuth = true;
        Config.Authenticator = Prism::Testing::ProviderAccount(Prism::Testing::ProviderAccountInput{Prism::AccountId{1U}, Prism::Account::Credential::Password("correct"), "alice", "alice", {}})->Authenticator;
        ConnSupport::RunCoroutine(IoContext, RunErrorScenario(ErrorScenario{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory)),
            Config,
            {0x05, 0x01, 0x02, 0x01, 0x05, 'a', 'l', 'i', 'c', 'e', 0x07,
             'w', 'r', 'o', 'n', 'g', 'p', 'w'},
             Prism::Fault::Code::AuthFailed}));
    }

    TEST(Socks5ConnErrorMatrix, BadCommand)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunErrorScenario(ErrorScenario{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory)),
            Socks5::ServerConfig{},
            {0x05, 0x01, 0x00, 0x05, 0x99, 0x00, 0x01, 10, 0, 0, 1, 0x01, 0xBB},
            Prism::Fault::Code::NotSupported}));
    }

    TEST(Socks5ConnErrorMatrix, BadAddressType)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunErrorScenario(ErrorScenario{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory)),
            Socks5::ServerConfig{},
            {0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x09, 0x00, 0x50},
            Prism::Fault::Code::BadMessage}));
    }

    TEST(Socks5ConnErrorMatrix, BadReservedRequestByte)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunErrorScenario(ErrorScenario{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory)),
            Socks5::ServerConfig{},
            {0x05, 0x01, 0x00, 0x05, 0x01, 0x01, 0x01, 10, 0, 0, 1, 0x01, 0xBB},
            Prism::Fault::Code::BadMessage}));
    }

    TEST(Socks5ConnErrorMatrix, RequestTruncated)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunErrorScenario(ErrorScenario{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory)),
            Socks5::ServerConfig{},
            {0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x14,
             'h', 'e', 'l', 'l', 'o'},
             Prism::Fault::Code::Eof}));
    }

    TEST(Socks5ConnErrorMatrix, ClientBadReply)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunClientReplyScenario(ClientReplyScenario{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Socks5::ClientConfig{},
            MakeAddress(Socks5::AddressType::Domain, "example.com", 443),
            Prism::Fault::Code::BadMessage,
            ClientReplyMode::BadReply}));
    }

    TEST(Socks5ConnErrorMatrix, ClientRejectsNonZeroReservedReply)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunClientReplyScenario(ClientReplyScenario{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Socks5::ClientConfig{},
            MakeAddress(Socks5::AddressType::Ipv4, "127.0.0.1", 443),
            Prism::Fault::Code::BadMessage,
            ClientReplyMode::ReservedByte}));
    }

    TEST(Socks5ConnErrorMatrix, ClientRejectsNoAuthDowngradeWhenAuthEnabled)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        Socks5::ClientConfig Config;
        Config.EnableAuth = true;
        Config.Username = "alice";
        Config.Password = "secret";
        ConnSupport::RunCoroutine(IoContext, RunClientReplyScenario(ClientReplyScenario{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Config,
            MakeAddress(Socks5::AddressType::Domain, "example.com", 443),
            Prism::Fault::Code::NotSupported,
            ClientReplyMode::NoAuthDowngrade}));
    }

    TEST(Socks5ConnErrorMatrix, NoAcceptableMethod)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunNoAcceptableMethod(
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream))));
    }
    TEST(Socks5ConnSession, TcpDisabledRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunTcpDisabledRejected(
            ConnSupport::StreamPairRequest{
                std::move(ClientMemory), std::move(ServerMemory)}));
    }
    TEST(Socks5ConnSession, UdpDisabledRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunUdpDisabledRejected(
            ConnSupport::StreamPairRequest{
                std::move(ClientMemory), std::move(ServerMemory)}));
    }
    TEST(Socks5ConnSession, BadCommandRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunBadCommandRejected(
            ConnSupport::StreamPairRequest{
                std::move(ClientMemory), std::move(ServerMemory)}));
    }
    TEST(Socks5ConnSession, BadAtypRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunBadAtypRejected(
            ConnSupport::StreamPairRequest{
                std::move(ClientMemory), std::move(ServerMemory)}));
    }
    TEST(Socks5ConnSession, ClientIoErrorOnClosedPeer)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunClientIoErrorOnClosedPeer(
            ConnSupport::StreamPairRequest{
                std::move(ClientMemory), std::move(ServerMemory)}));
    }
    TEST(Socks5ConnSession, ClientGreetingEof)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunClientGreetingEof(
            ConnSupport::StreamPairRequest{
                std::move(ClientMemory), std::move(ServerMemory)}));
    }
    TEST(Socks5ConnSession, DecoratorChain)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunDecoratorChain(
            ConnSupport::StreamPairRequest{
                std::move(ClientMemory), std::move(ServerMemory)}));
    }
    TEST(Socks5ConnDeep, ValidAfterHandshake)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ConnSupport::RunCoroutine(IoContext, RunValidAfterHandshake(
            ConnSupport::StreamPairRequest{
                std::move(ClientMemory), std::move(ServerMemory)}));
    }

} // namespace
