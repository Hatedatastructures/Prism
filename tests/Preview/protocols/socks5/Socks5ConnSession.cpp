/**
 * @file Socks5ConnSession.cpp
 * @brief SOCKS5 Conn 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手（无认证 + RFC 1929 用户认证）
 * 2. 预读缓冲消费路径（async_read_some 的 Used_ > 0 分支）
 * 3. 错误分支：version_mismatch / not_supported / bad_auth / bad_message
 * 4. 命令开关：EnableTcp / EnableUdp 关闭时的拒绝路径
 * 5. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Preview::Socks5;
    using Preview::AsBytes;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    /// 运行协程直至完成（异常重抛）
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

    /// 构造 socks5 目标地址
    auto MakeAddress(Socks5::AddressType Type, std::string Host, std::uint16_t Port)
        -> Socks5::Address
    {
        Socks5::Address Address{};
        Address.Type = Type;
        Address.Host = std::move(Host);
        Address.Port = Port;
        return Address;
    }

    TEST(Socks5ConnSession, NoAuthHandshakeEcho)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        const std::string Payload = "socks5 echo payload";

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：Accept 握手 → 预读缓冲读取（握手尾与载荷同批到达）→ 回显
                     auto ServerCoroutine = [&]() -> Net::awaitable<void>
                     {
                         auto [ErrorValue, Request, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(ServerStream)),
                                                     Socks5::ServerConfig{});
                         if (ErrorValue != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         EXPECT_EQ(Request.Cmd, Socks5::Command::Connect);
                         EXPECT_EQ(Request.Target.Host, "example.com");
                         EXPECT_EQ(Request.Target.Port, 443u);
                         EXPECT_EQ(Conn->Parsed().Target.Host, "example.com");
                         // 预读缓冲路径：握手超读的载荷直接由缓冲返回
                         std::array<std::byte, 1024> Buffer{};
                         std::error_code ErrorCode;
                         const auto BytesRead = co_await Conn->async_read_some(Buffer, ErrorCode);
                         EXPECT_FALSE(ErrorCode);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), BytesRead), Payload);
                         co_await Conn->async_write_some(std::span<const std::byte>(Buffer.data(), BytesRead), ErrorCode);
                         EXPECT_FALSE(ErrorCode);
                         Conn->Close();
                     };
                     Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                     // 原始客户端：Greeting + 请求 + 载荷一次写入（触发服务端预读）
                     std::vector<std::uint8_t> Wire{0x05, 0x01, 0x00}; // Greeting
                     const std::string Host = "example.com";
                     Wire.insert(Wire.end(), {0x05, 0x01, 0x00, 0x03,
                                              static_cast<std::uint8_t>(Host.size())});
                     Wire.insert(Wire.end(), Host.begin(), Host.end());
                     Wire.push_back(0x01);
                     Wire.push_back(0xBB); // port 443
                     Wire.insert(Wire.end(), Payload.begin(), Payload.end());
                     std::error_code ErrorCode;
                     co_await ClientStream.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
                     // 读取方法选择 + 成功响应（4 + ipv4 Bind 4 + port 2）
                     std::array<std::uint8_t, 12> Response{};
                     std::size_t Received = 0;
                     while (Received < Response.size())
                     {
                         const auto BytesRead = co_await ClientStream.async_read_some(
                             AsBytes(std::span<std::uint8_t>(Response).subspan(Received)), ErrorCode);
                         if (ErrorCode || BytesRead == 0)
                         {
                             break;
                         }
                         Received += BytesRead;
                     }
                     EXPECT_EQ(Received, 12u);
                     EXPECT_EQ(Response[0], Socks5::Version);
                     EXPECT_EQ(Response[1], 0x00); // no_auth 选中
                     EXPECT_EQ(Response[3], 0x00); // success
                     // 读取回显
                     std::array<std::byte, 1024> echo{};
                     Received = 0;
                     while (Received < Payload.size())
                     {
                         const auto BytesRead = co_await ClientStream.async_read_some(
                             std::span<std::byte>(echo.data() + Received, echo.size() - Received), ErrorCode);
                         if (ErrorCode || BytesRead == 0)
                         {
                             break;
                         }
                         Received += BytesRead;
                     }
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(echo.data()), Received), Payload);
                     ClientStream.Close();
                 });
    }

    TEST(Socks5ConnSession, FactoryConnectAcceptEcho)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     auto ServerCoroutine = [&]() -> Net::awaitable<void>
                     {
                         auto [ErrorValue, Request, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(ServerStream)),
                                                     Socks5::ServerConfig{});
                         if (ErrorValue != Error::None || !Conn)
                         {
                             co_return;
                         }
                         EXPECT_EQ(Request.Target.Host, "1.2.3.4");
                         std::array<std::byte, 256> Buffer{};
                         std::error_code ErrorCode;
                         const auto BytesRead = co_await Conn->async_read_some(Buffer, ErrorCode);
                         if (ErrorCode || BytesRead == 0)
                         {
                             co_return;
                         }
                         co_await Conn->async_write_some(std::span<const std::byte>(Buffer.data(), BytesRead), ErrorCode);
                         Conn->Close();
                     };
                     Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                     auto [HandshakeError, Client] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(ClientStream)), Socks5::ClientConfig{},
                         MakeAddress(Socks5::AddressType::Ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(HandshakeError, Error::None);
                     if (!Client)
                     {
                         co_return;
                     }
                     // BindEndpoint 已由成功响应填充（0.0.0.0:0）
                     EXPECT_EQ(Client->BindEndpoint().Host, "0.0.0.0");
                     const std::string Payload = "factory echo";
                     std::error_code ErrorCode;
                     co_await Client->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                                    Payload.size()),
                         ErrorCode);
                     std::array<std::byte, 256> Buffer{};
                     const auto BytesRead = co_await Client->async_read_some(Buffer, ErrorCode);
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), BytesRead), Payload);
                     Client->Close();
                 });
    }

    TEST(Socks5ConnSession, UserPassAuthHandshake)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     auto ServerCoroutine = [&]() -> Net::awaitable<void>
                     {
                         Socks5::ServerConfig Config;
                         Config.EnableAuth = true;
                         Config.username = "alice";
                         Config.password = "Secret";
                         auto [ErrorValue, Request, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(ServerStream)), Config);
                         if (ErrorValue != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         EXPECT_EQ(Request.Cmd, Socks5::Command::Connect);
                         EXPECT_EQ(Request.Target.Type, Socks5::AddressType::Ipv4);
                         EXPECT_EQ(Request.Target.Host, "1.2.3.4");
                         EXPECT_EQ(Request.Target.Port, 80u);
                         Conn->Close();
                     };
                     Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                     Socks5::ClientConfig Config;
                     Config.EnableAuth = true;
                     Config.username = "alice";
                     Config.password = "Secret";
                     auto [HandshakeError, Client] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(ClientStream)), Config,
                         MakeAddress(Socks5::AddressType::Ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(HandshakeError, Error::None);
                     if (Client)
                     {
                         Client->Close();
                     }
                 });
    }

    TEST(Socks5ConnSession, UserPassWrongPassword)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     auto ServerCoroutine = [&]() -> Net::awaitable<void>
                     {
                         Socks5::ServerConfig Config;
                         Config.EnableAuth = true;
                         Config.username = "alice";
                         Config.password = "Secret";
                         auto [ErrorValue, Request, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(ServerStream)), Config);
                         EXPECT_EQ(ErrorValue, Error::BadAuth);
                         EXPECT_FALSE(Conn);
                         (void)Request;
                     };
                     Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                     Socks5::ClientConfig Config;
                     Config.EnableAuth = true;
                     Config.username = "alice";
                     Config.password = "wrong";
                     auto [HandshakeError, Client] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(ClientStream)), Config,
                         MakeAddress(Socks5::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(HandshakeError, Error::BadAuth);
                     EXPECT_FALSE(Client);
                 });
    }

    TEST(Socks5ConnSession, UserPassMalformedVersion)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：userpass 子协商版本号非法 → bad_auth
                     auto ServerCoroutine = [&]() -> Net::awaitable<void>
                     {
                         Socks5::ServerConfig Config;
                         Config.EnableAuth = true;
                         Config.username = "alice";
                         Config.password = "Secret";
                         auto [ErrorValue, Request, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(ServerStream)), Config);
                         EXPECT_EQ(ErrorValue, Error::BadAuth);
                         EXPECT_FALSE(Conn);
                         (void)Request;
                     };
                     Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                     // 原始客户端：Greeting 含 user_pass 方法
                     std::error_code ErrorCode;
                     const std::array<std::uint8_t, 4> Greeting{0x05, 0x01, 0x02};
                     co_await ClientStream.async_write_some(AsBytes(std::span<const std::uint8_t>(Greeting)), ErrorCode);
                     // 读取方法选择
                     std::array<std::uint8_t, 2> Selection{};
                     const auto BytesRead = co_await ClientStream.async_read_some(AsBytes(std::span<std::uint8_t>(Selection)), ErrorCode);
                     EXPECT_EQ(BytesRead, 2u);
                     EXPECT_EQ(Selection[1], 0x02);
                     // 发送非法版本的 userpass 子协商
                     const std::array<std::uint8_t, 3> BadRequest{0x02, 0x01, 0x61}; // 版本 0x02
                     co_await ClientStream.async_write_some(AsBytes(std::span<const std::uint8_t>(BadRequest)), ErrorCode);
                     ClientStream.Close();
                 });
    }

    TEST(Socks5ConnSession, VersionMismatchRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     auto ServerCoroutine = [&]() -> Net::awaitable<void>
                     {
                         auto [ErrorValue, Request, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(ServerStream)),
                                                     Socks5::ServerConfig{});
                         EXPECT_EQ(ErrorValue, Error::VersionMismatch);
                         EXPECT_FALSE(Conn);
                         (void)Request;
                     };
                     Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                     const std::array<std::uint8_t, 3> BadGreeting{0x04, 0x01, 0x00}; // 版本错误
                     std::error_code ErrorCode;
                     co_await ClientStream.async_write_some(AsBytes(std::span<const std::uint8_t>(BadGreeting)), ErrorCode);
                     ClientStream.Close();
                 });
    }

    TEST(Socks5ConnSession, NoAcceptableMethod)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：要求 user_pass，客户端仅提供 no_auth
                     auto ServerCoroutine = [&]() -> Net::awaitable<void>
                     {
                         Socks5::ServerConfig Config;
                         Config.EnableAuth = true;
                         Config.username = "alice";
                         Config.password = "Secret";
                         auto [ErrorValue, Request, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(ServerStream)), Config);
                         EXPECT_EQ(ErrorValue, Error::NotSupported);
                         EXPECT_FALSE(Conn);
                         (void)Request;
                     };
                     Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                     auto [HandshakeError, Client] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(ClientStream)), Socks5::ClientConfig{},
                         MakeAddress(Socks5::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(HandshakeError, Error::NotSupported);
                     EXPECT_FALSE(Client);
                 });
    }

    TEST(Socks5ConnSession, ClientRejectsUnexpectedMethod)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     // 原始服务端：Greeting 后选择 gssapi（客户端未提供且未开认证）
                     auto ServerCoroutine = [&]() -> Net::awaitable<void>
                     {
                         std::array<std::uint8_t, 4> Greeting{0x05, 0x01, 0x00};
                         std::error_code ErrorCode;
                         co_await ServerStream.async_write_some(AsBytes(std::span<const std::uint8_t>(Greeting)), ErrorCode);
                         std::array<std::uint8_t, 2> Selection{0x05, 0x01}; // gssapi
                         co_await ServerStream.async_write_some(AsBytes(std::span<const std::uint8_t>(Selection)), ErrorCode);
                     };
                     Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                     auto [HandshakeError, Client] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(ClientStream)), Socks5::ClientConfig{},
                         MakeAddress(Socks5::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(HandshakeError, Error::NotSupported);
                     EXPECT_FALSE(Client);
                 });
    }

    TEST(Socks5ConnSession, TcpDisabledRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     auto ServerCoroutine = [&]() -> Net::awaitable<void>
                     {
                         Socks5::ServerConfig Config;
                         Config.EnableTcp = false;
                         auto [ErrorValue, Request, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(ServerStream)), Config);
                         EXPECT_EQ(ErrorValue, Error::NotSupported);
                         EXPECT_FALSE(Conn);
                         (void)Request;
                     };
                     Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                     // 客户端：收到 command_not_supported 响应 → bad_auth
                     auto [HandshakeError, Client] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(ClientStream)), Socks5::ClientConfig{},
                         MakeAddress(Socks5::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(HandshakeError, Error::BadAuth);
                     EXPECT_FALSE(Client);
                 });
    }

    TEST(Socks5ConnSession, UdpDisabledRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     auto ServerCoroutine = [&]() -> Net::awaitable<void>
                     {
                         Socks5::ServerConfig Config;
                         Config.EnableUdp = false;
                         auto [ErrorValue, Request, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(ServerStream)), Config);
                         EXPECT_EQ(ErrorValue, Error::NotSupported);
                         EXPECT_FALSE(Conn);
                         (void)Request;
                     };
                     Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                     auto [HandshakeError, Client] = co_await Socks5::Connect({
                         std::make_shared<MemoryStream>(std::move(ClientStream)), Socks5::ClientConfig{},
                         MakeAddress(Socks5::AddressType::Domain, "example.com", 443),
                         Socks5::Command::UdpAssociate});
                     EXPECT_EQ(HandshakeError, Error::BadAuth);
                     EXPECT_FALSE(Client);
                 });
    }

    TEST(Socks5ConnSession, BadCommandRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：非法命令 → not_supported + general_failure 响应
                     auto ServerCoroutine = [&]() -> Net::awaitable<void>
                     {
                         auto [ErrorValue, Request, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(ServerStream)),
                                                     Socks5::ServerConfig{});
                         EXPECT_EQ(ErrorValue, Error::NotSupported);
                         EXPECT_FALSE(Conn);
                         (void)Request;
                     };
                     Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                     // 原始客户端：Greeting + 请求（cmd=0x09 非法）
                     std::error_code ErrorCode;
                     const std::array<std::uint8_t, 3> Greeting{0x05, 0x01, 0x00};
                     co_await ClientStream.async_write_some(AsBytes(std::span<const std::uint8_t>(Greeting)), ErrorCode);
                     const std::array<std::uint8_t, 10> Request{0x05, 0x09, 0x00, 0x03, 0x0B, 'e', 'x',
                                                            'a',  'm',  'p'};
                     co_await ClientStream.async_write_some(AsBytes(std::span<const std::uint8_t>(Request)), ErrorCode);
                     // 读取方法选择（避免服务端响应写失败）
                     std::array<std::uint8_t, 2> Selection{};
                     co_await ClientStream.async_read_some(AsBytes(std::span<std::uint8_t>(Selection)), ErrorCode);
                     ClientStream.Close();
                 });
    }

    TEST(Socks5ConnSession, BadAtypRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：非法 ATYP → bad_message
                     auto ServerCoroutine = [&]() -> Net::awaitable<void>
                     {
                         auto [ErrorValue, Request, Conn] =
                             co_await Socks5::Accept(std::make_shared<MemoryStream>(std::move(ServerStream)),
                                                     Socks5::ServerConfig{});
                         EXPECT_EQ(ErrorValue, Error::BadMessage);
                         EXPECT_FALSE(Conn);
                         (void)Request;
                     };
                     Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                     std::error_code ErrorCode;
                     const std::array<std::uint8_t, 3> Greeting{0x05, 0x01, 0x00};
                     co_await ClientStream.async_write_some(AsBytes(std::span<const std::uint8_t>(Greeting)), ErrorCode);
                     const std::array<std::uint8_t, 6> Request{0x05, 0x01, 0x00, 0x99, 0x00, 0x50}; // ATYP 非法
                     co_await ClientStream.async_write_some(AsBytes(std::span<const std::uint8_t>(Request)), ErrorCode);
                     // 读取方法选择（避免服务端响应写失败）
                     std::array<std::uint8_t, 2> Selection{};
                     co_await ClientStream.async_read_some(AsBytes(std::span<std::uint8_t>(Selection)), ErrorCode);
                     ClientStream.Close();
                 });
    }

    TEST(Socks5ConnSession, ClientIoErrorOnClosedPeer)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     ServerStream.Close(); // 对端已全关 → Greeting 发送失败 → io_error
                     auto [HandshakeError, Client] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(ClientStream)), Socks5::ClientConfig{},
                         MakeAddress(Socks5::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(HandshakeError, Error::IoError);
                     EXPECT_FALSE(Client);
                 });
    }

    TEST(Socks5ConnSession, ClientGreetingEof)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     // 原始服务端：读完 Greeting 后直接关闭 → 客户端读方法选择 EOF → io_error
                     auto ServerCoroutine = [&]() -> Net::awaitable<void>
                     {
                         std::array<std::uint8_t, 4> Greeting{};
                         std::error_code ErrorCode;
                         const auto BytesRead = co_await ServerStream.async_read_some(AsBytes(std::span<std::uint8_t>(Greeting)),
                                                                   ErrorCode);
                         EXPECT_GT(BytesRead, 0u);
                         ServerStream.Close();
                     };
                     Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                     auto [HandshakeError, Client] = co_await Socks5::Connect(
                         std::make_shared<MemoryStream>(std::move(ClientStream)), Socks5::ClientConfig{},
                         MakeAddress(Socks5::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(HandshakeError, Error::IoError);
                     EXPECT_FALSE(Client);
                 });
    }

    TEST(Socks5ConnSession, DecoratorChain)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Connection = std::make_shared<Socks5::Conn<>>(std::make_shared<MemoryStream>(std::move(ClientStream)));
                     EXPECT_TRUE(Connection->Executor());
                     EXPECT_NE(Connection->NextLayer(), nullptr);
                     EXPECT_NE(Connection->lowest_layer<MemoryStream>(), nullptr);
                     // 透传读写（未握手状态原样透传）
                     const std::string Payload = "passthrough";
                     std::error_code ErrorCode;
                     co_await Connection->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                                    Payload.size()),
                         ErrorCode);
                     EXPECT_FALSE(ErrorCode);
                     std::array<std::byte, 64> Buffer{};
                     const auto BytesRead = co_await ServerStream.async_read_some(Buffer, ErrorCode);
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), BytesRead), Payload);
                     // ReadExact 公开接口（供包连接复用）
                     std::array<std::uint8_t, 4> Destination{};
                     co_await ServerStream.async_write_some(std::span<const std::byte>(Buffer.data(), 4), ErrorCode);
                     const auto Ok = co_await Connection->ReadExact(std::span<std::uint8_t>(Destination));
                     EXPECT_FALSE(Ok);
                     Connection->Close();
                     Connection->Cancel();
                     const Socks5::Conn<> *ConnectionPointer = Connection.get();
                     EXPECT_NE(ConnectionPointer->NextLayer(), nullptr);
                     auto Released = Connection->Release();
                     EXPECT_TRUE(Released);
                     EXPECT_EQ(Connection->NextLayer(), nullptr);
                 });
    }

} // namespace

    // ── 深度接口：IsValid / Underlying ──

    TEST(Socks5ConnDeep, ValidAfterHandshake)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorValue, Request, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerStream)), Socks5::ServerConfig{});
                if (ErrorValue == Error::None && Conn)
                {
                    EXPECT_TRUE(Conn->IsValid());
                    EXPECT_TRUE(Conn->Underlying() != nullptr);
                    Conn->Close();
                }
            };
            Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

            std::vector<std::uint8_t> Wire{0x05, 0x01, 0x00};
            std::string Host = "example.com";
            Wire.insert(Wire.end(), {0x05, 0x01, 0x00, 0x03, static_cast<std::uint8_t>(Host.size())});
            Wire.insert(Wire.end(), Host.begin(), Host.end());
            Wire.push_back(0x01);
            Wire.push_back(0xBB);
            std::error_code ErrorCode;
            co_await ClientStream.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            std::array<std::uint8_t, 12> Response{};
            co_await ClientStream.async_read_some(AsBytes(std::span<std::uint8_t>(Response)), ErrorCode);
        });
    }
