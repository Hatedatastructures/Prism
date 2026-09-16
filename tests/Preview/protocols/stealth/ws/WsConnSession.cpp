/**
 * @file WsConnSession.cpp
 * @brief WebSocket Conn 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept Upgrade 握手（Sec-WebSocket-Key/Accept）→ 双向回显
 * 2. 错误分支：bad_magic（非 Upgrade 请求 / 非 101 响应）/ bad_auth（Accept 不匹配）
 * 3. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release / Accept()
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Ws/Ws.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Ws = Preview::Ws;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto RunCoro(
        Net::io_context &IoContext,
        A Coroutine) -> void
    {
        std::exception_ptr Exception;
        auto Completion = [&](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(IoContext, std::move(Coroutine), std::move(Completion));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /// 标准测试密钥（RFC 6455 示例）
    inline constexpr const char *TestKey = "dGhlIHNhbXBsZSBub25jZQ==";

    TEST(WsConnSession, HandshakeClientServerEcho)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const std::string payload = "ws echo payload";

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：Accept 解析 Upgrade 请求 → 回显
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         auto [err, key, Conn] =
                             co_await Ws::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                 Ws::ServerConfig{});
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         EXPECT_EQ(key, TestKey);
                         std::array<std::byte, 1024> buf{};
                         std::error_code ec;
                         const auto n = co_await Conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                         co_await Conn->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
                         EXPECT_FALSE(ec);
                         Conn->Close();
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     Ws::ClientConfig cfg;
                     cfg.host = "example.com";
                     cfg.key = TestKey;
                     auto [herr, cli] = co_await Ws::Connect(std::make_shared<MemoryStream>(std::move(a)), cfg);
                     EXPECT_EQ(herr, Error::None);
                     if (!cli)
                     {
                         co_return;
                     }
                     // Accept() 返回服务端计算的 Sec-WebSocket-Accept
                     EXPECT_EQ(cli->Accept(), Ws::ComputeAccept(TestKey));
                     std::error_code ec;
                     co_await cli->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 1024> buf{};
                     const auto n = co_await cli->async_read_some(buf, ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                     cli->Close();
                 });
    }

    TEST(WsConnSession, ServerDecodesMaskedBinaryFrame)
    {
        Net::io_context ioc;
        auto [client, server] = MakeMemoryPair(ioc.get_executor());
        const std::string payload = "masked websocket payload";
        auto server_ok = std::make_shared<bool>(false);
        auto server_done = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
            ioc.get_executor(), 1);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         auto [err, key, Conn] = co_await Ws::Accept(
                             std::make_shared<MemoryStream>(std::move(server)), Ws::ServerConfig{});
                         EXPECT_EQ(err, Error::None);
                         EXPECT_EQ(key, TestKey);
                         if (!Conn)
                         {
                             (void)server_done->try_send(boost::system::error_code{});
                             co_return;
                         }
                         std::array<std::byte, 128> Buffer{};
                         std::error_code ReadError;
                         const auto Count = co_await Conn->async_read_some(Buffer, ReadError);
                         *server_ok = !ReadError && Count == payload.size() &&
                                      std::memcmp(Buffer.data(), payload.data(), payload.size()) == 0;
                         Conn->Close();
                         (void)server_done->try_send(boost::system::error_code{});
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     const std::string Request =
                         "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n"
                         "Connection: Upgrade\r\nSec-WebSocket-Key: " + std::string(TestKey) +
                         "\r\nSec-WebSocket-Version: 13\r\n\r\n";
                    std::error_code ErrorCode;
                    co_await client.async_write_some(
                        std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.data()),
                                                   Request.size()),
                        ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    if (ErrorCode)
                    {
                        client.Close();
                         co_await server_done->async_receive(Net::use_awaitable);
                        co_return;
                    }
                    std::array<std::byte, 256> Response{};
                    const auto ResponseSize = co_await client.async_read_some(Response, ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    EXPECT_GT(ResponseSize, 0U);
                    if (ErrorCode || ResponseSize == 0)
                    {
                        client.Close();
                         co_await server_done->async_receive(Net::use_awaitable);
                        co_return;
                    }

                    std::vector<std::byte> Frame;
                    Frame.reserve(2 + 4 + payload.size());
                    Frame.push_back(std::byte{0x82});
                    Frame.push_back(static_cast<std::byte>(0x80U | payload.size()));
                    const std::array<std::uint8_t, 4> Mask{0x01, 0x02, 0x03, 0x04};
                    for (const auto Byte : Mask)
                    {
                        Frame.push_back(static_cast<std::byte>(Byte));
                    }
                    for (std::size_t Index = 0; Index < payload.size(); ++Index)
                    {
                        Frame.push_back(static_cast<std::byte>(
                            static_cast<std::uint8_t>(payload[Index]) ^ Mask[Index % Mask.size()]));
                    }
                    co_await client.async_write_some(Frame, ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    client.Close();
                     co_await server_done->async_receive(Net::use_awaitable);
                 });

        EXPECT_TRUE(*server_ok);
    }

    TEST(WsConnSession, ClientWritesMaskedBinaryFrame)
    {
        Net::io_context ioc;
        auto [client, server] = MakeMemoryPair(ioc.get_executor());
        const std::string payload = "client mask wire payload";
        auto wire_ok = std::make_shared<bool>(false);
        auto server_done = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
            ioc.get_executor(), 1);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw_server = [&]() -> Net::awaitable<void>
                     {
                         auto Raw = std::make_shared<MemoryStream>(std::move(server));
                         std::array<std::byte, 1024> Request{};
                         std::error_code ErrorCode;
                         const auto RequestSize = co_await Raw->async_read_some(Request, ErrorCode);
                         if (ErrorCode || RequestSize == 0)
                         {
                             (void)server_done->try_send(boost::system::error_code{});
                             co_return;
                         }
                         const auto Accept = Ws::ComputeAccept(TestKey);
                         const std::string Response =
                             "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                             "Connection: Upgrade\r\nSec-WebSocket-Accept: " +
                             Accept + "\r\n\r\n";
                         co_await Raw->async_write_some(AsBytes(AsU8Span(Response)), ErrorCode);
                         if (ErrorCode)
                         {
                             (void)server_done->try_send(boost::system::error_code{});
                             co_return;
                         }

                         std::array<std::byte, 1024> Wire{};
                         const auto WireSize = co_await Raw->async_read_some(Wire, ErrorCode);
                         Ws::FrameHeader Header;
                         if (!ErrorCode && Ws::ParseFrameHeader(
                                                std::span<const std::byte>(Wire.data(), WireSize), Header) &&
                             Header.Masked && Header.Fin && Header.Opcode ==
                                                   static_cast<std::uint8_t>(Ws::Opcode::Binary) &&
                             Header.HeaderLen + Header.PayloadLen <= WireSize &&
                             Header.PayloadLen == payload.size())
                         {
                             std::vector<std::byte> Decoded(
                                 Wire.begin() + static_cast<std::ptrdiff_t>(Header.HeaderLen),
                                 Wire.begin() + static_cast<std::ptrdiff_t>(Header.HeaderLen + Header.PayloadLen));
                             Ws::ApplyMask(Decoded, Header.MaskKey);
                             *wire_ok = std::memcmp(Decoded.data(), payload.data(), payload.size()) == 0;
                         }
                         (void)server_done->try_send(boost::system::error_code{});
                     };
                     Net::co_spawn(ioc.get_executor(), raw_server(), Net::detached);

                     Ws::ClientConfig Config;
                     Config.host = "example.com";
                     Config.key = TestKey;
                     auto [HandshakeError, Conn] =
                         co_await Ws::Connect(std::make_shared<MemoryStream>(std::move(client)), Config);
                     EXPECT_EQ(HandshakeError, Error::None);
                     if (!Conn)
                     {
                         co_await server_done->async_receive(Net::use_awaitable);
                         co_return;
                     }
                     std::error_code ErrorCode;
                     co_await Conn->async_write_some(AsBytes(AsU8Span(payload)), ErrorCode);
                     EXPECT_FALSE(ErrorCode);
                     Conn->Close();
                         co_await server_done->async_receive(Net::use_awaitable);
                 });

        EXPECT_TRUE(*wire_ok);
    }

    TEST(WsConnSession, ServerRejectsUnmaskedClientFrame)
    {
        Net::io_context ioc;
        auto [client, server] = MakeMemoryPair(ioc.get_executor());
        auto server_error = std::make_shared<Error>(Error::None);
        auto server_done = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
            ioc.get_executor(), 1);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         auto [HandshakeError, Key, Conn] = co_await Ws::Accept(
                             std::make_shared<MemoryStream>(std::move(server)), Ws::ServerConfig{});
                         (void)Key;
                         if (HandshakeError != Error::None || !Conn)
                         {
                             *server_error = HandshakeError;
                             (void)server_done->try_send(boost::system::error_code{});
                             co_return;
                         }
                         std::array<std::byte, 64> Buffer{};
                         std::error_code ErrorCode;
                         (void)co_await Conn->async_read_some(Buffer, ErrorCode);
                         if (ErrorCode)
                         {
                             *server_error = static_cast<Error>(ErrorCode.value());
                         }
                         Conn->Close();
                         (void)server_done->try_send(boost::system::error_code{});
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     const std::string Request =
                         "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n"
                         "Connection: Upgrade\r\nSec-WebSocket-Key: " +
                         std::string(TestKey) + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
                     std::error_code ErrorCode;
                     co_await client.async_write_some(AsBytes(AsU8Span(Request)), ErrorCode);
                     EXPECT_FALSE(ErrorCode);
                     std::array<std::byte, 256> Response{};
                     (void)co_await client.async_read_some(Response, ErrorCode);
                     EXPECT_FALSE(ErrorCode);
                     const std::array<std::byte, 3> UnmaskedFrame{
                         std::byte{0x82}, std::byte{0x01}, std::byte{'x'}};
                     co_await client.async_write_some(UnmaskedFrame, ErrorCode);
                     EXPECT_FALSE(ErrorCode);
                     client.Close();
                     co_await server_done->async_receive(Net::use_awaitable);
                 });

        EXPECT_EQ(*server_error, Error::BadMessage);
    }

    TEST(WsConnSession, ServerRepliesToMaskedPing)
    {
        Net::io_context ioc;
        auto [client, server] = MakeMemoryPair(ioc.get_executor());
        const std::string PingPayload = "ping";
        auto server_done = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
            ioc.get_executor(), 1);
        auto pong_ok = std::make_shared<bool>(false);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         auto [HandshakeError, Key, Conn] = co_await Ws::Accept(
                             std::make_shared<MemoryStream>(std::move(server)), Ws::ServerConfig{});
                         (void)Key;
                         if (HandshakeError != Error::None || !Conn)
                         {
                             (void)server_done->try_send(boost::system::error_code{});
                             co_return;
                         }
                         std::array<std::byte, 64> Buffer{};
                         std::error_code ErrorCode;
                         (void)co_await Conn->async_read_some(Buffer, ErrorCode);
                         Conn->Close();
                         (void)server_done->try_send(boost::system::error_code{});
                     };
                      Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     const std::string Request =
                         "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n"
                         "Connection: Upgrade\r\nSec-WebSocket-Key: " +
                         std::string(TestKey) + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
                     std::error_code ErrorCode;
                     co_await client.async_write_some(AsBytes(AsU8Span(Request)), ErrorCode);
                     EXPECT_FALSE(ErrorCode);
                     std::array<std::byte, 256> Response{};
                     (void)co_await client.async_read_some(Response, ErrorCode);
                     EXPECT_FALSE(ErrorCode);

                     const std::array<std::uint8_t, 4> Mask{0xA1, 0xB2, 0xC3, 0xD4};
                     std::vector<std::byte> PingFrame{std::byte{0x89},
                                                       static_cast<std::byte>(0x80U | PingPayload.size())};
                     PingFrame.insert(PingFrame.end(),
                                      reinterpret_cast<const std::byte *>(Mask.data()),
                                      reinterpret_cast<const std::byte *>(Mask.data() + Mask.size()));
                     for (std::size_t Index = 0; Index < PingPayload.size(); ++Index)
                     {
                         PingFrame.push_back(static_cast<std::byte>(
                             static_cast<std::uint8_t>(PingPayload[Index]) ^ Mask[Index % Mask.size()]));
                     }
                     co_await client.async_write_some(PingFrame, ErrorCode);
                     EXPECT_FALSE(ErrorCode);

                     std::array<std::byte, 64> PongFrame{};
                     const auto PongSize = co_await client.async_read_some(PongFrame, ErrorCode);
                     Ws::FrameHeader Header;
                     if (!ErrorCode && Ws::ParseFrameHeader(
                                            std::span<const std::byte>(PongFrame.data(), PongSize), Header) &&
                         !Header.Masked && Header.Fin && Header.Opcode ==
                                                       static_cast<std::uint8_t>(Ws::Opcode::Pong) &&
                         Header.HeaderLen + Header.PayloadLen <= PongSize &&
                         Header.PayloadLen == PingPayload.size())
                     {
                         *pong_ok = std::memcmp(PongFrame.data() + Header.HeaderLen,
                                                PingPayload.data(), PingPayload.size()) == 0;
                     }

                     const std::array<std::byte, 6> CloseFrame{
                         std::byte{0x88}, std::byte{0x80}, std::byte{0x11}, std::byte{0x22},
                         std::byte{0x33}, std::byte{0x44}};
                     co_await client.async_write_some(CloseFrame, ErrorCode);
                     client.Close();
                         co_await server_done->async_receive(Net::use_awaitable);
                 });

        EXPECT_TRUE(*pong_ok);
    }

    TEST(WsConnSession, ServerAcceptsCaseInsensitiveHeaders)
    {
        Net::io_context ioc;
        auto [client, server] = MakeMemoryPair(ioc.get_executor());
        auto server_ok = std::make_shared<bool>(false);
        auto server_done = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
            ioc.get_executor(), 1);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         auto [ErrorCode, Key, Conn] = co_await Ws::Accept(
                             std::make_shared<MemoryStream>(std::move(server)), Ws::ServerConfig{});
                         *server_ok = ErrorCode == Error::None && Key == TestKey && Conn != nullptr;
                         if (Conn)
                         {
                             Conn->Close();
                         }
                         (void)server_done->try_send(boost::system::error_code{});
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     const std::string Request =
                         "GET / HTTP/1.1\r\nhost: example.com\r\nupgrade: WebSocket\r\n"
                         "connection: keep-alive, Upgrade\r\nsec-websocket-key: " +
                         std::string(TestKey) + "\r\nsec-websocket-version: 13\r\n\r\n";
                     std::error_code ErrorCode;
                     co_await client.async_write_some(AsBytes(AsU8Span(Request)), ErrorCode);
                     EXPECT_FALSE(ErrorCode);
                         co_await server_done->async_receive(Net::use_awaitable);
                     client.Close();
                 });

        EXPECT_TRUE(*server_ok);
    }

    TEST(WsConnSession, ClientAcceptsCaseInsensitiveResponseHeaders)
    {
        Net::io_context ioc;
        auto [client, server] = MakeMemoryPair(ioc.get_executor());
        auto server_done = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
            ioc.get_executor(), 1);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw_server = [&]() -> Net::awaitable<void>
                     {
                         auto Raw = std::make_shared<MemoryStream>(std::move(server));
                         std::array<std::byte, 512> Request{};
                         std::error_code ErrorCode;
                         (void)co_await Raw->async_read_some(Request, ErrorCode);
                         const auto Accept = Ws::ComputeAccept(TestKey);
                         const std::string Response =
                             "HTTP/1.1 101 Switching Protocols\r\nupgrade: WebSocket\r\n"
                             "connection: Upgrade\r\nsec-websocket-accept: " +
                             Accept + "\r\n\r\n";
                         co_await Raw->async_write_some(AsBytes(AsU8Span(Response)), ErrorCode);
                         (void)server_done->try_send(boost::system::error_code{});
                     };
                     Net::co_spawn(ioc.get_executor(), raw_server(), Net::detached);

                     Ws::ClientConfig Config;
                     Config.host = "example.com";
                     Config.key = TestKey;
                     auto [ErrorCode, Conn] =
                         co_await Ws::Connect(std::make_shared<MemoryStream>(std::move(client)), Config);
                     EXPECT_EQ(ErrorCode, Error::None);
                     EXPECT_NE(Conn, nullptr);
                     if (Conn)
                     {
                         Conn->Close();
                     }
                      co_await server_done->async_receive(Net::use_awaitable);
                 });
    }

    TEST(WsConnSession, ServerRejectsNonUpgrade)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：普通 HTTP 请求（无 Upgrade）→ bad_magic
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         auto [err, key, Conn] =
                             co_await Ws::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                 Ws::ServerConfig{});
                         EXPECT_EQ(err, Error::BadMagic);
                         EXPECT_FALSE(Conn);
                         (void)key;
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     const std::string plain = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
                     std::error_code ec;
                     co_await a.async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(plain.data()),
                                                    plain.size()),
                         ec);
                     a.Close();
                 });
    }

    TEST(WsConnSession, ServerRejectsMissingKey)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：有 Upgrade 但无 Sec-WebSocket-Key → bad_magic
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         auto [err, key, Conn] =
                             co_await Ws::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                 Ws::ServerConfig{});
                         EXPECT_EQ(err, Error::BadMagic);
                         EXPECT_FALSE(Conn);
                         (void)key;
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     const std::string req = "GET / HTTP/1.1\r\nHost: example.com\r\n"
                                             "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
                     std::error_code ec;
                     co_await a.async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(req.data()),
                                                    req.size()),
                         ec);
                     a.Close();
                 });
    }

    TEST(WsConnSession, ClientRejectsNon101)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 原始服务端：回复 200（非 101）→ 客户端 bad_magic
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         std::array<std::uint8_t, 512> req{};
                         std::error_code ec;
                         const auto n = co_await b.async_read_some(AsBytes(std::span<std::uint8_t>(req)), ec);
                         EXPECT_GT(n, 0u);
                         const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                         co_await b.async_write_some(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(resp.data()),
                                                        resp.size()),
                             ec);
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     Ws::ClientConfig cfg;
                     cfg.host = "example.com";
                     cfg.key = TestKey;
                     auto [herr, cli] = co_await Ws::Connect(std::make_shared<MemoryStream>(std::move(a)), cfg);
                     EXPECT_EQ(herr, Error::BadMagic);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(WsConnSession, ClientRejectsBadAccept)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 原始服务端：101 但 Sec-WebSocket-Accept 错误 → 客户端 bad_auth
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         std::array<std::uint8_t, 512> req{};
                         std::error_code ec;
                         const auto n = co_await b.async_read_some(AsBytes(std::span<std::uint8_t>(req)), ec);
                         EXPECT_GT(n, 0u);
                         const std::string resp = "HTTP/1.1 101 Switching Protocols\r\n"
                                                  "Upgrade: websocket\r\n"
                                                  "Connection: Upgrade\r\n"
                                                  "Sec-WebSocket-Accept: wrong-Accept-value\r\n\r\n";
                         co_await b.async_write_some(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(resp.data()),
                                                        resp.size()),
                             ec);
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     Ws::ClientConfig cfg;
                     cfg.host = "example.com";
                     cfg.key = TestKey;
                     auto [herr, cli] = co_await Ws::Connect(std::make_shared<MemoryStream>(std::move(a)), cfg);
                     EXPECT_EQ(herr, Error::BadAuth);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(WsConnSession, NotOpenRejected)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 未握手 Conn：读写返回 not_open
                     auto c = std::make_shared<Ws::Conn<>>(std::make_shared<MemoryStream>(std::move(a)));
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await c->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec.value(), static_cast<int>(Error::NotOpen));
                     ec.clear();
                     co_await c->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(ec.value(), static_cast<int>(Error::NotOpen));
                     c->Close();
                     c->Cancel();
                     EXPECT_TRUE(c->Executor());
                     EXPECT_NE(c->NextLayer(), nullptr);
                     EXPECT_NE(c->lowest_layer<MemoryStream>(), nullptr);
                     const Ws::Conn<> *const_c = c.get();
                     EXPECT_NE(const_c->NextLayer(), nullptr);
                     auto released = c->Release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(c->NextLayer(), nullptr);
                     EXPECT_TRUE(c->Accept().empty()); // 未握手 Accept 为空
                 });
    }

} // namespace
