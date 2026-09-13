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

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Socks5/Socks5.hpp>

namespace
{
    namespace Preview = ::Preview;
    namespace Net = boost::asio;
    namespace Socks5 = Preview::Socks5;
    using Preview::AsBytes;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    template <typename A>
    auto RunCoro(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine), [&](std::exception_ptr ErrorValue)
                      { Exception = ErrorValue; IoContext.stop(); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto MakeAddress(Socks5::AddressType Type, std::string Host, std::uint16_t Port) -> Socks5::Address
    {
        Socks5::Address Address{};
        Address.Type = Type;
        Address.Host = std::move(Host);
        Address.Port = Port;
        return Address;
    }

    auto SendBadReply(Preview::SharedTransmission Stream) -> Net::awaitable<void>
    {
        std::array<std::byte, 8> Buffer{};
        std::error_code ErrorCode;
        (void)co_await Stream->async_read_some(Buffer, ErrorCode);
        const std::array<std::byte, 2> Selection{std::byte{0x04}, std::byte{0x00}};
        (void)co_await Stream->async_write_some(Selection, ErrorCode);
    }

    auto SendBadReservedReply(Preview::SharedTransmission Stream) -> Net::awaitable<void>
    {
        std::array<std::byte, 3> Greeting{};
        std::array<std::byte, 2> Selection{std::byte{0x05}, std::byte{0x00}};
        std::array<std::byte, 10> Request{};
        std::array<std::byte, 10> Reply{
            std::byte{0x05}, std::byte{0x00}, std::byte{0x01}, std::byte{0x01},
            std::byte{127}, std::byte{0}, std::byte{0}, std::byte{1}, std::byte{0x01}, std::byte{0xBB}};
        std::error_code ErrorCode;
        if (co_await Stream->AsyncRead(Greeting, ErrorCode) != Greeting.size() ||
            co_await Stream->async_write_some(Selection, ErrorCode) != Selection.size() ||
            co_await Stream->AsyncRead(Request, ErrorCode) != Request.size())
        {
            co_return;
        }
        (void)co_await Stream->async_write_some(Reply, ErrorCode);
    }

    auto SendNoAuthDowngradeReply(Preview::SharedTransmission Stream) -> Net::awaitable<void>
    {
        std::array<std::byte, 3> Greeting{};
        const std::array<std::byte, 2> Selection{std::byte{0x05}, std::byte{0x00}};
        std::error_code ErrorCode;
        if (co_await Stream->AsyncRead(Greeting, ErrorCode) != Greeting.size() ||
            co_await Stream->async_write_some(Selection, ErrorCode) != Selection.size())
        {
            co_return;
        }
        Stream->Close();
    }

    TEST(Socks5ConnErrorMatrix, BadVersionGreeting)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, [&]() -> Net::awaitable<void>
        {
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                const auto [ErrorValue, Request, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Socks5::ServerConfig{});
                EXPECT_EQ(ErrorValue, Error::VersionMismatch);
            };
            auto ServerTask = Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::use_awaitable);

            const std::vector<std::uint8_t> Wire{0x04, 0x01, 0x00}; // 错误版本
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            co_await std::move(ServerTask);
        });
    }

    TEST(Socks5ConnErrorMatrix, GreetingTruncated)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, [&]() -> Net::awaitable<void>
        {
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                const auto [ErrorValue, Request, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Socks5::ServerConfig{});
                EXPECT_EQ(ErrorValue, Error::IoError); // 半包后 EOF → 底层 IO 错误
            };
            auto ServerTask = Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::use_awaitable);

            const std::vector<std::uint8_t> Wire{0x05, 0x02}; // 缺 nmethods 后续
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            ClientMemory.Close();
            co_await std::move(ServerTask);
        });
    }

    TEST(Socks5ConnErrorMatrix, AuthFailure)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, [&]() -> Net::awaitable<void>
        {
            Socks5::ServerConfig Config;
            Config.EnableAuth = true;
            Config.username = "alice";
            Config.password = "correct";

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                const auto [ErrorValue, Request, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                EXPECT_EQ(ErrorValue, Error::BadAuth);
            };
            auto ServerTask = Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::use_awaitable);

            // Greeting（user_pass 方法）→ userpass（错误密码）
            std::vector<std::uint8_t> Wire{0x05, 0x01, 0x02};
            Wire.insert(Wire.end(), {0x01, 0x05});
            Wire.insert(Wire.end(), {'a', 'l', 'i', 'c', 'e'});
            Wire.insert(Wire.end(), {0x07});
            Wire.insert(Wire.end(), {'w', 'r', 'o', 'n', 'g', 'p', 'w'});
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            co_await std::move(ServerTask);
        });
    }

    TEST(Socks5ConnErrorMatrix, BadCommand)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, [&]() -> Net::awaitable<void>
        {
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorValue, Request, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Socks5::ServerConfig{});
                // 非法命令 → not_supported（ParseRequest 命令白名单）
                EXPECT_EQ(ErrorValue, Error::NotSupported);
            };
            auto ServerTask = Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::use_awaitable);

            // 非法命令 0x99（服务端应拒绝——预期 Accept 失败或命令被拒）
            std::vector<std::uint8_t> Wire{0x05, 0x01, 0x00};
            Wire.insert(Wire.end(), {0x05, 0x99, 0x00, 0x01, 10, 0, 0, 1, 0x01, 0xBB});
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            co_await std::move(ServerTask);
        });
    }

    TEST(Socks5ConnErrorMatrix, BadAddressType)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, [&]() -> Net::awaitable<void>
        {
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                const auto [ErrorValue, Request, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Socks5::ServerConfig{});
                EXPECT_EQ(ErrorValue, Error::BadMessage); // ATYP=9 → ParseAddress 拒绝
            };
            auto ServerTask = Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::use_awaitable);

            std::vector<std::uint8_t> Wire{0x05, 0x01, 0x00};
            Wire.insert(Wire.end(), {0x05, 0x01, 0x00, 0x09, 0x00, 0x50}); // ATYP=9 非法
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            co_await std::move(ServerTask);
        });
    }

    TEST(Socks5ConnErrorMatrix, BadReservedRequestByte)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, [&]() -> Net::awaitable<void>
        {
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                const auto [ErrorValue, Request, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Socks5::ServerConfig{});
                EXPECT_EQ(ErrorValue, Error::BadMessage);
            };
            auto ServerTask = Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::use_awaitable);

            const std::vector<std::uint8_t> Wire{
                0x05, 0x01, 0x00, // Greeting: no-auth
                0x05, 0x01, 0x01, 0x01, 10, 0, 0, 1, 0x01, 0xBB}; // RSV=1
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            co_await std::move(ServerTask);
        });
    }

    TEST(Socks5ConnErrorMatrix, RequestTruncated)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, [&]() -> Net::awaitable<void>
        {
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                const auto [ErrorValue, Request, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Socks5::ServerConfig{});
                EXPECT_EQ(ErrorValue, Error::IoError); // 请求头半包后 EOF
            };
            auto ServerTask = Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::use_awaitable);

            // Greeting 正常 + 请求半包（域名长度声明 20 但只给 5）
            std::vector<std::uint8_t> Wire{0x05, 0x01, 0x00};
            Wire.insert(Wire.end(), {0x05, 0x01, 0x00, 0x03, 0x14});
            Wire.insert(Wire.end(), {'h', 'e', 'l', 'l', 'o'});
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            ClientMemory.Close();
            co_await std::move(ServerTask);
        });
    }

    TEST(Socks5ConnErrorMatrix, ClientBadReply)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        RunCoro(ioc, [&]() -> Net::awaitable<void>
        {
            auto Done = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
                ioc.get_executor(), 1);
            auto Failure = std::make_shared<std::exception_ptr>();
            Net::co_spawn(
                ioc.get_executor(),
                SendBadReply(std::make_shared<MemoryStream>(std::move(b))),
                [Done, Failure](std::exception_ptr Ep)
                {
                    *Failure = Ep;
                    Done->try_send(boost::system::error_code{});
                });

            Socks5::ClientConfig cfg;
            auto [err, Conn] = co_await Socks5::Connect(
                std::make_shared<MemoryStream>(std::move(a)), cfg,
                MakeAddress(Socks5::AddressType::Domain, "example.com", 443));
            EXPECT_EQ(err, Preview::Error::VersionMismatch);
            co_await Done->async_receive(Net::use_awaitable);
            EXPECT_FALSE(*Failure);
        });
    }

    TEST(Socks5ConnErrorMatrix, ClientRejectsNonZeroReservedReply)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        RunCoro(ioc, [&]() -> Net::awaitable<void>
        {
            auto Done = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
                ioc.get_executor(), 1);
            auto Failure = std::make_shared<std::exception_ptr>();
            Net::co_spawn(
                ioc.get_executor(),
                SendBadReservedReply(std::make_shared<MemoryStream>(std::move(b))),
                [Done, Failure](std::exception_ptr Ep)
                {
                    *Failure = Ep;
                    Done->try_send(boost::system::error_code{});
                });

            Socks5::ClientConfig cfg;
            const auto [err, Conn] = co_await Socks5::Connect(
                std::make_shared<MemoryStream>(std::move(a)), cfg,
                MakeAddress(Socks5::AddressType::Ipv4, "127.0.0.1", 443));
            EXPECT_EQ(err, Preview::Error::BadMessage);
            EXPECT_EQ(Conn, nullptr);
            co_await Done->async_receive(Net::use_awaitable);
            EXPECT_FALSE(*Failure);
        });
    }

    TEST(Socks5ConnErrorMatrix, ClientRejectsNoAuthDowngradeWhenAuthEnabled)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        RunCoro(ioc, [&]() -> Net::awaitable<void>
        {
            auto Done = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
                ioc.get_executor(), 1);
            auto Failure = std::make_shared<std::exception_ptr>();
            Net::co_spawn(
                ioc.get_executor(),
                SendNoAuthDowngradeReply(std::make_shared<MemoryStream>(std::move(b))),
                [Done, Failure](std::exception_ptr Ep)
                {
                    *Failure = Ep;
                    Done->try_send(boost::system::error_code{});
                });

            Socks5::ClientConfig cfg;
            cfg.EnableAuth = true;
            cfg.username = "alice";
            cfg.password = "secret";
            const auto [err, Conn] = co_await Socks5::Connect(
                std::make_shared<MemoryStream>(std::move(a)), cfg,
                MakeAddress(Socks5::AddressType::Domain, "example.com", 443));
            EXPECT_EQ(err, Preview::Error::NotSupported);
            EXPECT_EQ(Conn, nullptr);
            co_await Done->async_receive(Net::use_awaitable);
            EXPECT_FALSE(*Failure);
        });
    }

    TEST(Socks5ConnErrorMatrix, NoAcceptableMethod)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        RunCoro(ioc, [&]() -> Net::awaitable<void>
        {
            // 服务端启用认证，客户端只提 no_auth → 无可用方法
            Socks5::ServerConfig cfg;
            cfg.EnableAuth = true;

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                const auto [ErrorValue, Request, Connection] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(b)),
                    cfg);
                (void)Request;
                (void)Connection;
                EXPECT_EQ(ErrorValue, Error::NotSupported);
            };
            auto ServerTask = Net::co_spawn(
                ioc.get_executor(), ServerCoroutine(), Net::use_awaitable);

            const std::vector<std::uint8_t> wire{0x05, 0x01, 0x00}; // 只提 no_auth
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            co_await std::move(ServerTask);
        });
    }

} // namespace
