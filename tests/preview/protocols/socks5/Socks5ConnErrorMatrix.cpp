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
    using namespace Preview;
    namespace net = boost::asio;

    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e)
                      { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    auto make_addr(Socks5::AddressType Type, std::string host, std::uint16_t port) -> Socks5::Address
    {
        Socks5::Address addr{};
        addr.Type = Type;
        addr.Host = std::move(host);
        addr.Port = port;
        return addr;
    }

    /// 服务端 Accept（内存对）并返回错误码
    auto accept_server(net::io_context &ioc, SharedTransmission Stream, Socks5::ServerConfig cfg)
        -> net::awaitable<Preview::Error>
    {
        auto [err, req, Conn] = co_await Socks5::Accept(std::move(Stream), cfg);
        co_return err;
    }

    auto SendBadReply(SharedTransmission Stream) -> net::awaitable<void>
    {
        std::array<std::byte, 8> Buffer{};
        std::error_code ec;
        (void)co_await Stream->async_read_some(Buffer, ec);
        const std::array<std::byte, 2> Selection{std::byte{0x04}, std::byte{0x00}};
        (void)co_await Stream->async_write_some(Selection, ec);
    }

    TEST(Socks5ConnErrorMatrix, BadVersionGreeting)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                const auto err = co_await accept_server(ioc, std::make_shared<MemoryStream>(std::move(b)),
                                                        Socks5::ServerConfig{});
                EXPECT_EQ(err, Preview::Error::VersionMismatch);
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            const std::vector<std::uint8_t> wire{0x04, 0x01, 0x00}; // 错误版本
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            co_await std::move(server_task);
        });
    }

    TEST(Socks5ConnErrorMatrix, GreetingTruncated)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                const auto err = co_await accept_server(ioc, std::make_shared<MemoryStream>(std::move(b)),
                                                        Socks5::ServerConfig{});
                EXPECT_EQ(err, Preview::Error::IoError); // 半包后 EOF → 底层 IO 错误
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            const std::vector<std::uint8_t> wire{0x05, 0x02}; // 缺 nmethods 后续
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            a.Close();
            co_await std::move(server_task);
        });
    }

    TEST(Socks5ConnErrorMatrix, AuthFailure)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Socks5::ServerConfig cfg;
            cfg.EnableAuth = true;
            cfg.username = "alice";
            cfg.password = "correct";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                const auto err = co_await accept_server(ioc, std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Preview::Error::BadAuth);
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            // Greeting（user_pass 方法）→ userpass（错误密码）
            std::vector<std::uint8_t> wire{0x05, 0x01, 0x02};
            wire.insert(wire.end(), {0x01, 0x05});
            wire.insert(wire.end(), {'a', 'l', 'i', 'c', 'e'});
            wire.insert(wire.end(), {0x07});
            wire.insert(wire.end(), {'w', 'r', 'o', 'n', 'g', 'p', 'w'});
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            co_await std::move(server_task);
        });
    }

    TEST(Socks5ConnErrorMatrix, BadCommand)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), Socks5::ServerConfig{});
                // 非法命令 → not_supported（ParseRequest 命令白名单）
                EXPECT_EQ(err, Preview::Error::NotSupported);
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            // 非法命令 0x99（服务端应拒绝——预期 Accept 失败或命令被拒）
            std::vector<std::uint8_t> wire{0x05, 0x01, 0x00};
            wire.insert(wire.end(), {0x05, 0x99, 0x00, 0x01, 10, 0, 0, 1, 0x01, 0xBB});
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            co_await std::move(server_task);
        });
    }

    TEST(Socks5ConnErrorMatrix, BadAddressType)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                const auto err = co_await accept_server(ioc, std::make_shared<MemoryStream>(std::move(b)),
                                                        Socks5::ServerConfig{});
                EXPECT_EQ(err, Preview::Error::BadMessage); // ATYP=9 → ParseAddress 拒绝
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            std::vector<std::uint8_t> wire{0x05, 0x01, 0x00};
            wire.insert(wire.end(), {0x05, 0x01, 0x00, 0x09, 0x00, 0x50}); // ATYP=9 非法
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            co_await std::move(server_task);
        });
    }

    TEST(Socks5ConnErrorMatrix, RequestTruncated)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                const auto err = co_await accept_server(ioc, std::make_shared<MemoryStream>(std::move(b)),
                                                        Socks5::ServerConfig{});
                EXPECT_EQ(err, Preview::Error::IoError); // 请求头半包后 EOF
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            // Greeting 正常 + 请求半包（域名长度声明 20 但只给 5）
            std::vector<std::uint8_t> wire{0x05, 0x01, 0x00};
            wire.insert(wire.end(), {0x05, 0x01, 0x00, 0x03, 0x14});
            wire.insert(wire.end(), {'h', 'e', 'l', 'l', 'o'});
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            a.Close();
            co_await std::move(server_task);
        });
    }

    TEST(Socks5ConnErrorMatrix, ClientBadReply)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto Done = std::make_shared<net::experimental::channel<void(boost::system::error_code)>>(
                ioc.get_executor(), 1);
            auto Failure = std::make_shared<std::exception_ptr>();
            net::co_spawn(
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
                make_addr(Socks5::AddressType::Domain, "example.com", 443));
            EXPECT_EQ(err, Preview::Error::VersionMismatch);
            co_await Done->async_receive(net::use_awaitable);
            EXPECT_FALSE(*Failure);
        });
    }

    TEST(Socks5ConnErrorMatrix, NoAcceptableMethod)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            // 服务端启用认证，客户端只提 no_auth → 无可用方法
            Socks5::ServerConfig cfg;
            cfg.EnableAuth = true;

            auto server_coro = [&]() -> net::awaitable<void>
            {
                const auto err = co_await accept_server(ioc, std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Preview::Error::NotSupported);
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            const std::vector<std::uint8_t> wire{0x05, 0x01, 0x00}; // 只提 no_auth
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            co_await std::move(server_task);
        });
    }

} // namespace
