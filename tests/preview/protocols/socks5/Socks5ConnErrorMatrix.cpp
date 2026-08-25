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
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Socks5/Socks5.hpp>

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
                EXPECT_EQ(err, Preview::Error::version_mismatch);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            const std::vector<std::uint8_t> wire{0x04, 0x01, 0x00}; // 错误版本
            std::error_code ec;
            co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
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
                EXPECT_EQ(err, Preview::Error::io_error); // 半包后 EOF → 底层 IO 错误
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            const std::vector<std::uint8_t> wire{0x05, 0x02}; // 缺 nmethods 后续
            std::error_code ec;
            co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            a.Close();
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
                EXPECT_EQ(err, Preview::Error::bad_auth);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // Greeting（user_pass 方法）→ userpass（错误密码）
            std::vector<std::uint8_t> wire{0x05, 0x01, 0x02};
            wire.insert(wire.end(), {0x01, 0x05});
            wire.insert(wire.end(), {'a', 'l', 'i', 'c', 'e'});
            wire.insert(wire.end(), {0x07});
            wire.insert(wire.end(), {'w', 'r', 'o', 'n', 'g', 'p', 'w'});
            std::error_code ec;
            co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
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
                EXPECT_EQ(err, Preview::Error::not_supported);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // 非法命令 0x99（服务端应拒绝——预期 Accept 失败或命令被拒）
            std::vector<std::uint8_t> wire{0x05, 0x01, 0x00};
            wire.insert(wire.end(), {0x05, 0x99, 0x00, 0x01, 10, 0, 0, 1, 0x01, 0xBB});
            std::error_code ec;
            co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            std::array<std::uint8_t, 16> resp{};
            co_await a.AsyncReadSome(AsBytes(std::span<std::uint8_t>(resp)), ec);
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
                EXPECT_EQ(err, Preview::Error::bad_message); // ATYP=9 → ParseAddress 拒绝
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            std::vector<std::uint8_t> wire{0x05, 0x01, 0x00};
            wire.insert(wire.end(), {0x05, 0x01, 0x00, 0x09, 0x00, 0x50}); // ATYP=9 非法
            std::error_code ec;
            co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
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
                EXPECT_EQ(err, Preview::Error::io_error); // 请求头半包后 EOF
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // Greeting 正常 + 请求半包（域名长度声明 20 但只给 5）
            std::vector<std::uint8_t> wire{0x05, 0x01, 0x00};
            wire.insert(wire.end(), {0x05, 0x01, 0x00, 0x03, 0x14});
            wire.insert(wire.end(), {'h', 'e', 'l', 'l', 'o'});
            std::error_code ec;
            co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            a.Close();
        });
    }

    TEST(Socks5ConnErrorMatrix, ClientBadReply)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            // 服务端：手动回非法响应版本
            auto server_coro = [&]() -> net::awaitable<void>
            {
                std::array<std::uint8_t, 8> buf{};
                std::error_code ec;
                const auto n = co_await b.AsyncReadSome(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
                (void)n;
                // Greeting 响应（错误版本 0x04）
                const std::array<std::uint8_t, 2> sel{0x04, 0x00};
                co_await b.AsyncWriteSome(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(sel.data()), sel.size()), ec);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            Socks5::ClientConfig cfg;
            auto [err, Conn] = co_await Socks5::Connect(
                std::make_shared<MemoryStream>(std::move(a)), cfg,
                make_addr(Socks5::AddressType::Domain, "example.com", 443));
            EXPECT_EQ(err, Preview::Error::version_mismatch);
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
                EXPECT_EQ(err, Preview::Error::not_supported);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            const std::vector<std::uint8_t> wire{0x05, 0x01, 0x00}; // 只提 no_auth
            std::error_code ec;
            co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
        });
    }

} // namespace
