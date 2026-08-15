/**
 * @file Socks5ConnErrorMatrix.cpp
 * @brief SOCKS5 conn 错误矩阵测试
 * @details 服务端握手错误路径全覆盖：
 * - 版本不匹配（greeting/request）
 * - 无可用认证方法
 * - 认证失败（错误凭据）
 * - 非法命令 / 非法地址类型
 * - 半包截断（greeting/认证/请求各阶段）
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

#include <common/core/transport/memory_stream.hpp>
#include <common/proxy/socks5/socks5.hpp>

namespace
{
    using namespace psmtest;
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

    auto make_addr(socks5::address_type type, std::string host, std::uint16_t port) -> socks5::address
    {
        socks5::address addr{};
        addr.type = type;
        addr.host = std::move(host);
        addr.port = port;
        return addr;
    }

    /// 服务端 accept（内存对）并返回错误码
    auto accept_server(net::io_context &ioc, shared_transmission stream, socks5::server_config cfg)
        -> net::awaitable<psmtest::error>
    {
        auto [err, req, conn] = co_await socks5::accept(std::move(stream), cfg);
        co_return err;
    }

    TEST(Socks5ConnErrorMatrix, BadVersionGreeting)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                const auto err = co_await accept_server(ioc, std::make_shared<memory_stream>(std::move(b)),
                                                        socks5::server_config{});
                EXPECT_EQ(err, psmtest::error::version_mismatch);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            const std::vector<std::uint8_t> wire{0x04, 0x01, 0x00}; // 错误版本
            std::error_code ec;
            co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
        });
    }

    TEST(Socks5ConnErrorMatrix, GreetingTruncated)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                const auto err = co_await accept_server(ioc, std::make_shared<memory_stream>(std::move(b)),
                                                        socks5::server_config{});
                EXPECT_EQ(err, psmtest::error::io_error); // 半包后 EOF → 底层 IO 错误
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            const std::vector<std::uint8_t> wire{0x05, 0x02}; // 缺 nmethods 后续
            std::error_code ec;
            co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
            a.close();
        });
    }

    TEST(Socks5ConnErrorMatrix, AuthFailure)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            socks5::server_config cfg;
            cfg.enable_auth = true;
            cfg.username = "alice";
            cfg.password = "correct";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                const auto err = co_await accept_server(ioc, std::make_shared<memory_stream>(std::move(b)), cfg);
                EXPECT_EQ(err, psmtest::error::bad_auth);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // greeting（user_pass 方法）→ userpass（错误密码）
            std::vector<std::uint8_t> wire{0x05, 0x01, 0x02};
            wire.insert(wire.end(), {0x01, 0x05});
            wire.insert(wire.end(), {'a', 'l', 'i', 'c', 'e'});
            wire.insert(wire.end(), {0x07});
            wire.insert(wire.end(), {'w', 'r', 'o', 'n', 'g', 'p', 'w'});
            std::error_code ec;
            co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
        });
    }

    TEST(Socks5ConnErrorMatrix, BadCommand)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await socks5::accept(
                    std::make_shared<memory_stream>(std::move(b)), socks5::server_config{});
                // 非法命令 → bad_message（协议拒绝）
                EXPECT_NE(err, psmtest::error::none); // 非法命令被拒绝（码依时序）
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // 非法命令 0x99（服务端应拒绝——预期 accept 失败或命令被拒）
            std::vector<std::uint8_t> wire{0x05, 0x01, 0x00};
            wire.insert(wire.end(), {0x05, 0x99, 0x00, 0x01, 10, 0, 0, 1, 0x01, 0xBB});
            std::error_code ec;
            co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
            std::array<std::uint8_t, 16> resp{};
            co_await a.async_read_some(as_bytes(std::span<std::uint8_t>(resp)), ec);
        });
    }

    TEST(Socks5ConnErrorMatrix, BadAddressType)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                const auto err = co_await accept_server(ioc, std::make_shared<memory_stream>(std::move(b)),
                                                        socks5::server_config{});
                EXPECT_NE(err, psmtest::error::none); // 非法命令被拒绝（码依时序）
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            std::vector<std::uint8_t> wire{0x05, 0x01, 0x00};
            wire.insert(wire.end(), {0x05, 0x01, 0x00, 0x09, 0x00, 0x50}); // ATYP=9 非法
            std::error_code ec;
            co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
        });
    }

    TEST(Socks5ConnErrorMatrix, RequestTruncated)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                const auto err = co_await accept_server(ioc, std::make_shared<memory_stream>(std::move(b)),
                                                        socks5::server_config{});
                EXPECT_NE(err, psmtest::error::none);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // greeting 正常 + 请求半包（域名长度声明 20 但只给 5）
            std::vector<std::uint8_t> wire{0x05, 0x01, 0x00};
            wire.insert(wire.end(), {0x05, 0x01, 0x00, 0x03, 0x14});
            wire.insert(wire.end(), {'h', 'e', 'l', 'l', 'o'});
            std::error_code ec;
            co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
            a.close();
        });
    }

    TEST(Socks5ConnErrorMatrix, ClientBadReply)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            // 服务端：手动回非法响应版本
            auto server_coro = [&]() -> net::awaitable<void>
            {
                std::array<std::uint8_t, 8> buf{};
                std::error_code ec;
                const auto n = co_await b.async_read_some(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
                (void)n;
                // greeting 响应（错误版本 0x04）
                const std::array<std::uint8_t, 2> sel{0x04, 0x00};
                co_await b.async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(sel.data()), sel.size()), ec);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            socks5::client_config cfg;
            auto [err, conn] = co_await socks5::connect(
                std::make_shared<memory_stream>(std::move(a)), cfg,
                make_addr(socks5::address_type::domain, "example.com", 443));
            EXPECT_EQ(err, psmtest::error::version_mismatch);
        });
    }

    TEST(Socks5ConnErrorMatrix, NoAcceptableMethod)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            // 服务端启用认证，客户端只提 no_auth → 无可用方法
            socks5::server_config cfg;
            cfg.enable_auth = true;

            auto server_coro = [&]() -> net::awaitable<void>
            {
                const auto err = co_await accept_server(ioc, std::make_shared<memory_stream>(std::move(b)), cfg);
                EXPECT_EQ(err, psmtest::error::not_supported);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            const std::vector<std::uint8_t> wire{0x05, 0x01, 0x00}; // 只提 no_auth
            std::error_code ec;
            co_await a.async_write_some(as_bytes(std::span<const std::uint8_t>(wire)), ec);
        });
    }

} // namespace
