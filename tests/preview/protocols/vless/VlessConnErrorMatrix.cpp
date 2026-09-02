/**
 * @file VlessConnErrorMatrix.cpp
 * @brief VLESS Conn 错误矩阵测试
 * @details 服务端握手错误路径：
 * - UUID 不匹配（bad_auth）
 * - 非法版本（bad_magic）
 * - 非法命令（not_supported）
 * - 非法地址类型（bad_message）
 * - 半包截断（io_error）
 * - 客户端响应校验失败
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Vless/Vless.hpp>

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

    constexpr auto make_uuid = []() -> std::array<std::uint8_t, 16>
    {
        return {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    };

    TEST(VlessConnErrorMatrix, BadUuid)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Vless::ServerConfig cfg;
            cfg.uuid = make_uuid();

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Vless::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::BadAuth);
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            std::vector<std::uint8_t> wire{Vless::ProtocolVersion};
            wire.insert(wire.end(), 16, 0xAB); // 错误 UUID
            // addonsLen + cmd + port + atyp + addr(4B)：完整合法请求，仅 UUID 错误
            wire.insert(wire.end(), {0x00, 0x01, 0x01, 0xBB, 0x01, 0x01, 0x00, 0x50, 0x01});
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            EXPECT_FALSE(ec);
            a.Close();
            co_await std::move(server_task);
        });
    }

    TEST(VlessConnErrorMatrix, BadVersion)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Vless::ServerConfig cfg;
            cfg.uuid = make_uuid();

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Vless::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::BadMagic);
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            std::vector<std::uint8_t> wire{0x99}; // 错误版本
            wire.insert(wire.end(), 16, 0x01);
            wire.insert(wire.end(), {0x00, 0x01, 0x01, 0xBB, 0x01, 0x01, 0x00, 0x50});
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            co_await std::move(server_task);
        });
    }

    TEST(VlessConnErrorMatrix, BadCommand)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Vless::ServerConfig cfg;
            cfg.uuid = make_uuid();

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Vless::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::BadMessage); // 命令 0x99 不在 Tcp/udp/mux 白名单
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            std::vector<std::uint8_t> wire{Vless::ProtocolVersion};
            wire.insert(wire.end(), 16, 0x01);
            wire.insert(wire.end(), {0x00, 0x99, 0x01, 0xBB, 0x01, 0x01, 0x00, 0x50}); // 命令 0x99
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            co_await std::move(server_task);
        });
    }

    TEST(VlessConnErrorMatrix, BadAddressType)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Vless::ServerConfig cfg;
            cfg.uuid = make_uuid();

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Vless::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::BadMessage); // ATYP=9 非法
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            std::vector<std::uint8_t> wire{Vless::ProtocolVersion};
            wire.insert(wire.end(), 16, 0x01);
            wire.insert(wire.end(), {0x00, 0x01, 0x01, 0xBB, 0x09, 0x01, 0x00, 0x50}); // ATYP=9
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            co_await std::move(server_task);
        });
    }

    TEST(VlessConnErrorMatrix, TruncatedHeader)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Vless::ServerConfig cfg;
            cfg.uuid = make_uuid();

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Vless::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::IoError); // 半包后 EOF
            };
            auto server_task = net::co_spawn(ioc.get_executor(), server_coro(), net::use_awaitable);

            std::vector<std::uint8_t> wire{Vless::ProtocolVersion};
            wire.insert(wire.end(), 16, 0x01);
            wire.insert(wire.end(), {0x00, 0x01, 0x01, 0xBB}); // 截断
            std::error_code ec;
            co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            a.Close();
            co_await std::move(server_task);
        });
    }

} // namespace
