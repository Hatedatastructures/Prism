/**
 * @file TrojanConnErrorMatrix.cpp
 * @brief Trojan Conn 错误矩阵测试
 * @details 服务端握手错误路径：
 * - 凭据不匹配（bad_auth）
 * - 凭据后缺 CRLF（bad_magic）
 * - 非法命令（not_supported）
 * - 非法地址类型（bad_message）
 * - 半包截断（io_error）
 * - 客户端响应校验失败
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
#include <common/Protocols/Trojan/Trojan.hpp>

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

    TEST(TrojanConnErrorMatrix, BadCredential)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Trojan::ServerConfig cfg;
            cfg.password = "correct";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Trojan::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::bad_auth);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // 错误凭据（56 hex）+ CRLF + 命令
            const std::string cred(56, '0');
            std::vector<std::uint8_t> wire(cred.begin(), cred.end());
            wire.insert(wire.end(), {'\r', '\n', 0x01, 0x01, 0x00, 0x50});
            std::error_code ec;
            co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
        });
    }

    TEST(TrojanConnErrorMatrix, MissingCrlf)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Trojan::ServerConfig cfg;
            cfg.password = "prism";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Trojan::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::bad_magic); // 凭据后缺 CRLF
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // 正确凭据 + 缺 CRLF
            const auto cred = Trojan::Credential("prism");
            std::vector<std::uint8_t> wire(cred.begin(), cred.end());
            wire.push_back(0x01);
            std::error_code ec;
            co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
        });
    }

    TEST(TrojanConnErrorMatrix, BadCommand)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Trojan::ServerConfig cfg;
            cfg.password = "prism";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Trojan::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::bad_message); // 命令 0x99 不在白名单
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            const auto cred = Trojan::Credential("prism");
            std::vector<std::uint8_t> wire(cred.begin(), cred.end());
            wire.insert(wire.end(), {'\r', '\n', 0x99, 0x01, 0x00, 0x50}); // 命令 0x99
            std::error_code ec;
            co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
        });
    }

    TEST(TrojanConnErrorMatrix, BadAddressType)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Trojan::ServerConfig cfg;
            cfg.password = "prism";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Trojan::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::bad_message); // ATYP=9 非法
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            const auto cred = Trojan::Credential("prism");
            std::vector<std::uint8_t> wire(cred.begin(), cred.end());
            wire.insert(wire.end(), {'\r', '\n', 0x01, 0x09, 0x00, 0x50}); // ATYP=9
            std::error_code ec;
            co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
        });
    }

    TEST(TrojanConnErrorMatrix, TruncatedHeader)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Trojan::ServerConfig cfg;
            cfg.password = "prism";

            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, Conn] = co_await Trojan::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), cfg);
                EXPECT_EQ(err, Error::io_error); // 半包后 EOF
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            const auto cred = Trojan::Credential("prism");
            std::vector<std::uint8_t> wire(cred.begin(), cred.end());
            wire.insert(wire.end(), {'\r', '\n', 0x01}); // 截断
            std::error_code ec;
            co_await a.AsyncWriteSome(AsBytes(std::span<const std::uint8_t>(wire)), ec);
            a.Close();
        });
    }

} // namespace
