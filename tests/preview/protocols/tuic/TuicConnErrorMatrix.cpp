/**
 * @file TuicConnErrorMatrix.cpp
 * @brief Tuic Conn 错误矩阵测试
 * @details 服务端握手错误路径：
 * - 半包截断（帧头/地址体未收满 → unexpected_eof）
 * - 正常握手基线（Connect/Accept 成功）
 * @note Preview::Tuic 握手为简化实现（不做 UUID/密码认证），
 *       故无 BadCredential 用例。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Tuic/Tuic.hpp>

namespace
{
    using namespace Preview;
    namespace net = boost::asio;

    /**
     * @brief 驱动协程运行
     */
    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ioc.stop();
                      });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    /**
     * @brief 生成测试 UUID（全 0x55）
     */
    auto make_uuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> u{};
        u.fill(0x55);
        return u;
    }

    auto test_exporter(std::span<std::uint8_t> Output, std::span<const std::uint8_t> Label,
                       std::string_view Context) -> bool
    {
        std::uint8_t State = 0x5A;
        for (const auto Byte : Label)
        {
            State = static_cast<std::uint8_t>((State * 33U) ^ Byte);
        }
        for (const auto Byte : Context)
        {
            State = static_cast<std::uint8_t>((State * 33U) ^ static_cast<std::uint8_t>(Byte));
        }
        for (std::size_t I = 0; I < Output.size(); ++I)
        {
            State = static_cast<std::uint8_t>(State * 33U + static_cast<std::uint8_t>(I));
            Output[I] = State;
        }
        return true;
    }

    using CompletionChannel = net::experimental::channel<void(boost::system::error_code)>;

    auto RunTruncatedServer(SharedTransmission Data, Tuic::ServerConfig Config)
        -> net::awaitable<void>
    {
        auto [err, req, Conn] = co_await Tuic::Accept(std::move(Data), Config);
        EXPECT_EQ(err, Error::UnexpectedEof);
        EXPECT_FALSE(Conn);
        (void)req;
    }

    auto RunHandshakeServer(SharedTransmission Data, Tuic::ServerConfig Config,
                            std::shared_ptr<CompletionChannel> Done) -> net::awaitable<void>
    {
        auto [err, req, Conn] = co_await Tuic::Accept(std::move(Data), Config);
        EXPECT_EQ(err, Error::None);
        EXPECT_TRUE(Conn);
        EXPECT_EQ(req.Cmd, Tuic::CmdConnect);
        EXPECT_EQ(req.dst.Host, "t.internal");
        EXPECT_EQ(req.dst.Port, 443u);
        co_await Done->async_send(boost::system::error_code{}, net::use_awaitable);
    }

    TEST(TuicConnErrorMatrix, TruncatedHeader)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto [auth_a, auth_b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            Tuic::ServerConfig cfg;
            cfg.uuid = make_uuid();
            cfg.password = "pw";
            cfg.AuthStream = std::make_shared<MemoryStream>(std::move(auth_b));
            cfg.Exporter = test_exporter;

            auto Done = std::make_shared<CompletionChannel>(ioc.get_executor(), 1);
            auto Failure = std::make_shared<std::exception_ptr>();
            net::co_spawn(
                ioc.get_executor(),
                RunTruncatedServer(std::make_shared<MemoryStream>(std::move(b)),
                                   cfg),
                [Done, Failure](std::exception_ptr Ep)
                {
                    *Failure = Ep;
                    Done->try_send(boost::system::error_code{});
                });

            // 认证 uni stream 提前关闭，服务端必须拒绝不完整认证帧。
            (void)a;
            auth_a.Close();
            co_await Done->async_receive(net::use_awaitable);
            EXPECT_FALSE(*Failure);
            co_return;
        });
    }

    TEST(TuicConnErrorMatrix, HandshakeOk)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto [auth_a, auth_b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto Done = std::make_shared<CompletionChannel>(ioc.get_executor(), 1);
            auto Failure = std::make_shared<std::exception_ptr>();
            net::co_spawn(
                ioc.get_executor(),
                RunHandshakeServer(
                    std::make_shared<MemoryStream>(std::move(b)),
                    Tuic::ServerConfig{make_uuid(), "pw", std::make_shared<MemoryStream>(std::move(auth_b)),
                                       test_exporter},
                    Done),
                [Done, Failure](std::exception_ptr Ep)
                {
                    *Failure = Ep;
                    Done->try_send(boost::system::error_code{});
                });

            Tuic::ClientConfig cfg;
            cfg.uuid = make_uuid();
            cfg.password = "pw";
            cfg.AuthStream = std::make_shared<MemoryStream>(std::move(auth_a));
            cfg.Exporter = test_exporter;
            auto [err, Conn] = co_await Tuic::Connect(
                std::make_shared<MemoryStream>(std::move(a)), cfg,
                Tuic::Address{Tuic::AddressType::Domain, "t.internal", 443});
            EXPECT_EQ(err, Error::None);
            EXPECT_NE(Conn, nullptr);
            co_await Done->async_receive(net::use_awaitable);
            EXPECT_FALSE(*Failure);
            co_return;
        });
    }

} // namespace
