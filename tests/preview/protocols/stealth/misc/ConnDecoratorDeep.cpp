/**
 * @file ConnDecoratorDeep.cpp
 * @brief 测试库 Conn 装饰器剩余方法深度测试
 * @details 覆盖 gun / reality / anytls / tuic 四个 Conn 装饰器的
 *          Executor / Cancel / NextLayer（const + 非 const）/ Release
 *          / Close 等透传方法，以及 Mux::StreamTransmission 的
 *          空句柄 Executor 与 Cancel 分支。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>

#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Mux/Smux/Smux.hpp>
#include <common/Protocols/Mux/Stream.hpp>
#include <common/Protocols/Tuic/Conn.hpp>
#include <common/Protocols/Anytls/Conn.hpp>
#include <common/Protocols/Gun/Conn.hpp>
#include <common/Protocols/Reality/Conn.hpp>
#include <gtest/gtest.h>

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
        // 同一 io_context 可能被多次驱动，restart() 重置 stopped 标志
        ioc.restart();
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
     * @brief 断言装饰器透传方法（Executor/Cancel/NextLayer/Release/Close）
     */
    template <typename DecoT>
    auto check_decorator(const std::shared_ptr<DecoT> &ConnT, net::io_context &ioc) -> void
    {
        (void)ConnT->Executor();
        EXPECT_NE(ConnT->NextLayer(), nullptr);
        const auto *cconn = ConnT.get();
        EXPECT_NE(cconn->NextLayer(), nullptr);
        EXPECT_EQ(ConnT->template lowest_layer<MemoryStream>(), ConnT->NextLayer());
        ConnT->Cancel();
        ConnT->Close();
        auto released = ConnT->Release();
        EXPECT_NE(released, nullptr);
        EXPECT_EQ(ConnT->NextLayer(), nullptr);
    }

    TEST(ConnDecorator, GunConn)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Conn = std::make_shared<Gun::Conn<>>(std::make_shared<MemoryStream>(std::move(a)));

        // 未握手读写 → not_open
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code ec;
                     std::array<std::byte, 4> buf{};
                     const auto r = co_await Conn->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     EXPECT_TRUE(ec);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                     ec.clear();
                     const auto w = co_await Conn->async_write_some(std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(w, 0u);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                 });

        // 客户端握手 → 数据面透传
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     EXPECT_EQ(co_await Conn->WriteHandshake("example.com"), Error::None);
                     std::array<std::byte, 8> wbuf{std::byte{0x42}};
                     std::error_code ec;
                     EXPECT_EQ(co_await Conn->async_write_some(std::span<const std::byte>(wbuf), ec), 8u);

                     // 先读 CONNECT 握手头（"CONNECT example.com HTTP/2\r\n\r\n" 共 30 字节），
                     // 再验证数据面载荷原样透传
                     std::array<std::byte, 64> hdr{};
                     const auto hn = co_await peer->async_read_some(std::span<std::byte>(hdr), ec);
                     EXPECT_EQ(hn, 30u);
                     std::array<std::byte, 8> rbuf{};
                     const auto rn = co_await peer->async_read_some(std::span<std::byte>(rbuf), ec);
                     EXPECT_EQ(rn, 8u);
                     if (rn == 8u)
                     {
                         EXPECT_EQ(static_cast<std::uint8_t>(rbuf[0]), 0x42);
                     }
                 });

        check_decorator(Conn, ioc);
    }

    TEST(ConnDecorator, RealityConn)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Reality::Conn<>>(
            std::make_shared<MemoryStream>(std::move(a)), std::array<std::uint8_t, 32>{});
        check_decorator(Conn, ioc);
    }

    TEST(ConnDecorator, AnyTlsConn)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn =
            std::make_shared<Anytls::Conn<>>(std::make_shared<MemoryStream>(std::move(a)), "Secret");
        check_decorator(Conn, ioc);
    }

    TEST(ConnDecorator, TuicConn)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Tuic::Conn<>>(std::make_shared<MemoryStream>(std::move(a)),
                                                 std::array<std::uint8_t, 16>{});
        check_decorator(Conn, ioc);
    }

    TEST(ConnDecorator, StreamTransmission)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        // 空句柄：Executor 返回默认执行器，Cancel 空操作
        auto Empty = std::make_shared<Mux::StreamTransmission>(nullptr);
        (void)Empty->Executor();
        Empty->Cancel();
        EXPECT_FALSE(Empty->IsOpen());
        EXPECT_EQ(Empty->Handle(), nullptr);
        Empty->Close();
        Empty->Reset();
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code ec;
                     std::array<std::byte, 4> buf{};
                     const auto r = co_await Empty->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                     ec.clear();
                     const auto w = co_await Empty->async_write_some(std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(w, 0u);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                 });

        // 非空句柄：Cancel 生效
        auto Client = Mux::Smux::Connect(std::make_shared<MemoryStream>(std::move(a)));
        auto Session = Client.Session();
        EXPECT_TRUE(Client.IsOpen());
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto Handle = co_await Session->OpenStream();
                     if (!Handle)
                     {
                         EXPECT_TRUE(false) << "OpenStream Failed";
                         co_return;
                     }
                     auto Stream = std::make_shared<Mux::StreamTransmission>(Handle);
                     EXPECT_TRUE(Stream->IsOpen());
                     EXPECT_EQ(Stream->Handle(), Handle);
                     Stream->Cancel();
                     std::array<std::byte, 4> buf{};
                     std::error_code ec;
                     const auto r = co_await Stream->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     // 非空句柄 Close / Reset（co_spawn 投递）
                     Stream->Close();
                     Stream->Reset();
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_FALSE(Stream->IsOpen());
                 });
    }

} // namespace