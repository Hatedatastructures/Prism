/**
 * @file TestPsmTransport.cpp
 * @brief psm::transport 系测试库组件深度测试
 * @details 覆盖 psm::transport::transmission 抽象基类全部方法
 *          （prefix / transport_type / completion-handler 桥接 /
 *          next_layer / lowest_layer）与 async_write / async_read
 *          自由函数的错误路径，legacy_bridge 的空操作方法与
 *          cancel / set_timeout，socket_stream / udp_transmission
 *          的真实 socket 收发，以及 middleware dial / relay 的
 *          name() 访问器。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <future>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <common/core/byte_span.hpp>
#include <common/core/fault/code.hpp>
#include <common/core/fault/compatible.hpp>
#include <common/core/middleware/builtin/dial.hpp>
#include <common/core/middleware/builtin/relay.hpp>
#include <common/core/transport/legacy_bridge.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/core/transport/socket_stream.hpp>
#include <common/core/transport/transmission.hpp>
#include <common/core/transport/udp_transmission.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    namespace psmt = psm::transport;

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
     * @brief psm::transport::transmission 测试替身（叶子节点）
     */
    class mock_transport final : public psmt::transmission
    {
    public:
        explicit mock_transport(net::any_io_executor ex,
                                std::error_code read_ec = {}, std::size_t read_n = 0)
            : ex_(std::move(ex)), read_ec_(read_ec), read_n_(read_n)
        {
        }

        [[nodiscard]] auto executor() const -> executor_type override
        {
            return ex_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec = read_ec_;
            co_return read_n_;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte>, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (write_calls_++ == 0 && write_first_ok_)
            {
                ec.clear();
                co_return write_n_;
            }
            ec = write_ec_;
            co_return 0;
        }

        void close() override
        {
        }

        void cancel() override
        {
        }

        using psmt::transmission::async_read_some;
        using psmt::transmission::async_write_some;

        std::error_code write_ec_{};
        std::size_t write_n_{0};
        bool write_first_ok_{false};
        std::size_t write_calls_{0};

    private:
        net::any_io_executor ex_;
        std::error_code read_ec_;
        std::size_t read_n_;
    };

    TEST(PsmTransmission, BasicAccessors)
    {
        net::io_context ioc;
        mock_transport t(ioc.get_executor());

        // 叶子节点 transport_type → tcp
        EXPECT_EQ(t.transport_type(), psmt::transmission::type::tcp);
        EXPECT_EQ(t.next_layer(), nullptr);
        const auto *ct = &t;
        EXPECT_EQ(ct->next_layer(), nullptr);
        EXPECT_EQ(t.get_executor(), t.executor());
        EXPECT_EQ(t.lowest_layer<mock_transport>(), &t);
        EXPECT_EQ(ct->lowest_layer<const mock_transport>(), ct);
        EXPECT_EQ(t.lowest_layer<net::io_context>(), nullptr);

        // prefix 访问器
        auto ctx = std::make_shared<psm::diagnose::context>();
        t.set_prefix(ctx);
        EXPECT_EQ(t.prefix(), ctx);
    }

    TEST(PsmTransmission, DelegatedTransportType)
    {
        net::io_context ioc;
        // 子节点覆写 transport_type 返回 udp，验证委托路径
        struct udp_like final : public psmt::transmission
        {
            explicit udp_like(net::any_io_executor ex) : ex_(std::move(ex))
            {
            }
            [[nodiscard]] auto transport_type() const noexcept -> type override
            {
                return type::udp;
            }
            [[nodiscard]] auto executor() const -> executor_type override
            {
                return ex_;
            }
            [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &ec)
                -> net::awaitable<std::size_t> override
            {
                co_return 0;
            }
            [[nodiscard]] auto async_write_some(std::span<const std::byte>, std::error_code &ec)
                -> net::awaitable<std::size_t> override
            {
                co_return 0;
            }
            void close() override
            {
            }
            void cancel() override
            {
            }
            net::any_io_executor ex_;
        };
        udp_like leaf(ioc.get_executor());
        EXPECT_EQ(leaf.transport_type(), psmt::transmission::type::udp);

        // 装饰器：next_layer 非空 → 委托
        struct wrapper final : public psmt::transmission
        {
            explicit wrapper(psmt::transmission *n) : n_(n)
            {
            }
            [[nodiscard]] auto next_layer() noexcept -> transmission * override
            {
                return n_;
            }
            [[nodiscard]] auto next_layer() const noexcept -> const transmission * override
            {
                return n_;
            }
            [[nodiscard]] auto executor() const -> executor_type override
            {
                return n_->executor();
            }
            [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &ec)
                -> net::awaitable<std::size_t> override
            {
                co_return 0;
            }
            [[nodiscard]] auto async_write_some(std::span<const std::byte>, std::error_code &ec)
                -> net::awaitable<std::size_t> override
            {
                co_return 0;
            }
            void close() override
            {
            }
            void cancel() override
            {
            }
            psmt::transmission *n_;
        };
        wrapper w(&leaf);
        EXPECT_EQ(w.transport_type(), psmt::transmission::type::udp);
        EXPECT_EQ(w.lowest_layer<udp_like>(), &leaf);
        EXPECT_EQ(w.next_layer(), &leaf);
    }

    TEST(PsmTransmission, CompletionHandlerBridges)
    {
        net::io_context ioc;
        mock_transport t(ioc.get_executor(), std::make_error_code(std::errc::io_error), 0);

        // completion-handler 风格读（默认 co_spawn 桥接）
        std::promise<std::pair<boost::system::error_code, std::size_t>> done_r;
        auto fr = done_r.get_future();
        t.async_read_some(std::span<std::byte>{}, [&](boost::system::error_code ec, std::size_t n)
                          { done_r.set_value({ec, n}); });
        ioc.run();
        const auto [rec, rn] = fr.get();
        EXPECT_EQ(rn, 0u);

        // completion-handler 风格写（独立 io_context）
        net::io_context ioc2;
        mock_transport t2(ioc2.get_executor());
        std::promise<std::pair<boost::system::error_code, std::size_t>> done_w;
        auto fw = done_w.get_future();
        std::array<std::byte, 4> buf{};
        t2.async_write_some(std::span<const std::byte>(buf), [&](boost::system::error_code ec, std::size_t n)
                            { done_w.set_value({ec, n}); });
        ioc2.run();
        (void)fw.get();
    }

    TEST(PsmTransmission, FreeAsyncWriteRead)
    {
        net::io_context ioc;
        std::array<std::byte, 8> buf{};
        std::error_code ec;

        // async_write：单次写满
        mock_transport ok(ioc.get_executor());
        ok.write_first_ok_ = true;
        ok.write_n_ = 8;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto n = co_await psmt::async_write(ok, std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(n, 8u);
                     EXPECT_FALSE(ec);
                 });

        // async_write：部分写入后错误中断
        mock_transport err(ioc.get_executor());
        err.write_first_ok_ = true;
        err.write_n_ = 4;
        err.write_ec_ = std::make_error_code(std::errc::io_error);
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto n = co_await psmt::async_write(err, std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_TRUE(ec);
                 });

        // async_write：n==0 停止（ec 保持原值）
        ec.clear();
        mock_transport zero(ioc.get_executor());
        zero.write_n_ = 0;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto n = co_await psmt::async_write(zero, std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_FALSE(ec);
                 });

        // async_read：错误中断
        mock_transport rerr(ioc.get_executor(), std::make_error_code(std::errc::io_error), 0);
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto n = co_await psmt::async_read(rerr, std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_TRUE(ec);
                 });
    }

    TEST(PsmTransmission, ToEcBranches)
    {
        // 空错误码 → 空 boost ec（经 completion-handler 桥接触发 to_ec）
        {
            net::io_context ioc;
            mock_transport ok(ioc.get_executor());
            std::promise<boost::system::error_code> done1;
            auto f1 = done1.get_future();
            ok.async_read_some(std::span<std::byte>{}, [&](boost::system::error_code ec, std::size_t)
                               { done1.set_value(ec); });
            ioc.run();
            EXPECT_FALSE(f1.get());
        }

        // fault 分类错误 → boost 协议分类（fault::category() 匹配）
        {
            net::io_context ioc;
            const auto fault_ec = psm::fault::make_error_code(psm::fault::code::eof);
            mock_transport ft(ioc.get_executor(), fault_ec, 0);
            std::promise<boost::system::error_code> done2;
            auto f2 = done2.get_future();
            ft.async_read_some(std::span<std::byte>{}, [&](boost::system::error_code ec, std::size_t)
                               { done2.set_value(ec); });
            ioc.run();
            EXPECT_TRUE(f2.get());
        }

        // generic 分类错误 → generic boost ec
        {
            net::io_context ioc;
            const auto gen_ec = std::make_error_code(std::errc::connection_reset);
            mock_transport gt(ioc.get_executor(), gen_ec, 0);
            std::promise<boost::system::error_code> done3;
            auto f3 = done3.get_future();
            gt.async_read_some(std::span<std::byte>{}, [&](boost::system::error_code ec, std::size_t)
                               { done3.set_value(ec); });
            ioc.run();
            EXPECT_EQ(f3.get(), boost::system::error_code(gen_ec.value(),
                                                          boost::system::generic_category()));
        }
    }

    TEST(LegacyBridge, NoopMethods)
    {
        net::io_context ioc;
        auto [a, b] = psmtest::make_memory_pair(ioc.get_executor());
        auto bridge = psmtest::make_legacy(std::make_shared<psmtest::memory_stream>(std::move(a)));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::fprintf(stderr, "[dbg] s1\n");
                     co_await bridge->shutdown();
                     std::fprintf(stderr, "[dbg] s2\n");
                     bridge->set_timeout(std::chrono::milliseconds(100));
                     std::fprintf(stderr, "[dbg] s3\n");
                     bridge->cancel();
                     std::fprintf(stderr, "[dbg] s4\n");
                     EXPECT_TRUE(bridge->is_open());
                     std::fprintf(stderr, "[dbg] s5\n");
                     (void)bridge->executor();
                     std::fprintf(stderr, "[dbg] s6\n");
                     co_await bridge->close();
                     std::fprintf(stderr, "[dbg] s7\n");
                     EXPECT_FALSE(bridge->is_open());
                 });
    }

    TEST(SocketStream, LoopbackTransfer)
    {
        net::io_context ioc;
        psmtest::socket_stream server_sock(ioc.get_executor());
        psmtest::socket_stream client_sock(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto acceptor_ep =
                         net::ip::tcp::endpoint(net::ip::address_v4::loopback(), 0);
                     net::ip::tcp::acceptor acceptor(ioc.get_executor(), acceptor_ep);
                     const auto ep = acceptor.local_endpoint();

                     auto accept_coro = [&]() -> net::awaitable<void>
                     {
                         co_await acceptor.async_accept(server_sock.lowest_layer(), net::use_awaitable);
                         co_return;
                     };
                     net::co_spawn(ioc.get_executor(), accept_coro(), net::detached);

                     const auto cerr = co_await client_sock.connect(ep);
                     EXPECT_FALSE(cerr);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_TRUE(client_sock.is_open());

                    // 写 → 读
                    const std::string_view msg = "ping";
                    const auto werr = co_await client_sock.write_all(psmtest::as_u8_span(msg));
                     EXPECT_FALSE(werr);
                     std::array<std::uint8_t, 8> rbuf{};
                     const auto n = co_await server_sock.read_some(std::span<std::uint8_t>(rbuf));
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(rbuf.data()), n), "ping");

                     // 半关
                     co_await client_sock.shutdown();
                     client_sock.cancel();
                     server_sock.close();
                     client_sock.close();
                 });
    }

    TEST(UdpTransmission, LoopbackDatagram)
    {
        net::io_context ioc;
        psmtest::udp_transmission client(ioc.get_executor());
        psmtest::udp_transmission server(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // udp_transmission 构造后 socket 未打开，需先 open
                     boost::system::error_code oec;
                     server.socket().open(net::ip::udp::v4(), oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "open failed: " << oec.message();
                         co_return;
                     }
                     if (!server.bind(0))
                     {
                         EXPECT_TRUE(false) << "bind failed";
                         co_return;
                     }
                     client.socket().open(net::ip::udp::v4(), oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "client open failed";
                         co_return;
                     }
                     const auto local = server.socket().local_endpoint();
                     const auto local_addr = local.address().is_unspecified()
                                                 ? std::string("127.0.0.1")
                                                 : local.address().to_string();
                     if (!client.connect(local_addr + ":" + std::to_string(local.port())))
                     {
                         EXPECT_TRUE(false) << "connect failed";
                         co_return;
                     }

                     const std::string_view msg = "udp!";
                     std::error_code ec;
                     const auto w =
                         co_await client.async_write_some(psmtest::as_bytes(psmtest::as_u8_span(msg)), ec);
                     EXPECT_EQ(w, 4u);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 16> rbuf{};
                     const auto r = co_await server.async_read_some(std::span<std::byte>(rbuf), ec);
                     EXPECT_EQ(r, 4u);
                     EXPECT_EQ(static_cast<char>(rbuf[0]), 'u');

                     server.cancel();
                     server.close();
                     client.close();
                 });
    }

    TEST(MiddlewareNames, Accessors)
    {
        psm::middleware::builtin::dial_middleware dial;
        EXPECT_EQ(dial.name(), "dial");
        psm::middleware::builtin::relay_middleware relay(nullptr);
        EXPECT_EQ(relay.name(), "relay");
    }

} // namespace
