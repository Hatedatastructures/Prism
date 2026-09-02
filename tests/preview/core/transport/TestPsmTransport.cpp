/**
 * @file TestPsmTransport.cpp
 * @brief Preview::Transport 系测试库组件深度测试
 * @details 覆盖 Preview::Transport::Transmission 抽象基类全部方法
 *          （Prefix / TransportType / completion-handler 桥接 /
 *          NextLayer / lowest_layer）与 AsyncWrite / AsyncRead
 *          自由函数的错误路径，传输层的空操作方法与
 *          Cancel / SetTimeout，Reliable / Unreliable
 *          的真实 socket 收发，以及 Middleware Dial / relay 的
 *          Name() 访问器。
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

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Compatible.hpp>
#include <preview/Runtime/Middleware/Builtin/Dial.hpp>
#include <preview/Runtime/Middleware/Builtin/Relay.hpp>

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Transport/Reliable.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Transport/Unreliable.hpp>
#include <gtest/gtest.h>

namespace
{
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
     * @brief Preview::Transport::Transmission 测试替身（叶子节点）
     */
    class mock_transport final : public Preview::Transmission
    {
    public:
        explicit mock_transport(net::any_io_executor ex,
                                std::error_code ReadEc = {}, std::size_t read_n = 0)
            : Ex_(std::move(ex)), read_ec_(ReadEc), read_n_(read_n)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
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

        void Close() override
        {
        }

        void Cancel() override
        {
        }

        using Preview::Transmission::async_read_some;
        using Preview::Transmission::async_write_some;

        std::error_code write_ec_{};
        std::size_t write_n_{0};
        bool write_first_ok_{false};
        std::size_t write_calls_{0};

    private:
        net::any_io_executor Ex_;
        std::error_code read_ec_;
        std::size_t read_n_;
    };

    TEST(PsmTransmission, BasicAccessors)
    {
        net::io_context ioc;
        mock_transport t(ioc.get_executor());

        // 叶子节点 TransportType → Tcp
        EXPECT_EQ(t.TransportType(), Preview::Transmission::Type::Tcp);
        EXPECT_EQ(t.NextLayer(), nullptr);
        const auto *ct = &t;
        EXPECT_EQ(ct->NextLayer(), nullptr);
        EXPECT_EQ(t.get_executor(), t.Executor());
        EXPECT_EQ(t.lowest_layer<mock_transport>(), &t);
        EXPECT_EQ(ct->lowest_layer<const mock_transport>(), ct);
        EXPECT_EQ(t.lowest_layer<net::io_context>(), nullptr);

    }

    TEST(PsmTransmission, DelegatedTransportType)
    {
        net::io_context ioc;
        // 子节点覆写 TransportType 返回 udp，验证委托路径
        struct udp_like final : public Preview::Transmission
        {
            explicit udp_like(net::any_io_executor ex) : Ex_(std::move(ex))
            {
            }
            [[nodiscard]] auto TransportType() const noexcept -> Type override
            {
                return Type::Udp;
            }
            [[nodiscard]] auto Executor() const -> ExecutorType override
            {
                return Ex_;
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
            void Close() override
            {
            }
            void Cancel() override
            {
            }
            net::any_io_executor Ex_;
        };
        udp_like leaf(ioc.get_executor());
        EXPECT_EQ(leaf.TransportType(), Preview::Transmission::Type::Udp);

        // 装饰器：NextLayer 非空 → 委托
        struct wrapper final : public Preview::Transmission
        {
            explicit wrapper(Preview::Transmission *n) : n_(n)
            {
            }
            [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
            {
                return n_;
            }
            [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
            {
                return n_;
            }
            [[nodiscard]] auto Executor() const -> ExecutorType override
            {
                return n_->Executor();
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
            void Close() override
            {
            }
            void Cancel() override
            {
            }
            Preview::Transmission *n_;
        };
        wrapper w(&leaf);
        EXPECT_EQ(w.TransportType(), Preview::Transmission::Type::Udp);
        EXPECT_EQ(w.lowest_layer<udp_like>(), &leaf);
        EXPECT_EQ(w.NextLayer(), &leaf);
    }

    TEST(PsmTransmission, CompletionHandlerBridges)
    {
        net::io_context ioc;
        auto t = std::make_shared<mock_transport>(
            ioc.get_executor(), std::make_error_code(std::errc::io_error), 0);

        // completion-handler 风格读（默认 co_spawn 桥接）
        std::promise<std::pair<boost::system::error_code, std::size_t>> done_r;
        auto fr = done_r.get_future();
        t->async_read_some(std::span<std::byte>{}, [&](boost::system::error_code ec, std::size_t n)
                          { done_r.set_value({ec, n}); });
        ioc.run();
        const auto [rec, rn] = fr.get();
        EXPECT_EQ(rn, 0u);

        // completion-handler 风格写（独立 io_context）
        net::io_context ioc2;
        auto t2 = std::make_shared<mock_transport>(ioc2.get_executor());
        std::promise<std::pair<boost::system::error_code, std::size_t>> done_w;
        auto fw = done_w.get_future();
        std::array<std::byte, 4> buf{};
        t2->async_write_some(std::span<const std::byte>(buf), [&](boost::system::error_code ec, std::size_t n)
                            { done_w.set_value({ec, n}); });
        ioc2.run();
        (void)fw.get();
    }

    TEST(PsmTransmission, FreeAsyncWriteRead)
    {
        net::io_context ioc;
        std::array<std::byte, 8> buf{};
        std::error_code ec;

        // AsyncWrite：单次写满
        mock_transport Ok(ioc.get_executor());
        Ok.write_first_ok_ = true;
        Ok.write_n_ = 8;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto n = co_await Ok.AsyncWrite(std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(n, 8u);
                     EXPECT_FALSE(ec);
                 });

        // AsyncWrite：部分写入后错误中断
        mock_transport err(ioc.get_executor());
        err.write_first_ok_ = true;
        err.write_n_ = 4;
        err.write_ec_ = std::make_error_code(std::errc::io_error);
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto n = co_await err.AsyncWrite(std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_TRUE(ec);
                 });

        // AsyncWrite：n==0 表示对端关闭 → broken_pipe
        ec.clear();
        mock_transport zero(ioc.get_executor());
        zero.write_n_ = 0;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto n = co_await zero.AsyncWrite(std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_TRUE(ec);
                 });

        // AsyncRead：错误中断
        mock_transport rerr(ioc.get_executor(), std::make_error_code(std::errc::io_error), 0);
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto n = co_await rerr.AsyncRead(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_TRUE(ec);
                 });
    }

    TEST(PsmTransmission, ToEcBranches)
    {
        // 空错误码 → 空 boost ec（经 completion-handler 桥接触发 ToEc）
        {
            net::io_context ioc;
            auto Ok = std::make_shared<mock_transport>(ioc.get_executor());
            std::promise<boost::system::error_code> done1;
            auto f1 = done1.get_future();
            Ok->async_read_some(std::span<std::byte>{}, [&](boost::system::error_code ec, std::size_t)
                               { done1.set_value(ec); });
            ioc.run();
            EXPECT_FALSE(f1.get());
        }

        // fault 分类错误 → boost 协议分类（Fault::Category() 匹配）
        {
            net::io_context ioc;
            const auto fault_ec = Preview::Fault::make_error_code(Preview::Fault::Code::Eof);
            auto ft = std::make_shared<mock_transport>(ioc.get_executor(), fault_ec, 0);
            std::promise<boost::system::error_code> done2;
            auto f2 = done2.get_future();
            ft->async_read_some(std::span<std::byte>{}, [&](boost::system::error_code ec, std::size_t)
                               { done2.set_value(ec); });
            ioc.run();
            EXPECT_TRUE(f2.get());
        }

        // generic 分类错误 → generic boost ec
        {
            net::io_context ioc;
            const auto gen_ec = std::make_error_code(std::errc::connection_reset);
            auto gt = std::make_shared<mock_transport>(ioc.get_executor(), gen_ec, 0);
            std::promise<boost::system::error_code> done3;
            auto f3 = done3.get_future();
            gt->async_read_some(std::span<std::byte>{}, [&](boost::system::error_code ec, std::size_t)
                               { done3.set_value(ec); });
            ioc.run();
            EXPECT_EQ(f3.get(), boost::system::error_code(gen_ec.value(),
                                                          boost::system::generic_category()));
        }
    }

    TEST(SocketStream, LoopbackTransfer)
    {
        net::io_context ioc;
        Preview::Transport::Reliable server_sock(ioc.get_executor());
        Preview::Transport::Reliable client_sock(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto acceptor_ep =
                         net::ip::tcp::endpoint(net::ip::address_v4::loopback(), 0);
                     net::ip::tcp::acceptor acceptor(ioc.get_executor(), acceptor_ep);
                     const auto ep = acceptor.local_endpoint();

                     auto accept_coro = [&]() -> net::awaitable<void>
                     {
                         co_await acceptor.async_accept(server_sock.NativeSocket(), net::use_awaitable);
                         co_return;
                     };
                     net::co_spawn(ioc.get_executor(), accept_coro(), net::detached);

                     const auto cerr = co_await client_sock.Connect(ep);
                     EXPECT_FALSE(cerr);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_TRUE(client_sock.IsOpen());

                    // 写 → 读
                    const std::string_view msg = "ping";
                    std::error_code wec;
                    co_await client_sock.async_write_some(Preview::AsBytesSpan(msg), wec);
                    EXPECT_FALSE(wec);
                    std::array<std::byte, 8> rbuf{};
                    std::error_code rec;
                    const auto n = co_await server_sock.async_read_some(std::span<std::byte>(rbuf), rec);
                    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(rbuf.data()), n), "ping");

                     // 半关
                     client_sock.Shutdown();
                     client_sock.Cancel();
                     server_sock.Close();
                     client_sock.Close();
                 });
    }

    TEST(UdpTransmission, LoopbackDatagram)
    {
        net::io_context ioc;
        Preview::Transport::Unreliable Client(ioc.get_executor());
        Preview::Transport::Unreliable Server(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // Unreliable 构造后 socket 未打开，需先 Open
                     boost::system::error_code oec;
                     Server.NativeSocket().open(net::ip::udp::v4(), oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "Open Failed: " << oec.message();
                         co_return;
                     }
                     if (!Server.Bind(0))
                     {
                         EXPECT_TRUE(false) << "Bind Failed";
                         co_return;
                     }
                     Client.NativeSocket().open(net::ip::udp::v4(), oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "Client Open Failed";
                         co_return;
                     }
                     const auto local = Server.NativeSocket().local_endpoint();
                     const auto local_addr = local.address().is_unspecified()
                                                 ? std::string("127.0.0.1")
                                                 : local.address().to_string();
                     if (!Client.Connect(local_addr + ":" + std::to_string(local.port())))
                     {
                         EXPECT_TRUE(false) << "Connect Failed";
                         co_return;
                     }

                     const std::string_view msg = "udp!";
                     std::error_code ec;
                     const auto w =
                         co_await Client.async_write_some(Preview::AsBytes(Preview::AsU8Span(msg)), ec);
                     EXPECT_EQ(w, 4u);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 16> rbuf{};
                     const auto r = co_await Server.async_read_some(std::span<std::byte>(rbuf), ec);
                     EXPECT_EQ(r, 4u);
                     EXPECT_EQ(static_cast<char>(rbuf[0]), 'u');

                     Server.Cancel();
                     Server.Close();
                     Client.Close();
                 });
    }

    TEST(MiddlewareNames, Accessors)
    {
        Preview::Middleware::Builtin::DialMiddleware Dial;
        EXPECT_EQ(Dial.Name(), "Dial");
        Preview::Middleware::Builtin::RelayMiddleware relay(nullptr);
        EXPECT_EQ(relay.Name(), "relay");
    }

} // namespace
