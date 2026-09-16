/**
 * @file TransportTest.cpp
 * @brief 传输抽象测试（MemoryStream / Reliable / bench）
 * @details 验证：
 *          - MemoryStream 双向数据一致与关闭语义
 *          - BenchThroughput / bench_latency 统计正确
 *          - Stream concept 约束生效
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstring>
#include <limits>

#include <TestSupport/Benchmark/Bench.hpp>
#include <Preview/Transport/Algorithm.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <Preview/Transport/Stream.hpp>
#include <Preview/Transport/Unreliable.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;

    /// 回环跑一个协程并返回异常（MuxLifecycle 模式）
    template <typename A>
    auto RunCoro(Net::io_context &Ioc, A Coro) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Coro),
                      [&](std::exception_ptr Error)
                      {
                          Exception = Error;
                          Ioc.stop();
                      });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    class AlgorithmStream final
    {
    public:
        AlgorithmStream(Net::any_io_executor Ex, std::vector<std::uint8_t> Input)
            : Ex_(std::move(Ex)), Input_(std::move(Input))
        {
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &Ec)
            -> Net::awaitable<std::size_t>
        {
            if (!ReadFailureConsumed && ReadFailure)
            {
                ReadFailureConsumed = true;
                const auto Count = (std::min)(ReadFailureBytes, Input_.size() - Offset_);
                if (Count > 0)
                {
                    std::memcpy(Buffer.data(), Input_.data() + Offset_, Count);
                    Offset_ += Count;
                }
                Ec = ReadFailure;
                co_return Count;
            }
            const auto Count = (std::min)(Buffer.size(), Input_.size() - Offset_);
            if (Count == 0)
            {
                Ec.clear();
                co_return 0;
            }
            std::memcpy(Buffer.data(), Input_.data() + Offset_, Count);
            Offset_ += Count;
            Ec.clear();
            if (OverreportRead && Count != 0)
            {
                co_return Count + 1U;
            }
            co_return Count;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &Ec)
            -> Net::awaitable<std::size_t>
        {
            if (!WriteFailureConsumed && WriteFailure)
            {
                WriteFailureConsumed = true;
                const auto Count = (std::min)(WriteFailureBytes, Buffer.size());
                Ec = WriteFailure;
                co_return Count;
            }
            Ec.clear();
            if (OverreportWrite && !Buffer.empty())
            {
                co_return Buffer.size() + 1U;
            }
            co_return Buffer.size();
        }

        auto Close() -> void { Closed_ = true; }
        auto Cancel() -> void { Canceled_ = true; }
        [[nodiscard]] auto IsOpen() const -> bool { return !Closed_; }
        [[nodiscard]] auto Executor() const -> Net::any_io_executor { return Ex_; }

    private:
        Net::any_io_executor Ex_;
        std::vector<std::uint8_t> Input_;
        std::size_t Offset_{0};
        bool Closed_{false};
        bool Canceled_{false};

    public:
        bool OverreportRead{false};
        bool OverreportWrite{false};
        std::error_code ReadFailure{};
        std::size_t ReadFailureBytes{0};
        std::error_code WriteFailure{};
        std::size_t WriteFailureBytes{0};

    private:
        bool ReadFailureConsumed{false};
        bool WriteFailureConsumed{false};
    };

    static_assert(Preview::Stream<AlgorithmStream>);

    TEST(Transport, AlgorithmReadExactUsesStreamPrimitives)
    {
        Net::io_context ioc;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     AlgorithmStream Stream(ioc.get_executor(), {0x01, 0x02, 0x03});
                     std::array<std::uint8_t, 3> Buffer{};
                     const auto Ec = co_await Preview::AsyncReadExact(Stream, Buffer);
                     EXPECT_FALSE(Ec);
                     EXPECT_EQ(Buffer, (std::array<std::uint8_t, 3>{0x01, 0x02, 0x03}));
                 });
    }

    TEST(Transport, AlgorithmWriteExactUsesStreamPrimitives)
    {
        Net::io_context ioc;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     AlgorithmStream Stream(ioc.get_executor(), {});
                     const std::array<std::uint8_t, 3> Buffer{0x01, 0x02, 0x03};
                     const auto Ec = co_await Preview::AsyncWriteExact(Stream, Buffer);
                     EXPECT_FALSE(Ec);
                 });
    }

    TEST(Transport, AlgorithmReadExactRejectsOverreport)
    {
        Net::io_context ioc;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     AlgorithmStream Stream(ioc.get_executor(), {0x01, 0x02, 0x03});
                     Stream.OverreportRead = true;
                     std::array<std::uint8_t, 2> Buffer{};
                     const auto Ec = co_await Preview::AsyncReadExact(Stream, Buffer);
                     EXPECT_EQ(Ec, Preview::make_error_code(Preview::Error::BrokenPipe));
                 });
    }

    TEST(Transport, AlgorithmReadExactPreservesTimeout)
    {
        Net::io_context Ioc;
        RunCoro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     AlgorithmStream Stream(Ioc.get_executor(), {0x01U});
                     Stream.ReadFailure = std::make_error_code(std::errc::timed_out);
                     std::array<std::uint8_t, 1> Buffer{};
                     const auto ErrorCode = co_await Preview::AsyncReadExact(Stream, Buffer);
                     EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::Timeout));
                 });
    }

    TEST(Transport, AlgorithmReadExactPreservesCanceled)
    {
        Net::io_context Ioc;
        RunCoro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     AlgorithmStream Stream(Ioc.get_executor(), {0x01U});
                     Stream.ReadFailure = std::make_error_code(std::errc::operation_canceled);
                     std::array<std::uint8_t, 1> Buffer{};
                     const auto ErrorCode = co_await Preview::AsyncReadExact(Stream, Buffer);
                     EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::Canceled));
                 });
    }

    TEST(Transport, AlgorithmWriteExactPreservesBrokenPipe)
    {
        Net::io_context Ioc;
        RunCoro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     AlgorithmStream Stream(Ioc.get_executor(), {});
                     Stream.WriteFailure = std::make_error_code(std::errc::broken_pipe);
                     const std::array<std::uint8_t, 1> Buffer{0x01U};
                     const auto ErrorCode = co_await Preview::AsyncWriteExact(Stream, Buffer);
                     EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::BrokenPipe));
                 });
    }

    TEST(Transport, AlgorithmWriteExactRejectsOverreport)
    {
        Net::io_context ioc;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     AlgorithmStream Stream(ioc.get_executor(), {});
                     Stream.OverreportWrite = true;
                     const std::array<std::uint8_t, 2> Buffer{0x01, 0x02};
                     const auto Ec = co_await Preview::AsyncWriteExact(Stream, Buffer);
                     EXPECT_EQ(Ec, Preview::make_error_code(Preview::Error::BrokenPipe));
                 });
    }

    TEST(Transport, MemoryPairEcho)
    {
        Net::io_context ioc;
        auto [a, b] = Preview::MakeMemoryPair(ioc.get_executor());
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const std::string msg = "hello memory pipe";
                     EXPECT_FALSE(co_await a.WriteAll(std::span<const std::uint8_t>(
                         reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size())));
                     std::array<std::uint8_t, 64> buf{};
                     const auto n = co_await b.ReadSome(buf);
                     EXPECT_EQ(n, msg.size());
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), msg);
                 });
    }

    TEST(Transport, MemoryPairCloseSemantics)
    {
        Net::io_context ioc;
        auto [a, b] = Preview::MakeMemoryPair(ioc.get_executor());
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     a.Close();
                     // 对端读返回 0
                     std::array<std::uint8_t, 8> buf{};
                     const auto n = co_await b.ReadSome(buf);
                     EXPECT_EQ(n, 0u);
                     // 对端写返回 broken_pipe
                     const auto ec = co_await b.WriteAll(buf);
                     EXPECT_EQ(ec, Net::error::broken_pipe);
                 });
    }

    TEST(Transport, BenchThroughputMemory)
    {
        Net::io_context ioc;
        auto [a, b] = Preview::MakeMemoryPair(ioc.get_executor());
        Preview::BenchReport r{};
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Preview::BenchOptions opt;
                     opt.Total = 16 * 1024 * 1024; // 16MB
                     opt.Block = 64 * 1024;
                     r = co_await Preview::BenchThroughput(a, b, opt);
                 });
        EXPECT_EQ(r.Bytes, 16u * 1024u * 1024u);
        EXPECT_GT(r.Mbps, 0.0);
    }

    TEST(Transport, ReadTimeout)
    {
        Net::io_context ioc;
        auto [a, b] = Preview::MakeMemoryPair(ioc.get_executor());
        bool timed_out = false;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     std::array<std::uint8_t, 16> buf{};
                     a.SetTimeout(std::chrono::milliseconds(50));
                     const auto t0 = std::chrono::steady_clock::now();
                     const auto n = co_await a.ReadSome(buf);
                     const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                         std::chrono::steady_clock::now() - t0)
                                         .count();
                     EXPECT_EQ(n, 0u);
                     EXPECT_GE(ms, 40);
                     timed_out = true;
                 });
        EXPECT_TRUE(timed_out);
    }

    TEST(Transport, ShutdownSemantics)
    {
        Net::io_context ioc;
        auto [a, b] = Preview::MakeMemoryPair(ioc.get_executor());
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     a.Shutdown();
                     // 对端读返回 0（半关）
                     std::array<std::uint8_t, 8> buf{};
                     const auto n = co_await b.ReadSome(buf);
                     EXPECT_EQ(n, 0u);
                     // 半关后本端写端已关闭，继续写必须返回 broken_pipe
                     const auto local_ec = co_await a.WriteAll(buf);
                     EXPECT_EQ(local_ec, Net::error::broken_pipe);
                     // 半关后本端仍可读对端数据
                     const auto wec = co_await b.WriteAll(buf);
                     EXPECT_FALSE(wec);
                     std::array<std::uint8_t, 8> buf2{};
                     const auto n2 = co_await a.ReadSome(buf2);
                     EXPECT_EQ(n2, 8u);
                 });
    }

    TEST(Transport, CancelSemantics)
    {
        Net::io_context ioc;
        auto [a, b] = Preview::MakeMemoryPair(ioc.get_executor());
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto reader = [&]() -> Net::awaitable<void>
                     {
                         std::array<std::uint8_t, 8> buf{};
                         const auto n = co_await a.ReadSome(buf);
                         EXPECT_EQ(n, 0u);
                     };
                     auto reader_task = Net::co_spawn(a.Executor(), std::move(reader), Net::use_awaitable);
                     // 让 reader 先挂起
                     co_await Net::post(a.Executor(), Net::use_awaitable);
                     co_await Net::post(a.Executor(), Net::use_awaitable);
                     a.Cancel();
                     co_await std::move(reader_task);
                 });
    }

    TEST(Transport, MemoryStreamCloseWhileReadPending)
    {
        Net::io_context ioc;
        auto [a_value, b] = Preview::MakeMemoryPair(ioc.get_executor());
        auto a = std::make_shared<Preview::MemoryStream>(std::move(a_value));
        auto read_done = std::make_shared<bool>(false);
        auto child_ep = std::make_shared<std::exception_ptr>();

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto AsyncRead = [a, read_done]()
                         -> Net::awaitable<void>
                     {
                         std::array<std::uint8_t, 8> Buffer{};
                         const auto n = co_await a->ReadSome(Buffer);
                         EXPECT_EQ(n, 0U);
                         *read_done = true;
                     };
                     auto on_error = [read_done, child_ep](const std::exception_ptr &ep)
                     {
                         *child_ep = ep;
                         *read_done = true;
                     };
                     Net::co_spawn(a->Executor(), std::move(AsyncRead), std::move(on_error));
                     co_await Net::post(a->Executor(), Net::use_awaitable);
                     a->Close();

                     Net::steady_timer Wait(a->Executor());
                     Wait.expires_after(std::chrono::milliseconds(20));
                     co_await Wait.async_wait(Net::use_awaitable);
                 });

        ASSERT_FALSE(*child_ep);
        EXPECT_TRUE(*read_done);
    }

    TEST(Transport, MemoryStreamCancelWhileReadPending)
    {
        Net::io_context ioc;
        auto [a_value, b] = Preview::MakeMemoryPair(ioc.get_executor());
        auto a = std::make_shared<Preview::MemoryStream>(std::move(a_value));
        auto read_done = std::make_shared<bool>(false);
        auto child_ep = std::make_shared<std::exception_ptr>();

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto AsyncRead = [a, read_done]()
                         -> Net::awaitable<void>
                     {
                         std::array<std::uint8_t, 8> Buffer{};
                         const auto n = co_await a->ReadSome(Buffer);
                         EXPECT_EQ(n, 0U);
                         *read_done = true;
                     };
                     auto on_error = [read_done, child_ep](const std::exception_ptr &ep)
                     {
                         *child_ep = ep;
                         *read_done = true;
                     };
                     Net::co_spawn(a->Executor(), std::move(AsyncRead), std::move(on_error));
                     co_await Net::post(a->Executor(), Net::use_awaitable);
                     a->Cancel();

                     Net::steady_timer Wait(a->Executor());
                     Wait.expires_after(std::chrono::milliseconds(20));
                     co_await Wait.async_wait(Net::use_awaitable);
                 });

        ASSERT_FALSE(*child_ep);
        EXPECT_TRUE(*read_done);
    }

    TEST(Transport, MemoryStreamTimeoutWhileReadPending)
    {
        Net::io_context ioc;
        auto [a_value, b] = Preview::MakeMemoryPair(ioc.get_executor());
        auto a = std::make_shared<Preview::MemoryStream>(std::move(a_value));
        auto read_done = std::make_shared<bool>(false);
        auto child_ep = std::make_shared<std::exception_ptr>();

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     a->SetTimeout(std::chrono::milliseconds(20));
                     auto AsyncRead = [a, read_done]()
                         -> Net::awaitable<void>
                     {
                         std::array<std::byte, 8> Buffer{};
                         std::error_code ec;
                         const auto n = co_await a->async_read_some(Buffer, ec);
                         EXPECT_EQ(n, 0U);
                         EXPECT_EQ(ec, std::make_error_code(std::errc::timed_out));
                         *read_done = true;
                     };
                     auto on_error = [read_done, child_ep](const std::exception_ptr &ep)
                     {
                         *child_ep = ep;
                         *read_done = true;
                     };
                     Net::co_spawn(a->Executor(), std::move(AsyncRead), std::move(on_error));
                     Net::steady_timer Wait(a->Executor());
                     Wait.expires_after(std::chrono::milliseconds(50));
                     co_await Wait.async_wait(Net::use_awaitable);
                 });

        ASSERT_FALSE(*child_ep);
        EXPECT_TRUE(*read_done);
    }

    // ══════════════ T0-3 超时语义（Transmission 虚接口） ══════════════

    TEST(Transport, AsyncReadTimeoutError)
    {
        // async_read_some 超时 → operation_timed_out 错误
        Net::io_context ioc;
        auto [a, b] = Preview::MakeMemoryPair(ioc.get_executor());
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     a.SetTimeout(std::chrono::milliseconds(30));
                     std::array<std::byte, 16> buf{};
                     std::error_code ec;
                     const auto n = co_await a.async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec, std::make_error_code(std::errc::timed_out));
                 });
    }

    TEST(Transport, AsyncReadTimeoutDisabled)
    {
        // SetTimeout(0) 禁用 → 挂起直到数据到达
        Net::io_context ioc;
        auto [a, b] = Preview::MakeMemoryPair(ioc.get_executor());
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     a.SetTimeout(std::chrono::milliseconds(0));
                     auto writer = [&]() -> Net::awaitable<void>
                     {
                         std::array<std::byte, 4> Data{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
                         co_await Net::post(a.Executor(), Net::use_awaitable);
                         co_await Net::post(a.Executor(), Net::use_awaitable);
                         std::error_code wec;
                         co_await b.async_write_some(Data, wec);
                     };
                     Net::co_spawn(a.Executor(), writer(), Net::detached);
                     std::array<std::byte, 16> buf{};
                     std::error_code ec;
                     const auto n = co_await a.async_read_some(buf, ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_FALSE(ec);
                 });
    }

    TEST(Transport, InterfaceTransmissionLike)
    {
        // Transmission 派生类满足扩展 concept（Shutdown/SetTimeout/IsOpen）
        static_assert(Preview::TransmissionLike<Preview::MemoryStream>);
        static_assert(Preview::TransmissionLike<Preview::Transport::Reliable>);
    }

    TEST(Transport, InterfaceIsOpen)
    {
        Net::io_context ioc;
        auto [a, b] = Preview::MakeMemoryPair(ioc.get_executor());
        EXPECT_TRUE(a.IsOpen());
        a.Close();
        EXPECT_FALSE(a.IsOpen());
    }

    TEST(Transport, InterfaceShutdownEof)
    {
        // 通过虚接口多态调用 Shutdown：对端读 EOF
        Net::io_context ioc;
        auto [a, b] = Preview::MakeMemoryPair(ioc.get_executor());
        Preview::Transmission &ref = a;
        ref.Shutdown();
        std::array<std::uint8_t, 8> buf{};
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto n = co_await b.ReadSome(buf);
                     EXPECT_EQ(n, 0u);
                 });
    }

    TEST(Transport, InterfaceSetTimeoutPolymorphic)
    {
        // 通过基类指针设置超时 → 读超时错误
        Net::io_context ioc;
        auto [a, b] = Preview::MakeMemoryPair(ioc.get_executor());
        Preview::Transmission *base = &a;
        base->SetTimeout(std::chrono::milliseconds(20));
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     std::array<std::byte, 8> buf{};
                     std::error_code ec;
                     const auto n = co_await a.async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec, std::make_error_code(std::errc::timed_out));
                 });
    }

    // ══════════════ 真实 TCP/UDP 叶子读超时 ══════════════

    /// 建立一对已连接的 TCP socket（回环、同步 accept）
    auto MakeTcpPair(Net::io_context &Ioc) -> std::pair<Net::ip::tcp::socket, Net::ip::tcp::socket>
    {
        Net::ip::tcp::acceptor Acceptor(Ioc, Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        Net::ip::tcp::socket Client(Ioc);
        Client.connect(Acceptor.local_endpoint());
        Net::ip::tcp::socket Server(Ioc);
        Acceptor.accept(Server);
        return {std::move(Client), std::move(Server)};
    }

    TEST(Transport, ReliableReadTimeout)
    {
        // 真实 TCP：SetTimeout 后无数据到达 → operation_timed_out，且不早于超时时间
        Net::io_context ioc;
        auto [Client, Server] = MakeTcpPair(ioc);
        auto Reliable = std::make_shared<Preview::Transport::Reliable>(std::move(Client));
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Reliable->SetTimeout(std::chrono::milliseconds(40));
                     std::array<std::byte, 8> Buffer{};
                     std::error_code ec;
                     const auto Start = std::chrono::steady_clock::now();
                     const auto N = co_await Reliable->async_read_some(Buffer, ec);
                     const auto Elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::steady_clock::now() - Start)
                                              .count();
                     EXPECT_EQ(N, 0u);
                     EXPECT_EQ(ec, std::make_error_code(std::errc::timed_out));
                     EXPECT_GE(Elapsed, 25);
                     Server.close();
                 });
    }

    TEST(Transport, ReliableReadBeforeTimeoutStillSucceeds)
    {
        // 真实 TCP：超时窗口内到达的数据照常返回，不触发超时
        Net::io_context ioc;
        auto [Client, Server] = MakeTcpPair(ioc);
        auto Reliable = std::make_shared<Preview::Transport::Reliable>(std::move(Client));
        const std::array<std::byte, 4> Payload{std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};
        boost::system::error_code WriteEc;
        Net::write(Server, Net::buffer(Payload), WriteEc);
        ASSERT_FALSE(WriteEc);
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Reliable->SetTimeout(std::chrono::milliseconds(500));
                     std::array<std::byte, 8> Buffer{};
                     std::error_code ec;
                     const auto N = co_await Reliable->async_read_some(Buffer, ec);
                     EXPECT_EQ(N, Payload.size());
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(Buffer[0], Payload[0]);
                     Server.close();
                  });
    }

    TEST(Transport, ReliableConnectReturnsErrorCodeOnRefusal)
    {
        Net::io_context ioc;
        Net::ip::tcp::acceptor Acceptor(
            ioc, Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        const auto Endpoint = Acceptor.local_endpoint();
        boost::system::error_code CloseError;
        Acceptor.close(CloseError);
        ASSERT_FALSE(CloseError);

        auto Reliable = std::make_shared<Preview::Transport::Reliable>(ioc.get_executor());
        boost::system::error_code Result;
        std::exception_ptr Thrown;
        Net::co_spawn(
            ioc,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Reliable->Connect(Endpoint, std::chrono::milliseconds(0));
            },
            [&](std::exception_ptr Error)
            {
                Thrown = std::move(Error);
                ioc.stop();
            });
        ioc.run();

        EXPECT_FALSE(Thrown);
        EXPECT_TRUE(Result);
    }

    TEST(Transport, ReliableHandlerReadTimeout)
    {
        // 真实 TCP：completion-handler 读路径同样遵守 SetTimeout
        Net::io_context ioc;
        auto [Client, Server] = MakeTcpPair(ioc);
        auto Reliable = std::make_shared<Preview::Transport::Reliable>(std::move(Client));
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Reliable->SetTimeout(std::chrono::milliseconds(40));
                     std::array<std::byte, 8> Buffer{};
                     auto Result = std::make_shared<std::pair<boost::system::error_code, std::size_t>>();
                     Net::experimental::channel<void(boost::system::error_code)> Done(ioc.get_executor(), 1);
                     Reliable->async_read_some(
                         std::span<std::byte>(Buffer.data(), Buffer.size()),
                         [Result, &Done](const boost::system::error_code Ec, const std::size_t N)
                         {
                             Result->first = Ec;
                             Result->second = N;
                             (void)Done.try_send(boost::system::error_code{});
                        });
                     co_await Done.async_receive(Net::use_awaitable);
                     EXPECT_EQ(Result->second, 0u);
                      EXPECT_EQ(Result->first, Net::error::timed_out);
                     Server.close();
                  });
    }

    TEST(Transport, UnreliableHandlerReadTimeout)
    {
        // 真实 UDP：completion-handler 读路径不能因 Transmission 所有权桥接失败而返回 not_supported
        Net::io_context ioc;
        auto Udp = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
        ASSERT_TRUE(Udp->Bind(0));
        Net::ip::udp::socket Peer(ioc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
        Udp->SetRemote(Peer.local_endpoint());
        auto Base = std::static_pointer_cast<Preview::Transmission>(Udp);
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Udp->SetTimeout(std::chrono::milliseconds(40));
                     std::array<std::byte, 8> Buffer{};
                     auto Result = std::make_shared<std::pair<boost::system::error_code, std::size_t>>();
                     Net::experimental::channel<void(boost::system::error_code)> Done(ioc.get_executor(), 1);
                     Base->async_read_some(
                         std::span<std::byte>(Buffer.data(), Buffer.size()),
                         [Result, &Done](const boost::system::error_code Ec, const std::size_t N)
                         {
                             Result->first = Ec;
                             Result->second = N;
                             (void)Done.try_send(boost::system::error_code{});
                         });
                     co_await Done.async_receive(Net::use_awaitable);
                     EXPECT_EQ(Result->second, 0u);
                      EXPECT_EQ(Result->first, boost::system::errc::make_error_code(
                                                   boost::system::errc::timed_out));
                     Udp->Close();
                 });
    }

    TEST(Transport, UnreliableReadTimeout)
    {
        // 真实 UDP：SetTimeout 后无数据到达 → operation_timed_out
        Net::io_context ioc;
        auto Udp = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
        ASSERT_TRUE(Udp->Bind(0));
        Net::ip::udp::socket Peer(ioc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
        Udp->SetRemote(Peer.local_endpoint());
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Udp->SetTimeout(std::chrono::milliseconds(40));
                     std::array<std::byte, 8> Buffer{};
                     std::error_code ec;
                     const auto N = co_await Udp->async_read_some(Buffer, ec);
                     EXPECT_EQ(N, 0u);
                     EXPECT_EQ(ec, std::make_error_code(std::errc::timed_out));
                     Udp->Close();
                 });
    }

    TEST(Transport, UnreliableReadBeforeTimeoutStillSucceeds)
    {
        // 真实 UDP：超时窗口内到达的数据照常返回
        Net::io_context ioc;
        auto Udp = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
        boost::system::error_code BindEc;
        Udp->NativeSocket().open(Net::ip::udp::v4(), BindEc);
        ASSERT_FALSE(BindEc);
        Udp->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0), BindEc);
        ASSERT_FALSE(BindEc);
        Net::ip::udp::socket Peer(ioc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
        Udp->SetRemote(Peer.local_endpoint());
        const std::array<std::byte, 3> Payload{std::byte{0x0A}, std::byte{0x0B}, std::byte{0x0C}};
        boost::system::error_code SendEc;
        Peer.send_to(Net::buffer(Payload), Udp->LocalEndpoint(), 0, SendEc);
        ASSERT_FALSE(SendEc) << "send_to failed: " << SendEc.message()
                             << " target=" << Udp->LocalEndpoint();
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Udp->SetTimeout(std::chrono::milliseconds(500));
                     std::array<std::byte, 8> Buffer{};
                     std::error_code ec;
                     const auto N = co_await Udp->async_read_some(Buffer, ec);
                     EXPECT_EQ(N, Payload.size());
                     EXPECT_FALSE(ec);
                     Udp->Close();
                 });
    }

} // namespace
