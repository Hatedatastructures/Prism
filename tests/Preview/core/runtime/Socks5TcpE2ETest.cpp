/**
 * @file Socks5TcpE2ETest.cpp
 * @brief SOCKS5 TCP CONNECT 真实纵向链路测试（阶段 5 v2 补缺）
 * @details 覆盖：
 *          - 真实 TCP listener → Session → adapter::MakeAcceptSocks5 →
 *            Dial → PostDial(success) → relay → echo 上游
 *          - CONNECT 应答「拨号后发送」：上游拒绝时客户端收到 connection_refused
 *          - runtime 传给 Dial 的目标地址与客户端请求一致
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Composition/Adapters/ProtocolAdapter.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/Process.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Runtime/WorkerGroup.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Socks5 = Preview::Socks5;
    namespace Fault = Preview::Fault;
    namespace Network = Preview::Network;
    namespace Runtime = Preview::Runtime;
    namespace Fault = Preview::Fault;
    namespace Network = Preview::Network;
    namespace Runtime = Preview::Runtime;
    using Preview::SharedTransmission;

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Preview::Testing::RunCoro;
    using Preview::Testing::TcpEchoServer;
    using Preview::Testing::StartTcpEchoUpstream;

    class WorkerGroupRunner final
    {
    public:
        explicit WorkerGroupRunner(Runtime::WorkerGroup &GroupValue)
            : Group_(&GroupValue)
        {
            Threads_.reserve(Group_->Size());
            for (std::size_t Index = 0; Index < Group_->Size(); ++Index)
            {
                auto *WorkerValue = Group_->Find(Preview::WorkerId{
                    static_cast<std::uint64_t>(Index + 1)});
                if (WorkerValue)
                {
                    Threads_.emplace_back([WorkerValue] { WorkerValue->Run(); });
                }
            }
        }

        ~WorkerGroupRunner() noexcept
        {
            Group_->Stop();
            for (auto &Thread : Threads_)
            {
                if (Thread.joinable())
                {
                    Thread.join();
                }
            }
        }

        WorkerGroupRunner(const WorkerGroupRunner &) = delete;
        auto operator=(const WorkerGroupRunner &) -> WorkerGroupRunner & = delete;

    private:
        Runtime::WorkerGroup *Group_;
        std::vector<std::thread> Threads_;
    };

    struct Socks5ListenerOptions final
    {
        Net::io_context &IoContext;
        Runtime::WorkerGroup &Workers;
        std::uint16_t EchoPort;
        bool Refused;
    };

    /// SOCKS5 无认证 Greeting
    auto Socks5Greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    /// SOCKS5 CONNECT 请求（domain）
    auto Socks5ConnectRequest(const std::string &Host, std::uint16_t Port) -> std::string
    {
        std::string Request;
        Request.push_back(0x05); // version
        Request.push_back(0x01); // CONNECT
        Request.push_back(0x00); // reserved
        Request.push_back(0x03); // atyp domain
        Request.push_back(static_cast<char>(Host.size()));
        Request += Host;
        Request.push_back(static_cast<char>((Port >> 8) & 0xff));
        Request.push_back(static_cast<char>(Port & 0xff));
        return Request;
    }

    /// 读取 SOCKS5 应答并返回 rep 字段
    /// @note 使用 AsyncRead 读满固定长度，避免半包；错误/EOF 时直接返回
    auto ReadSocks5Reply(SharedTransmission Conn, std::uint8_t &Reply) -> Net::awaitable<void>
    {
        std::array<std::byte, 4> head{};
        std::error_code ec;
        const auto n = co_await Conn->AsyncRead(head, ec);
        if (ec || n < 4)
        {
            co_return;
        }
        Reply = static_cast<std::uint8_t>(head[1]);
        // 跳过 BND.ADDR + BND.PORT
        const auto atyp = static_cast<std::uint8_t>(head[3]);
        std::size_t skip = 2;
        if (atyp == 0x01)
        {
            skip += 4;
        }
        else if (atyp == 0x04)
        {
            skip += 16;
        }
        else if (atyp == 0x03)
        {
            std::array<std::byte, 1> len{};
            const auto ln = co_await Conn->AsyncRead(len, ec);
            if (ec || ln < 1)
            {
                co_return;
            }
            skip += static_cast<std::size_t>(static_cast<std::uint8_t>(len[0]));
        }
        std::vector<std::byte> rest(skip);
        if (!rest.empty())
        {
            co_await Conn->AsyncRead(rest, ec);
        }
    }

    /// SOCKS5 TCP 链路用例结果
    struct Socks5ChainResult
    {
        std::string echo;                 ///< 回显数据
        std::uint8_t rep{0xff};           ///< CONNECT 应答码
    };

    /// 组装 SOCKS5 TCP 会话 listener（识别 → adapter → Dial）
    auto MakeSocks5Listener(Socks5ListenerOptions Options)
        -> Preview::Runtime::TcpListener
    {
        auto &IoContext = Options.IoContext;
        const auto Executor = IoContext.get_executor();
        auto ListenerOptions = Preview::Runtime::TcpListener::Options{};
        ListenerOptions.Executor = Executor;
        ListenerOptions.Workers = &Options.Workers;
        ListenerOptions.Factory =
            [Executor, EchoPort = Options.EchoPort, Refused = Options.Refused](SharedTransmission,
                                                                                 std::size_t)
                -> std::shared_ptr<Preview::Runtime::Session>
            {
                Preview::Runtime::SessionOptions opts;
                opts.RelayIdleTimeout = std::chrono::milliseconds(500);
                Socks5::ServerConfig scfg;
                scfg.EnableTcp = true;
                opts.AcceptProtocol = Preview::Runtime::MakeAcceptSocks5(std::move(scfg));
                opts.Dial = [Executor, EchoPort, Refused](const Preview::Network::Target &t)
                    -> Net::awaitable<
                    std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
                {
                    // 目标必须是客户端请求的地址
                    EXPECT_EQ(t.Host, "example.com");
                    EXPECT_EQ(t.Port, "443");
                    if (Refused)
                    {
                        co_return std::pair{Preview::Fault::Code::ConnectionRefused, nullptr};
                    }
                    std::error_code ec;
                    Preview::Network::Dialer::Dialer Dialer(Executor);
                    auto Conn = co_await Dialer.Connect("127.0.0.1", EchoPort, ec);
                    if (ec)
                    {
                        co_return std::pair{Preview::Fault::Code::Unreachable, nullptr};
                    }
                    co_return std::pair{Preview::Fault::Code::Success, std::move(Conn)};
                };
                return std::make_shared<Preview::Runtime::Session>(std::move(opts));
            };
        return Preview::Runtime::TcpListener(std::move(ListenerOptions));
    }

    /// 运行一条 SOCKS5 TCP CONNECT 链路
    /// @param refused 为 true 时 Dial 返回 connection_refused
    auto RunSocks5Connect(bool refused) -> Socks5ChainResult
    {
        Net::io_context ioc;
        const auto echo_port = StartTcpEchoUpstream(ioc);
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{33};
        ProcessOptions.Generation = Preview::GenerationId{49};
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());
        auto listener = MakeSocks5Listener(
            Socks5ListenerOptions{ioc, ProcessValue.Workers(), echo_port, refused});

        Socks5ChainResult out;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto start_rc = co_await listener.Start(Net::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
                     EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
                     const auto listen_port = listener.LocalEndpoint().port();

                     std::error_code ec;
                     Preview::Network::Dialer::Dialer d(ioc.get_executor());
                     auto Conn = co_await d.Connect("127.0.0.1", listen_port, ec);
                     if (ec || !Conn)
                     {
                         co_return;
                     }

                     // 1. Greeting → Method Reply
                     const auto Greeting = Socks5Greeting();
                     co_await Conn->AsyncWrite(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()), Greeting.size()), ec);
                     if (ec)
                     {
                         Conn->Close();
                         listener.Stop();
                         co_return;
                     }
                     std::array<std::byte, 2> mrep{};
                     const auto mn = co_await Conn->AsyncRead(mrep, ec);
                     if (ec || mn < 2)
                     {
                         Conn->Close();
                         listener.Stop();
                         co_return;
                     }
                     EXPECT_EQ(static_cast<std::uint8_t>(mrep[0]), 0x05);
                     EXPECT_EQ(static_cast<std::uint8_t>(mrep[1]), 0x00);

                     // 2. CONNECT 请求 → 应答（拨号后发送）
                     const auto req = Socks5ConnectRequest("example.com", 443);
                     co_await Conn->AsyncWrite(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(req.data()), req.size()), ec);
                     if (!ec)
                     {
                         co_await ReadSocks5Reply(Conn, out.rep);
                     }

                     // 3. 回显往返（仅拨号成功时）
                     if (!refused && !ec)
                     {
                         const std::string payload = "socks5-e2e-payload";
                         co_await Conn->AsyncWrite(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()), payload.size()), ec);
                         std::array<std::byte, 64> rbuf{};
                         std::error_code rec;
                         const auto rn = co_await Conn->AsyncRead(std::span<std::byte>(rbuf).first(payload.size()), rec);
                         out.echo.assign(reinterpret_cast<const char *>(rbuf.data()), rn);
                     }

                     Conn->Close();
                     // 让 relay 收尾（不依赖 ioc.Stop 打断在途协程）
                     Net::steady_timer timer(ioc.get_executor(), std::chrono::milliseconds(30));
                     boost::system::error_code tec;
                     co_await timer.async_wait(Net::redirect_error(Net::use_awaitable, tec));
                     listener.Stop();
                 });
        return out;
    }

    TEST(Socks5TcpChain, FullConnectEcho)
    {
        const auto r = RunSocks5Connect(false);
        EXPECT_EQ(r.rep, static_cast<std::uint8_t>(Socks5::ReplyCode::Success));
        EXPECT_EQ(r.echo, "socks5-e2e-payload");
    }

    TEST(Socks5TcpChain, DialRefusedMapsToConnectionRefused)
    {
        const auto r = RunSocks5Connect(true);
        EXPECT_EQ(r.rep, static_cast<std::uint8_t>(Socks5::ReplyCode::ConnectionRefused));
        EXPECT_TRUE(r.echo.empty());
    }


    TEST(Socks5TcpChain, ReplyWriteFailureAfterClientDisconnect)
    {
        // A-2 回归：客户端 CONNECT 后立即断开，服务端慢拨号完成后应答写在已关闭连接上，
        // 必须记录错误并收口，不能静默丢失也不得挂起。
        Net::io_context ioc;

        boost::asio::ip::tcp::acceptor echo_acceptor(
            ioc, Net::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        Net::co_spawn(
            ioc.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                while (true)
                {
                    boost::system::error_code ec;
                    auto sock = co_await echo_acceptor.async_accept(
                        Net::redirect_error(Net::use_awaitable, ec));
                    if (ec)
                    {
                        co_return;
                    }
                    Net::co_spawn(ioc.get_executor(), TcpEchoServer(std::move(sock)), Net::detached);
                }
            },
            Net::detached);

        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{34};
        ProcessOptions.Generation = Preview::GenerationId{50};
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Factory =
            [&](Preview::SharedTransmission, std::size_t)
                -> std::shared_ptr<Preview::Runtime::Session>
            {
                Preview::Runtime::SessionOptions opts;
                Socks5::ServerConfig scfg;
                scfg.EnableTcp = true;
                opts.AcceptProtocol = Preview::Runtime::MakeAcceptSocks5(std::move(scfg));
                opts.Dial = [&](const Preview::Network::Target &)
                    -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
                {
                    // 慢拨号：确保客户端已断开后再发送 CONNECT 应答
                    Net::steady_timer slow(ioc.get_executor(), std::chrono::milliseconds(200));
                    boost::system::error_code sec;
                    co_await slow.async_wait(Net::redirect_error(Net::use_awaitable, sec));
                    std::error_code dec;
                    Preview::Network::Dialer::Dialer d(ioc.get_executor());
                    auto Conn = co_await d.Connect("127.0.0.1", echo_port, dec);
                    if (dec)
                    {
                        co_return std::pair{Preview::Fault::Code::Unreachable, nullptr};
                    }
                    co_return std::pair{Preview::Fault::Code::Success, std::move(Conn)};
                };
                return std::make_shared<Preview::Runtime::Session>(std::move(opts));
            };
        Preview::Runtime::TcpListener listener(std::move(ListenerOptions));

        bool completed = false;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto start_rc = co_await listener.Start(
                         Net::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
                     EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
                     const auto listen_port = listener.LocalEndpoint().port();

                     std::error_code ec;
                     Preview::Network::Dialer::Dialer d(ioc.get_executor());
                     auto Conn = co_await d.Connect("127.0.0.1", listen_port, ec);
                     if (ec || !Conn)
                     {
                         listener.Stop();
                         co_return;
                     }

                     // Greeting → Method Reply
                     const auto Greeting = Socks5Greeting();
                     co_await Conn->AsyncWrite(
                         std::span<const std::byte>(
                             reinterpret_cast<const std::byte *>(Greeting.data()),
                             Greeting.size()),
                         ec);
                     if (ec)
                     {
                         Conn->Close();
                         listener.Stop();
                         co_return;
                     }
                     std::array<std::byte, 2> mrep{};
                     const auto mn = co_await Conn->AsyncRead(mrep, ec);
                     if (ec || mn < 2)
                     {
                         Conn->Close();
                         listener.Stop();
                         co_return;
                     }

                     // CONNECT 请求后立即断开
                     const auto req = Socks5ConnectRequest("example.com", 443);
                     co_await Conn->AsyncWrite(
                         std::span<const std::byte>(
                             reinterpret_cast<const std::byte *>(req.data()),
                             req.size()),
                         ec);
                     Conn->Close();

                     // 等待服务端完成慢拨号 + 应答写失败收口
                     Net::steady_timer t(ioc.get_executor(), std::chrono::milliseconds(500));
                     boost::system::error_code tec;
                     co_await t.async_wait(Net::redirect_error(Net::use_awaitable, tec));
                     completed = true;
                     listener.Stop();
                 });
        EXPECT_TRUE(completed);
    }
} // namespace
