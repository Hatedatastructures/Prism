/**
 * @file MuxUploadSim.cpp
 * @brief 模拟 Clash 客户端上行行为的诊断测试
 * @details 模拟真实客户端测速场景：SYN + 地址帧 + 数据帧连续快速发送
 *          （不等服务端 0x00 状态），大数据量多帧上行，验证 echo 完整回传。
 *          三个用例：快速上行（8×1KB）、大流量上传（32×32KB=1MB）、
 *          多流并发上传（6 流 × 8MB）。
 * @note 测试进程退出时 io_context 析构会销毁挂起的协程，Windows 上
 *       存在竞态（挂死/崩溃）。因此 echo server 支持显式停止：
 *       测试末尾设置 stop 并 cancel 挂起的 accept，再驱动 run 让
 *       所有协程正常退出，避免 ioc 析构销毁挂起协程。
 */

#include <prism/diagnose/log.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/connection/outbound/direct.hpp>
#include <prism/net/dns/resolver.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/protocol/protocol.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <utility>

#include <gtest/gtest.h>

namespace net = boost::asio;
using tcp = net::ip::tcp;

using namespace psm::multiplex;

namespace
{

    using CompletionChannel = net::experimental::channel<void(boost::system::error_code)>;

    [[nodiscard]] auto build_smux_header(const smux::command cmd, const std::uint16_t length,
                                         const std::uint32_t stream_id) -> std::array<std::byte, 8>
    {
        return {
            std::byte{smux::protocol_version},
            static_cast<std::byte>(cmd),
            static_cast<std::byte>(length & 0xFF),
            static_cast<std::byte>((length >> 8) & 0xFF),
            static_cast<std::byte>(stream_id & 0xFF),
            static_cast<std::byte>((stream_id >> 8) & 0xFF),
            static_cast<std::byte>((stream_id >> 16) & 0xFF),
            static_cast<std::byte>((stream_id >> 24) & 0xFF),
        };
    }

    [[nodiscard]] auto make_tcp_address(const std::uint16_t port) -> std::vector<std::byte>
    {
        std::vector<std::byte> buf;
        buf.push_back(std::byte{0x00});
        buf.push_back(std::byte{0x00});
        buf.push_back(std::byte{0x01});
        buf.push_back(std::byte{127});
        buf.push_back(std::byte{0});
        buf.push_back(std::byte{0});
        buf.push_back(std::byte{1});
        buf.push_back(std::byte{static_cast<unsigned char>((port >> 8) & 0xFF)});
        buf.push_back(std::byte{static_cast<unsigned char>(port & 0xFF)});
        return buf;
    }

    /**
 * @brief echo 服务器（可停止）
 * @details accept 被取消（stop 后测试端 cancel）时 ec=aborted，协程
 *          正常 co_return 退出——避免 ioc 析构销毁挂起 accept 协程。
 */
    auto echo_connection(std::shared_ptr<tcp::socket> Socket,
                         std::shared_ptr<CompletionChannel> connection_done)
        -> net::awaitable<void>
    {
        try
        {
            std::array<std::byte, 8192> buf{};
            while (true)
            {
                auto n = co_await Socket->async_read_some(net::buffer(buf), net::use_awaitable);
                if (n == 0)
                {
                    break;
                }
                co_await net::async_write(*Socket, net::buffer(buf, n), net::use_awaitable);
            }
        }
        catch (...)
        {
        }
        (void)connection_done->try_send(boost::system::error_code{});
    }

    auto echo_server(std::shared_ptr<tcp::acceptor> acceptor, std::shared_ptr<std::atomic<bool>> stop,
                     std::shared_ptr<CompletionChannel> server_done,
                     std::shared_ptr<CompletionChannel> connection_done,
                     std::shared_ptr<tcp::socket> connection)
        -> net::awaitable<void>
    {
        while (!stop->load())
        {
            boost::system::error_code ec;
            co_await acceptor->async_accept(*connection, net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                (void)connection_done->try_send(boost::system::error_code{});
                break;
            }
            if (stop->load())
            {
                connection->close();
                (void)connection_done->try_send(boost::system::error_code{});
                break;
            }
            co_await echo_connection(connection, connection_done);
        }
        (void)server_done->try_send(boost::system::error_code{});
    }

    auto make_socket_pair(net::any_io_executor ex) -> net::awaitable<std::pair<tcp::socket, tcp::socket>>
    {
        tcp::acceptor acceptor(ex, tcp::endpoint(net::ip::address_v4::loopback(), 0));
        auto ep = acceptor.local_endpoint();
        tcp::socket client(ex);
        co_await client.async_connect(ep, net::use_awaitable);
        auto server = co_await acceptor.async_accept(net::use_awaitable);
        client.set_option(tcp::no_delay(true));
        server.set_option(tcp::no_delay(true));
        co_return std::make_pair(std::move(client), std::move(server));
    }

    auto async_write_raw(tcp::socket &sock, const std::span<const std::byte> data) -> net::awaitable<void>
    {
        co_await net::async_write(sock, net::buffer(data.data(), data.size()), net::use_awaitable);
    }

    auto async_read_at_least(tcp::socket &sock, std::span<std::byte> buffer, const std::size_t need)
        -> net::awaitable<std::size_t>
    {
        std::size_t total = 0;
        while (total < need && total < buffer.size())
        {
            auto n = co_await sock.async_read_some(net::buffer(buffer.data() + total, buffer.size() - total),
                                                   net::use_awaitable);
            if (n == 0)
            {
                break;
            }
            total += n;
        }
        co_return total;
    }

    /**
 * @brief echo 服务器资源（acceptor + stop 标志，测试末尾统一停止）
 */
    struct echo_harness
    {
        std::shared_ptr<tcp::acceptor> acceptor;
        std::shared_ptr<std::atomic<bool>> stop;
        std::shared_ptr<CompletionChannel> server_done;
        std::shared_ptr<CompletionChannel> connection_done;
        std::shared_ptr<tcp::socket> connection;

        echo_harness(net::any_io_executor ex, std::uint16_t &port)
        {
            acceptor = std::make_shared<tcp::acceptor>(ex, tcp::endpoint(net::ip::address_v4::loopback(), 0));
            port = acceptor->local_endpoint().port();
            stop = std::make_shared<std::atomic<bool>>(false);
            server_done = std::make_shared<CompletionChannel>(ex, 1);
            connection_done = std::make_shared<CompletionChannel>(ex, 1);
            connection = std::make_shared<tcp::socket>(ex);
            net::co_spawn(ex, echo_server(acceptor, stop, server_done, connection_done, connection),
                          net::detached);
        }

        void shutdown()
        {
            stop->store(true);
            boost::system::error_code Ec;
            acceptor->cancel(Ec);
            connection->cancel(Ec);
            connection->close(Ec);
        }

        [[nodiscard]] auto wait_for_connection() -> net::awaitable<void>
        {
            co_await connection_done->async_receive(net::use_awaitable);
        }

        [[nodiscard]] auto wait_for_server() -> net::awaitable<void>
        {
            co_await server_done->async_receive(net::use_awaitable);
        }
    };

    struct LifecycleContext
    {
        net::io_context ioc{1};
        psm::multiplex::config mux_config;
        psm::dns::config dns_cfg;
        std::unique_ptr<psm::connect::dialer> router;
        std::unique_ptr<psm::outbound::direct> outbound;

        LifecycleContext()
        {
            router = std::make_unique<psm::connect::dialer>(
                psm::connect::dialer_options{ioc, dns_cfg});
            outbound = std::make_unique<psm::outbound::direct>(*router);
            mux_config.enabled = true;
            // 测试环境关闭 keepalive：避免 ioc 析构时销毁挂起的 30s timer 协程
            mux_config.smux.keepalive_interval = 0;
        }

        [[nodiscard]] auto Outbound() -> psm::outbound::direct &
        {
            return *outbound;
        }

        void Shutdown()
        {
            outbound.reset();
            router.reset();
        }
    };

    /**
 * @brief 驱动 io_context 直到协程完成，然后清理挂起协程
 * @details 协程完成回调 ioc.stop() 后，restart + run 让所有
 *          已取消/完成的协程恢复并退出；ioc 析构时
 *          不再有挂起协程（规避 Windows 销毁竞态）。
 */
    void run_and_drain(net::io_context &ioc, const std::exception_ptr &ep, bool pass, const char *label,
                       const char *detail)
    {
        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << label << " coroutine exception: " << e.what();
            }
        }
        EXPECT_TRUE(pass) << label << ": " << detail;
        ioc.restart();
        ioc.run();
    }

    // ── 模拟 Clash 快速上行：不等 0x00 状态，SYN+addr+多帧数据连续发送 ──

    TEST(MuxUploadSim, SmuxRapidUplink)
    {
        psm::diagnose::config tcfg;
        tcfg.enable_console = true;
        tcfg.log_level = "debug";
        psm::diagnose::init(tcfg);

        auto ctx = std::make_unique<LifecycleContext>();

        std::exception_ptr ep;
        bool pass = false;

        auto coro = [&]() -> net::awaitable<void>
        {
            auto ex = ctx->ioc.get_executor();

            std::uint16_t echo_port = 0;
            echo_harness echo(ex, echo_port);

            auto [client_sock, server_sock] = co_await make_socket_pair(ex);

            auto server_transport = psm::transport::make_reliable(std::move(server_sock));
            auto session = std::make_shared<smux::control>(
                multiplexer_options{std::move(server_transport), &ctx->Outbound(), ctx->mux_config});
            session->start();

            const std::uint32_t stream_id = 1;

            // Clash 风格：SYN + 地址 PSH + 数据 PSH 连续快速发送（不等服务端状态）
            auto syn_frame = build_smux_header(smux::command::syn, 0, stream_id);
            co_await async_write_raw(client_sock, syn_frame);

            auto address = make_tcp_address(echo_port);
            auto psh_header =
                build_smux_header(smux::command::push, static_cast<std::uint16_t>(address.size()), stream_id);
            std::vector<std::byte> addr_frame;
            addr_frame.insert(addr_frame.end(), psh_header.begin(), psh_header.end());
            addr_frame.insert(addr_frame.end(), address.begin(), address.end());
            co_await async_write_raw(client_sock, addr_frame);

            // 立即发送 8 个数据帧（每帧 1KB），不等连接状态
            constexpr std::size_t chunk = 1024;
            std::array<std::byte, chunk> data{};
            for (std::size_t i = 0; i < data.size(); ++i)
            {
                data[i] = static_cast<std::byte>(i & 0xFF);
            }

            for (int i = 0; i < 8; ++i)
            {
                auto data_header =
                    build_smux_header(smux::command::push, static_cast<std::uint16_t>(chunk), stream_id);
                std::vector<std::byte> data_frame;
                data_frame.insert(data_frame.end(), data_header.begin(), data_header.end());
                data_frame.insert(data_frame.end(), data.begin(), data.end());
                co_await async_write_raw(client_sock, data_frame);
            }

            // 完整帧解析：逐帧读取服务端回传（0x00 状态帧 + echo 数据帧）
            constexpr std::size_t expected = 8 * 1024;
            bool data_match = true;
            std::size_t matched = 0;
            bool status_seen = false;

            while (matched < expected)
            {
                std::array<std::byte, 8> hdr_buf{};
                auto hn = co_await async_read_at_least(client_sock, hdr_buf, 8);
                if (hn < 8)
                {
                    data_match = false;
                    break;
                }
                auto hdr = smux::deserialization(hdr_buf);
                if (!hdr || hdr->stream_id != stream_id)
                {
                    data_match = false;
                    break;
                }
                if (hdr->cmd != smux::command::push || hdr->length == 0)
                {
                    continue;
                }

                std::vector<std::byte> payload(hdr->length);
                auto pn = co_await async_read_at_least(client_sock, payload, hdr->length);
                if (pn < hdr->length)
                {
                    data_match = false;
                    break;
                }

                // 状态帧：length=1 且内容 0x00，仅首帧
                if (!status_seen && hdr->length == 1 && payload[0] == std::byte{0x00})
                {
                    status_seen = true;
                    continue;
                }
                status_seen = true;

                // echo 数据帧：逐字节校验
                for (const auto b : payload)
                {
                    if (matched >= expected)
                    {
                        break;
                    }
                    if (b != data[matched % chunk])
                    {
                        data_match = false;
                        break;
                    }
                    ++matched;
                }
                if (!data_match)
                {
                    break;
                }
            }
            if (matched < expected)
            {
                data_match = false;
            }

            pass = data_match;

            client_sock.close();
            session->close();
            echo.shutdown();
            co_await echo.wait_for_connection();
            co_await echo.wait_for_server();
        };

        net::co_spawn(ctx->ioc, coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ctx->ioc.stop();
                      });
        ctx->ioc.run();

        ctx->Shutdown();
        run_and_drain(ctx->ioc, ep, pass, "SmuxRapidUplink",
                      "smux rapid uplink (no wait for status): echo must be complete");
        ctx.reset();
    }

    // ── 模拟大流量上传：32 帧 × 32KB = 1MB ──

    TEST(MuxUploadSim, SmuxLargeUpload)
    {
        auto ctx = std::make_unique<LifecycleContext>();

        std::exception_ptr ep;
        bool pass = false;

        auto coro = [&]() -> net::awaitable<void>
        {
            auto ex = ctx->ioc.get_executor();

            std::uint16_t echo_port = 0;
            echo_harness echo(ex, echo_port);

            auto [client_sock, server_sock] = co_await make_socket_pair(ex);

            auto server_transport = psm::transport::make_reliable(std::move(server_sock));
            auto session = std::make_shared<smux::control>(
                multiplexer_options{std::move(server_transport), &ctx->Outbound(), ctx->mux_config});
            session->start();

            const std::uint32_t stream_id = 2;

            // SYN + 地址
            auto syn_frame = build_smux_header(smux::command::syn, 0, stream_id);
            co_await async_write_raw(client_sock, syn_frame);

            auto address = make_tcp_address(echo_port);
            auto psh_header =
                build_smux_header(smux::command::push, static_cast<std::uint16_t>(address.size()), stream_id);
            std::vector<std::byte> addr_frame;
            addr_frame.insert(addr_frame.end(), psh_header.begin(), psh_header.end());
            addr_frame.insert(addr_frame.end(), address.begin(), address.end());
            co_await async_write_raw(client_sock, addr_frame);

            // 32 帧 × 32KB = 1MB 上行（smux 帧长度字段 2B，上限 65535）
            constexpr std::size_t chunk = 32768;
            constexpr int frames = 32;
            constexpr std::size_t expected = chunk * frames;
            std::vector<std::byte> data(chunk);
            for (std::size_t i = 0; i < data.size(); ++i)
            {
                data[i] = static_cast<std::byte>(i & 0xFF);
            }

            for (int i = 0; i < frames; ++i)
            {
                auto data_header =
                    build_smux_header(smux::command::push, static_cast<std::uint16_t>(chunk), stream_id);
                std::vector<std::byte> data_frame;
                data_frame.insert(data_frame.end(), data_header.begin(), data_header.end());
                data_frame.insert(data_frame.end(), data.begin(), data.end());
                co_await async_write_raw(client_sock, data_frame);
            }

            // 逐帧解析 echo 回传
            bool data_match = true;
            std::size_t matched = 0;
            bool status_seen = false;

            while (matched < expected)
            {
                std::array<std::byte, 8> hdr_buf{};
                auto hn = co_await async_read_at_least(client_sock, hdr_buf, 8);
                if (hn < 8)
                {
                    data_match = false;
                    break;
                }
                auto hdr = smux::deserialization(hdr_buf);
                if (!hdr || hdr->stream_id != stream_id)
                {
                    data_match = false;
                    break;
                }
                if (hdr->cmd != smux::command::push || hdr->length == 0)
                {
                    continue;
                }

                std::vector<std::byte> payload(hdr->length);
                auto pn = co_await async_read_at_least(client_sock, payload, hdr->length);
                if (pn < hdr->length)
                {
                    data_match = false;
                    break;
                }

                if (!status_seen && hdr->length == 1 && payload[0] == std::byte{0x00})
                {
                    status_seen = true;
                    continue;
                }
                status_seen = true;

                for (const auto b : payload)
                {
                    if (matched >= expected)
                    {
                        break;
                    }
                    if (b != data[matched % chunk])
                    {
                        data_match = false;
                        break;
                    }
                    ++matched;
                }
                if (!data_match)
                {
                    break;
                }
            }
            if (matched < expected)
            {
                data_match = false;
            }

            pass = data_match;

            client_sock.close();
            session->close();
            echo.shutdown();
            co_await echo.wait_for_connection();
            co_await echo.wait_for_server();
        };

        net::co_spawn(ctx->ioc, coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ctx->ioc.stop();
                      });
        ctx->ioc.run();

        ctx->Shutdown();
        run_and_drain(ctx->ioc, ep, pass, "SmuxLargeUpload", "smux 1MB upload echo must be complete");
        ctx.reset();
    }

    // ── 模拟测速站多流并发上传：6 流 × 每流 8MB = 48MB ──

    TEST(MuxUploadSim, SmuxMultiStreamUpload)
    {
        auto ctx = std::make_unique<LifecycleContext>();

        std::exception_ptr ep;
        bool pass = false;

        auto coro = [&]() -> net::awaitable<void>
        {
            auto ex = ctx->ioc.get_executor();

            // 6 个 echo server（每流一个目标端口）
            constexpr int streams = 6;
            std::vector<std::uint16_t> ports;
            std::vector<echo_harness> echoes;
            for (int i = 0; i < streams; ++i)
            {
                std::uint16_t port = 0;
                echoes.emplace_back(ex, port);
                ports.push_back(port);
            }

            auto [client_sock, server_sock] = co_await make_socket_pair(ex);
            auto server_transport = psm::transport::make_reliable(std::move(server_sock));
            auto session = std::make_shared<smux::control>(
                multiplexer_options{std::move(server_transport), &ctx->Outbound(), ctx->mux_config});
            session->start();

            // 6 个流交错建立 + 并发上传
            constexpr std::size_t chunk = 32768;
            constexpr int frames_per_stream = 256; // 8MB 每流
            std::vector<std::byte> data(chunk);
            for (std::size_t i = 0; i < data.size(); ++i)
            {
                data[i] = static_cast<std::byte>(i & 0xFF);
            }

            // 建立所有流（SYN + 地址）
            for (int sid = 0; sid < streams; ++sid)
            {
                const std::uint32_t stream_id = static_cast<std::uint32_t>(sid * 2 + 1);
                auto syn_frame = build_smux_header(smux::command::syn, 0, stream_id);
                co_await async_write_raw(client_sock, syn_frame);

                auto address = make_tcp_address(ports[sid]);
                auto psh_header = build_smux_header(smux::command::push,
                                                    static_cast<std::uint16_t>(address.size()), stream_id);
                std::vector<std::byte> addr_frame;
                addr_frame.insert(addr_frame.end(), psh_header.begin(), psh_header.end());
                addr_frame.insert(addr_frame.end(), address.begin(), address.end());
                co_await async_write_raw(client_sock, addr_frame);
            }

            // 交错上传：轮询每流发一帧（模拟并发）
            for (int f = 0; f < frames_per_stream; ++f)
            {
                for (int sid = 0; sid < streams; ++sid)
                {
                    const std::uint32_t stream_id = static_cast<std::uint32_t>(sid * 2 + 1);
                    auto data_header =
                        build_smux_header(smux::command::push, static_cast<std::uint16_t>(chunk), stream_id);
                    std::vector<std::byte> data_frame;
                    data_frame.insert(data_frame.end(), data_header.begin(), data_header.end());
                    data_frame.insert(data_frame.end(), data.begin(), data.end());
                    co_await async_write_raw(client_sock, data_frame);
                }
            }

            // 校验每流的 echo 回传（回传帧交错到达，按 stream_id 分组累计）
            constexpr std::size_t expected_per_stream = chunk * frames_per_stream;
            std::array<std::size_t, streams> matched{};
            std::array<bool, streams> status_seen{};
            std::size_t total_matched = 0;
            bool all_match = true;

            while (total_matched < expected_per_stream * streams)
            {
                std::array<std::byte, 8> hdr_buf{};
                auto hn = co_await async_read_at_least(client_sock, hdr_buf, 8);
                if (hn < 8)
                {
                    all_match = false;
                    break;
                }
                auto hdr = smux::deserialization(hdr_buf);
                if (!hdr || (hdr->stream_id & 1) == 0 ||
                    hdr->stream_id > static_cast<std::uint32_t>(streams * 2))
                {
                    all_match = false;
                    break;
                }
                if (hdr->cmd != smux::command::push || hdr->length == 0)
                {
                    continue;
                }

                std::vector<std::byte> payload(hdr->length);
                auto pn = co_await async_read_at_least(client_sock, payload, hdr->length);
                if (pn < hdr->length)
                {
                    all_match = false;
                    break;
                }

                const auto sid = static_cast<std::size_t>((hdr->stream_id - 1) / 2);
                if (!status_seen[sid] && hdr->length == 1 && payload[0] == std::byte{0x00})
                {
                    status_seen[sid] = true;
                    continue;
                }
                status_seen[sid] = true;

                for (const auto b : payload)
                {
                    if (matched[sid] >= expected_per_stream)
                    {
                        break;
                    }
                    if (b != data[matched[sid] % chunk])
                    {
                        all_match = false;
                        break;
                    }
                    ++matched[sid];
                    ++total_matched;
                }
                if (!all_match)
                {
                    break;
                }
            }
            for (const auto m : matched)
            {
                if (m < expected_per_stream)
                {
                    all_match = false;
                }
            }

            pass = all_match;

            client_sock.close();
            session->close();
            for (auto &e : echoes)
            {
                e.shutdown();
            }
            for (auto &e : echoes)
            {
                co_await e.wait_for_connection();
                co_await e.wait_for_server();
            }
        };

        net::co_spawn(ctx->ioc, coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ctx->ioc.stop();
                      });
        ctx->ioc.run();

        ctx->Shutdown();
        run_and_drain(ctx->ioc, ep, pass, "SmuxMultiStreamUpload",
                      "smux 6-stream concurrent upload (48MB) echo must be complete");
        ctx.reset();
    }

} // namespace
