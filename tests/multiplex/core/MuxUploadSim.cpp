/**
 * @file MuxUploadSim.cpp
 * @brief 模拟 Clash 客户端上行行为的诊断测试
 * @details 模拟真实客户端测速场景：SYN + 地址帧 + 数据帧连续快速发送
 *          （不等服务端 0x00 状态），大数据量多帧上行，验证 echo 完整回传。
 *          诊断"有下行没上行"问题。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/net/connect/outbound/direct.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/protocol/protocol.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/dns/resolver.hpp>
#include <prism/foundation/fault/code.hpp>

#include <gtest/gtest.h>
#include <prism/trace/config.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace net = boost::asio;
using tcp = net::ip::tcp;

using namespace psm::multiplex;

namespace
{

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

auto echo_server(tcp::acceptor acceptor) -> net::awaitable<void>
{
    while (true)
    {
        auto sock = co_await acceptor.async_accept(net::use_awaitable);
        net::co_spawn(sock.get_executor(),
            [s = std::move(sock)]() mutable -> net::awaitable<void>
            {
                try
                {
                    std::array<std::byte, 8192> buf{};
                    while (true)
                    {
                        auto n = co_await s.async_read_some(net::buffer(buf), net::use_awaitable);
                        if (n == 0)
                            break;
                        co_await net::async_write(s, net::buffer(buf, n), net::use_awaitable);
                    }
                }
                catch (...)
                {
                }
            },
            net::detached);
    }
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
            break;
        total += n;
    }
    co_return total;
}

struct LifecycleContext
{
    net::io_context ioc{1};
    psm::multiplex::config mux_config;
    psm::connect::connection_pool pool{ioc};
    psm::dns::config dns_cfg;
    psm::connect::router router{psm::connect::router_options{pool, ioc, dns_cfg}};
    psm::outbound::direct outbound{router};

    LifecycleContext()
    {
        mux_config.enabled = true;
    }
};

// ── 模拟 Clash 快速上行：不等 0x00 状态，SYN+addr+多帧数据连续发送 ──

TEST(MuxUploadSim, SmuxRapidUplink)
{
    psm::trace::config tcfg;
    tcfg.enable_console = true;
    tcfg.log_level = "debug";
    psm::trace::init(tcfg);

    auto ctx = std::make_unique<LifecycleContext>();

    std::exception_ptr ep;
    bool pass = false;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto ex = ctx->ioc.get_executor();

        tcp::acceptor echo_acceptor(ex, tcp::endpoint(net::ip::address_v4::loopback(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        net::co_spawn(ex, echo_server(std::move(echo_acceptor)), net::detached);

        auto [client_sock, server_sock] = co_await make_socket_pair(ex);

        auto server_transport = psm::transport::make_reliable(std::move(server_sock));
        auto session = std::make_shared<smux::control>(
            multiplexer_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        const std::uint32_t stream_id = 1;

        // Clash 风格：SYN + 地址 PSH + 数据 PSH 连续快速发送（不等服务端状态）
        auto syn_frame = build_smux_header(smux::command::syn, 0, stream_id);
        co_await async_write_raw(client_sock, syn_frame);

        auto address = make_tcp_address(echo_port);
        auto psh_header = build_smux_header(smux::command::push, static_cast<std::uint16_t>(address.size()), stream_id);
        std::vector<std::byte> addr_frame;
        addr_frame.insert(addr_frame.end(), psh_header.begin(), psh_header.end());
        addr_frame.insert(addr_frame.end(), address.begin(), address.end());
        co_await async_write_raw(client_sock, addr_frame);

        // 立即发送 8 个数据帧（每帧 1KB），不等连接状态
        constexpr std::size_t chunk = 1024;
        std::array<std::byte, chunk> data{};
        for (std::size_t i = 0; i < data.size(); ++i)
            data[i] = static_cast<std::byte>(i & 0xFF);

        for (int i = 0; i < 8; ++i)
        {
            auto data_header = build_smux_header(smux::command::push, static_cast<std::uint16_t>(chunk), stream_id);
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
                    break;
                if (b != data[matched % chunk])
                {
                    data_match = false;
                    break;
                }
                ++matched;
            }
            if (!data_match)
                break;
        }
        if (matched < expected)
        {
            data_match = false;
        }

        pass = data_match;

        client_sock.close();
        session->close();
    };

    net::co_spawn(ctx->ioc, coro(), [&](std::exception_ptr e)
                  { ep = e; ctx->ioc.stop(); });
    ctx->ioc.run();

    if (ep)
    {
        try
        {
            std::rethrow_exception(ep);
        }
        catch (const std::exception &e)
        {
            FAIL() << "coroutine exception: " << e.what();
        }
    }

    EXPECT_TRUE(pass) << "smux rapid uplink (no wait for status): echo must be complete";
}

// ── 模拟大流量上传：16 帧 × 64KB = 1MB ──

TEST(MuxUploadSim, SmuxLargeUpload)
{
    auto ctx = std::make_unique<LifecycleContext>();

    std::exception_ptr ep;
    bool pass = false;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto ex = ctx->ioc.get_executor();

        tcp::acceptor echo_acceptor(ex, tcp::endpoint(net::ip::address_v4::loopback(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        net::co_spawn(ex, echo_server(std::move(echo_acceptor)), net::detached);

        auto [client_sock, server_sock] = co_await make_socket_pair(ex);

        auto server_transport = psm::transport::make_reliable(std::move(server_sock));
        auto session = std::make_shared<smux::control>(
            multiplexer_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        const std::uint32_t stream_id = 2;

        // SYN + 地址
        auto syn_frame = build_smux_header(smux::command::syn, 0, stream_id);
        co_await async_write_raw(client_sock, syn_frame);

        auto address = make_tcp_address(echo_port);
        auto psh_header = build_smux_header(smux::command::push, static_cast<std::uint16_t>(address.size()), stream_id);
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
            data[i] = static_cast<std::byte>(i & 0xFF);

        for (int i = 0; i < frames; ++i)
        {
            auto data_header = build_smux_header(smux::command::push, static_cast<std::uint16_t>(chunk), stream_id);
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
                    break;
                if (b != data[matched % chunk])
                {
                    data_match = false;
                    break;
                }
                ++matched;
            }
            if (!data_match)
                break;
        }
        if (matched < expected)
        {
            data_match = false;
        }

        pass = data_match;

        client_sock.close();
        session->close();
    };

    net::co_spawn(ctx->ioc, coro(), [&](std::exception_ptr e)
                  { ep = e; ctx->ioc.stop(); });
    ctx->ioc.run();

    if (ep)
    {
        try
        {
            std::rethrow_exception(ep);
        }
        catch (const std::exception &e)
        {
            FAIL() << "coroutine exception: " << e.what();
        }
    }

    EXPECT_TRUE(pass) << "smux 1MB upload echo must be complete";
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
        std::vector<std::uint16_t> ports;
        for (int i = 0; i < 6; ++i)
        {
            tcp::acceptor acc(ex, tcp::endpoint(net::ip::address_v4::loopback(), 0));
            ports.push_back(acc.local_endpoint().port());
            net::co_spawn(ex, echo_server(std::move(acc)), net::detached);
        }

        auto [client_sock, server_sock] = co_await make_socket_pair(ex);
        auto server_transport = psm::transport::make_reliable(std::move(server_sock));
        auto session = std::make_shared<smux::control>(
            multiplexer_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        // 6 个流交错建立 + 并发上传
        constexpr int streams = 6;
        constexpr std::size_t chunk = 32768;
        constexpr int frames_per_stream = 256;  // 8MB 每流
        std::vector<std::byte> data(chunk);
        for (std::size_t i = 0; i < data.size(); ++i)
            data[i] = static_cast<std::byte>(i & 0xFF);

        // 建立所有流（SYN + 地址）
        for (int sid = 0; sid < streams; ++sid)
        {
            const std::uint32_t stream_id = static_cast<std::uint32_t>(sid * 2 + 1);
            auto syn_frame = build_smux_header(smux::command::syn, 0, stream_id);
            co_await async_write_raw(client_sock, syn_frame);

            auto address = make_tcp_address(ports[sid]);
            auto psh_header = build_smux_header(smux::command::push, static_cast<std::uint16_t>(address.size()), stream_id);
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
                auto data_header = build_smux_header(smux::command::push, static_cast<std::uint16_t>(chunk), stream_id);
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
            if (!hdr || (hdr->stream_id & 1) == 0 || hdr->stream_id > static_cast<std::uint32_t>(streams * 2))
            {
                all_match = false;
                break;
            }
            if (hdr->cmd != smux::command::push || hdr->length == 0)
                continue;

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
                    break;
                if (b != data[matched[sid] % chunk])
                {
                    all_match = false;
                    break;
                }
                ++matched[sid];
                ++total_matched;
            }
            if (!all_match)
                break;
        }
        for (const auto m : matched)
        {
            if (m < expected_per_stream)
                all_match = false;
        }

        pass = all_match;

        client_sock.close();
        session->close();
    };

    net::co_spawn(ctx->ioc, coro(), [&](std::exception_ptr e)
                  { ep = e; ctx->ioc.stop(); });
    ctx->ioc.run();

    if (ep)
    {
        try
        {
            std::rethrow_exception(ep);
        }
        catch (const std::exception &e)
        {
            FAIL() << "coroutine exception: " << e.what();
        }
    }

    EXPECT_TRUE(pass) << "smux 6-stream concurrent upload (48MB) echo must be complete";
}

} // namespace
