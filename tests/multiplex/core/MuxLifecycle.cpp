/**
 * @file MuxLifecycle.cpp
 * @brief 多路复用流生命周期集成测试
 * @details 验证 smux 和 yamux 多路复用协议的完整流生命周期：
 * 1. smux TCP 流完整生命周期（SYN -> 地址数据 -> PSH -> FIN）
 * 2. yamux TCP 流完整生命周期（Data SYN -> 数据 -> FIN）
 * 3. UDP 流生命周期（SYN -> UDP 地址 -> 数据报 -> 关闭）
 * 4. 异常断连后流清理（transport 突然关闭后 core 安全退出）
 * @note 所有 I/O 操作在协程中完成，使用 socket pair 连接
 * server-side craft session 与模拟客户端
 */

#include <prism/foundation/foundation.hpp>
#include <prism/instance/outbound/direct.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/proto/proto.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/resolve/dns/dns.hpp>
#include <prism/foundation/fault/code.hpp>

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string_view>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace net = boost::asio;
using tcp = net::ip::tcp;

using namespace psm::multiplex;

// ── 帧辅助函数 ──

namespace
{

/**
 * @brief 构建 smux 帧头（小端序）
 */
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

/**
 * @brief 构建 yamux 帧头（大端序）
 */
[[nodiscard]] auto build_yamux_header(const yamux::message_type type, const yamux::flags flag,
                                      const std::uint32_t stream_id,
                                      const std::uint32_t length) -> std::array<std::byte, 12>
{
    yamux::frame_header hdr{};
    hdr.version = yamux::protocol_version;
    hdr.type = type;
    hdr.flag = flag;
    hdr.stream_id = stream_id;
    hdr.length = length;
    return yamux::build_header(hdr);
}

/**
 * @brief 构建指向 127.0.0.1:port 的 SOCKS5 TCP 地址（sing-mux StreamRequest 格式）
 */
[[nodiscard]] auto make_tcp_address(const std::uint16_t port) -> std::vector<std::byte>
{
    std::vector<std::byte> buf;
    buf.push_back(std::byte{0x00}); // flags high
    buf.push_back(std::byte{0x00}); // flags low: TCP
    buf.push_back(std::byte{0x01}); // ATYP IPv4
    buf.push_back(std::byte{127});
    buf.push_back(std::byte{0});
    buf.push_back(std::byte{0});
    buf.push_back(std::byte{1}); // 127.0.0.1
    buf.push_back(std::byte{static_cast<unsigned char>((port >> 8) & 0xFF)});
    buf.push_back(std::byte{static_cast<unsigned char>(port & 0xFF)});
    return buf;
}

/**
 * @brief 构建指向 127.0.0.1:port 的 SOCKS5 UDP 地址
 */
[[nodiscard]] auto make_udp_address(const std::uint16_t port) -> std::vector<std::byte>
{
    std::vector<std::byte> buf;
    buf.push_back(std::byte{0x00}); // flags high
    buf.push_back(std::byte{0x01}); // flags low: is_udp=true
    buf.push_back(std::byte{0x01}); // ATYP IPv4
    buf.push_back(std::byte{127});
    buf.push_back(std::byte{0});
    buf.push_back(std::byte{0});
    buf.push_back(std::byte{1}); // 127.0.0.1
    buf.push_back(std::byte{static_cast<unsigned char>((port >> 8) & 0xFF)});
    buf.push_back(std::byte{static_cast<unsigned char>(port & 0xFF)});
    return buf;
}

/**
 * @brief 构建 SOCKS5 UDP relay 数据报
 */
[[nodiscard]] auto make_udp_datagram(const std::uint16_t port,
                                     const std::span<const std::byte> payload) -> std::vector<std::byte>
{
    std::vector<std::byte> buf;
    buf.push_back(std::byte{0x01}); // ATYP IPv4
    buf.push_back(std::byte{127});
    buf.push_back(std::byte{0});
    buf.push_back(std::byte{0});
    buf.push_back(std::byte{1}); // 127.0.0.1
    buf.push_back(std::byte{static_cast<unsigned char>((port >> 8) & 0xFF)});
    buf.push_back(std::byte{static_cast<unsigned char>(port & 0xFF)});
    buf.insert(buf.end(), payload.begin(), payload.end());
    return buf;
}

// ── echo server 协程 ──

/**
 * @brief TCP echo server 协程，接受一个连接后原样回传
 */
auto echo_server(tcp::acceptor acceptor) -> net::awaitable<void>
{
    boost::system::error_code ec;
    auto token = net::redirect_error(net::use_awaitable, ec);
    auto socket = co_await acceptor.async_accept(token);
    if (ec)
    {
        co_return;
    }

    std::array<char, 8192> buf{};
    while (true)
    {
        boost::system::error_code read_ec;
        auto read_token = net::redirect_error(net::use_awaitable, read_ec);
        const auto n = co_await socket.async_read_some(net::buffer(buf), read_token);
        if (read_ec || n == 0)
        {
            break;
        }
        boost::system::error_code write_ec;
        auto write_token = net::redirect_error(net::use_awaitable, write_ec);
        co_await net::async_write(socket, net::buffer(buf.data(), n), write_token);
        if (write_ec)
        {
            break;
        }
    }
}

// ── 辅助：通过 localhost 创建已连接的 socket pair ──

auto make_socket_pair(net::any_io_executor ex) -> net::awaitable<std::pair<tcp::socket, tcp::socket>>
{
    tcp::acceptor acceptor(ex, tcp::endpoint(net::ip::address_v4::loopback(), 0));
    auto client_socket = tcp::socket(ex);
    co_await client_socket.async_connect(acceptor.local_endpoint(), net::use_awaitable);
    auto server_socket = co_await acceptor.async_accept(net::use_awaitable);
    co_return std::make_pair(std::move(client_socket), std::move(server_socket));
}

// ── 辅助：异步写入原始字节 ──

auto async_write_raw(tcp::socket &sock, const std::span<const std::byte> data) -> net::awaitable<void>
{
    boost::system::error_code ec;
    co_await net::async_write(sock, net::buffer(data.data(), data.size()),
                              net::redirect_error(net::use_awaitable, ec));
}

// ── 辅助：异步读取至少 min_bytes 字节 ──

auto async_read_at_least(tcp::socket &sock, std::span<std::byte> buffer,
                         const std::size_t min_bytes) -> net::awaitable<std::size_t>
{
    boost::system::error_code ec;
    auto n = co_await net::async_read(sock, net::mutable_buffer(buffer.data(), buffer.size()),
                                      net::transfer_at_least(min_bytes),
                                      net::redirect_error(net::use_awaitable, ec));
    if (ec)
    {
        co_return 0;
    }
    co_return n;
}

// ── 辅助：异步等待 ──

auto async_wait(net::any_io_executor ex, const std::chrono::milliseconds dur) -> net::awaitable<void>
{
    net::steady_timer timer(ex);
    timer.expires_after(dur);
    boost::system::error_code ec;
    co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
}

// ── 辅助：等待 session 变为非活跃 ──

auto wait_for_inactive(const std::shared_ptr<core> &session, net::any_io_executor ex,
                       const std::chrono::milliseconds timeout = std::chrono::milliseconds(500))
    -> net::awaitable<void>
{
    // 轮询等待 session 变为非活跃状态，或超时
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (session->is_active() && std::chrono::steady_clock::now() < deadline)
    {
        net::steady_timer timer(ex);
        timer.expires_after(std::chrono::milliseconds(10));
        boost::system::error_code ec;
        co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
    }
}

// ── 测试基础设施工厂 ──

struct LifecycleContext
{
    net::io_context ioc;
    psm::connect::connection_pool pool;
    psm::connect::router router;
    psm::outbound::direct outbound;
    psm::multiplex::config mux_config;

    LifecycleContext()
        : pool(ioc),
          router({pool, ioc, psm::resolve::dns::config{}}),
          outbound(router)
    {
        mux_config.smux.keepalive_interval = 0;
        mux_config.yamux.enable_ping = false;
        mux_config.yamux.ping_interval = 0;
        mux_config.yamux.open_timeout = 0;
    }
};

} // namespace

// ── Test 1: smux TCP 流完整生命周期 ──

TEST(MuxLifecycle, SmuxTcpLifecycle)
{
    auto ctx = std::make_unique<LifecycleContext>();

    std::exception_ptr ep;
    bool pass = false;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto ex = ctx->ioc.get_executor();

        // 启动 echo server
        tcp::acceptor echo_acceptor(ex, tcp::endpoint(net::ip::address_v4::loopback(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        net::co_spawn(ex, echo_server(std::move(echo_acceptor)), net::detached);

        auto [client_sock, server_sock] = co_await make_socket_pair(ex);

        // 创建 smux 服务端 session
        auto server_transport = psm::transport::make_reliable(std::move(server_sock));
        auto session = std::make_shared<smux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        const std::uint32_t stream_id = 1;
        auto syn_frame = build_smux_header(smux::command::syn, 0, stream_id);
        co_await async_write_raw(client_sock, syn_frame);

        // PSH 携带 TCP 目标地址
        auto address = make_tcp_address(echo_port);
        auto psh_header = build_smux_header(smux::command::push, static_cast<std::uint16_t>(address.size()), stream_id);
        std::vector<std::byte> addr_frame;
        addr_frame.insert(addr_frame.end(), psh_header.begin(), psh_header.end());
        addr_frame.insert(addr_frame.end(), address.begin(), address.end());
        co_await async_write_raw(client_sock, addr_frame);

        // 读取服务端返回的连接状态（帧头 8 字节 + 状态 1 字节）
        std::array<std::byte, 4096> read_buf{};
        auto n = co_await async_read_at_least(client_sock, read_buf, 9);
        if (n < 9)
        {
            co_return;
        }

        auto hdr = smux::deserialization(read_buf);
        if (!hdr || hdr->cmd != smux::command::push || hdr->stream_id != stream_id)
        {
            co_return;
        }
        if (read_buf[8] != std::byte{0x00})
        {
            co_return;
        }

        // 发送测试数据
        const char test_data[] = "Hello smux lifecycle!";
        const auto test_len = static_cast<std::uint16_t>(std::strlen(test_data));
        auto data_header = build_smux_header(smux::command::push, test_len, stream_id);
        std::vector<std::byte> data_frame;
        data_frame.insert(data_frame.end(), data_header.begin(), data_header.end());
        for (std::size_t i = 0; i < test_len; ++i)
        {
            data_frame.push_back(static_cast<std::byte>(test_data[i]));
        }
        co_await async_write_raw(client_sock, data_frame);

        // 读取 echo 回传
        std::array<std::byte, 8192> echo_buf{};
        n = co_await async_read_at_least(client_sock, echo_buf, 8 + test_len);
        if (n < 8 + test_len)
        {
            co_return;
        }

        auto echo_hdr = smux::deserialization(echo_buf);
        if (!echo_hdr || echo_hdr->cmd != smux::command::push || echo_hdr->stream_id != stream_id)
        {
            co_return;
        }

        bool data_match = true;
        for (std::size_t i = 0; i < test_len; ++i)
        {
            if (echo_buf[8 + i] != static_cast<std::byte>(test_data[i]))
            {
                data_match = false;
                break;
            }
        }

        pass = data_match;

        // FIN 关闭流
        auto fin_frame = build_smux_header(smux::command::fin, 0, stream_id);
        co_await async_write_raw(client_sock, fin_frame);

        // 关闭 client socket 让服务端 frame_loop 感知 EOF
        client_sock.close();

        // 等待 session 自然退出
        co_await wait_for_inactive(session, ex);
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

    EXPECT_TRUE(pass) << "smux TCP stream lifecycle (SYN/PSH/FIN)";
}

// ── Test 2: yamux TCP 流完整生命周期 ──

TEST(MuxLifecycle, YamuxTcpLifecycle)
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
        auto session = std::make_shared<yamux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        const std::uint32_t stream_id = 1;

        auto address = make_tcp_address(echo_port);
        auto data_syn = yamux::build_syn(stream_id, address);
        std::vector<std::byte> syn_frame;
        syn_frame.insert(syn_frame.end(), data_syn.header.begin(), data_syn.header.end());
        syn_frame.insert(syn_frame.end(), data_syn.payload.begin(), data_syn.payload.end());
        co_await async_write_raw(client_sock, syn_frame);

        // 读取响应：WindowUpdate ACK + 连接状态 Data 帧
        std::array<std::byte, 4096> read_buf{};
        auto n = co_await async_read_at_least(client_sock, read_buf, 12);

        auto wu_ack = yamux::parse_header(read_buf);
        if (!wu_ack || wu_ack->type != yamux::message_type::window_update ||
            !yamux::has_flag(wu_ack->flag, yamux::flags::ack))
        {
            co_return;
        }

        // 查找连接状态 Data 帧
        bool connect_ok = false;
        if (n >= 25) // 12 (WU ACK) + 12 (Data header) + 1 (status)
        {
            auto st = yamux::parse_header(std::span<const std::byte>{read_buf.data() + 12, 12});
            if (st && st->type == yamux::message_type::data && st->length >= 1)
            {
                connect_ok = (read_buf[24] == std::byte{0x00});
            }
        }

        if (!connect_ok)
        {
            std::array<std::byte, 256> extra{};
            auto extra_n = co_await async_read_at_least(client_sock, extra, 13);
            if (extra_n >= 13)
            {
                auto st = yamux::parse_header(extra);
                if (st && st->type == yamux::message_type::data && st->length >= 1)
                {
                    connect_ok = (extra[12] == std::byte{0x00});
                }
            }
        }

        if (!connect_ok)
        {
            co_return;
        }

        // 发送测试数据
        const char test_data[] = "Hello yamux lifecycle!";
        const auto test_len = static_cast<std::uint32_t>(std::strlen(test_data));
        std::vector<std::byte> payload;
        for (std::size_t i = 0; i < test_len; ++i)
        {
            payload.push_back(static_cast<std::byte>(test_data[i]));
        }
        auto data_frame = yamux::build_data(yamux::flags::none, stream_id, payload);
        std::vector<std::byte> send_buf;
        send_buf.insert(send_buf.end(), data_frame.header.begin(), data_frame.header.end());
        send_buf.insert(send_buf.end(), data_frame.payload.begin(), data_frame.payload.end());
        co_await async_write_raw(client_sock, send_buf);

        // 读取 echo 回传
        std::array<std::byte, 8192> echo_buf{};
        n = co_await async_read_at_least(client_sock, echo_buf, 12);
        if (n < 12)
        {
            co_return;
        }

        // 在响应中查找 Data 帧
        bool echo_ok = false;
        std::size_t search_off = 0;
        while (search_off + 12 <= n)
        {
            auto resp = yamux::parse_header(std::span<const std::byte>{echo_buf.data() + search_off, 12});
            if (!resp)
            {
                break;
            }
            if (resp->type == yamux::message_type::data && resp->stream_id == stream_id)
            {
                const auto data_start = search_off + 12;
                const auto data_len = std::min(static_cast<std::size_t>(resp->length), n - data_start);
                if (data_len == test_len)
                {
                    echo_ok = true;
                    for (std::size_t i = 0; i < data_len; ++i)
                    {
                        if (echo_buf[data_start + i] != static_cast<std::byte>(test_data[i]))
                        {
                            echo_ok = false;
                            break;
                        }
                    }
                }
                break;
            }
            const auto frame_payload = (resp->type == yamux::message_type::data) ? resp->length : 0;
            search_off += 12 + frame_payload;
        }

        pass = echo_ok;

        // FIN 关闭流
        auto fin_hdr = yamux::build_fin(stream_id);
        co_await async_write_raw(client_sock, fin_hdr);

        // 关闭 client socket 让服务端 frame_loop 感知 EOF
        client_sock.close();

        // 等待 session 自然退出
        co_await wait_for_inactive(session, ex);
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

    EXPECT_TRUE(pass) << "yamux TCP stream lifecycle (Data SYN/FIN)";
}

// ── Test 3: UDP 流生命周期 ──

TEST(MuxLifecycle, SmuxUdpLifecycle)
{
    auto ctx = std::make_unique<LifecycleContext>();

    std::exception_ptr ep;
    bool pass = false;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto ex = ctx->ioc.get_executor();

        auto [client_sock, server_sock] = co_await make_socket_pair(ex);

        auto server_transport = psm::transport::make_reliable(std::move(server_sock));
        auto session = std::make_shared<smux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        const std::uint32_t stream_id = 2;
        auto syn_frame = build_smux_header(smux::command::syn, 0, stream_id);
        co_await async_write_raw(client_sock, syn_frame);

        auto address = make_udp_address(53);
        auto psh_header = build_smux_header(smux::command::push, static_cast<std::uint16_t>(address.size()), stream_id);
        std::vector<std::byte> addr_frame;
        addr_frame.insert(addr_frame.end(), psh_header.begin(), psh_header.end());
        addr_frame.insert(addr_frame.end(), address.begin(), address.end());
        co_await async_write_raw(client_sock, addr_frame);

        std::array<std::byte, 4096> read_buf{};
        auto n = co_await async_read_at_least(client_sock, read_buf, 9);
        bool status_ok = false;
        if (n >= 9)
        {
            auto hdr = smux::deserialization(read_buf);
            if (hdr && hdr->cmd == smux::command::push && hdr->stream_id == stream_id && read_buf[8] == std::byte{0x00})
            {
                status_ok = true;
            }
        }

        // 发送 UDP 数据报
        const std::byte udp_payload[] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
        auto udp_dg = make_udp_datagram(53, udp_payload);
        auto dg_header = build_smux_header(smux::command::push, static_cast<std::uint16_t>(udp_dg.size()), stream_id);
        std::vector<std::byte> dg_frame;
        dg_frame.insert(dg_frame.end(), dg_header.begin(), dg_header.end());
        dg_frame.insert(dg_frame.end(), udp_dg.begin(), udp_dg.end());
        co_await async_write_raw(client_sock, dg_frame);

        co_await async_wait(ex, std::chrono::milliseconds(100));

        pass = status_ok;

        auto fin_frame = build_smux_header(smux::command::fin, 0, stream_id);
        co_await async_write_raw(client_sock, fin_frame);

        client_sock.close();

        co_await wait_for_inactive(session, ex);
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

    EXPECT_TRUE(pass) << "smux UDP stream lifecycle";
}

// ── Test 4: smux 异常断连 ──

TEST(MuxLifecycle, SmuxAbruptDisconnect)
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
        auto session = std::make_shared<smux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        const std::uint32_t stream_id = 1;
        auto syn = build_smux_header(smux::command::syn, 0, stream_id);
        co_await async_write_raw(client_sock, syn);

        auto address = make_tcp_address(echo_port);
        auto psh = build_smux_header(smux::command::push, static_cast<std::uint16_t>(address.size()), stream_id);
        std::vector<std::byte> frame;
        frame.insert(frame.end(), psh.begin(), psh.end());
        frame.insert(frame.end(), address.begin(), address.end());
        co_await async_write_raw(client_sock, frame);

        // 等待并读取状态
        std::array<std::byte, 4096> read_buf{};
        co_await async_read_at_least(client_sock, read_buf, 1);

        // 突然关闭
        client_sock.close();

        // 等待 session 因传输层关闭而变为非活跃
        co_await wait_for_inactive(session, ex);

        bool inactive = !session->is_active();

        // 幂等 close
        session->close();
        session->close();

        pass = inactive;
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

    EXPECT_TRUE(pass) << "smux abrupt disconnect cleanup";
}

// ── Test 5: yamux 异常断连 ──

TEST(MuxLifecycle, YamuxAbruptDisconnect)
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
        auto session = std::make_shared<yamux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        const std::uint32_t stream_id = 1;

        auto address = make_tcp_address(echo_port);
        auto data_syn = yamux::build_syn(stream_id, address);
        std::vector<std::byte> syn_frame;
        syn_frame.insert(syn_frame.end(), data_syn.header.begin(), data_syn.header.end());
        syn_frame.insert(syn_frame.end(), data_syn.payload.begin(), data_syn.payload.end());
        co_await async_write_raw(client_sock, syn_frame);

        std::array<std::byte, 4096> read_buf{};
        co_await async_read_at_least(client_sock, read_buf, 1);

        client_sock.close();

        // 等待 session 因传输层关闭而变为非活跃
        co_await wait_for_inactive(session, ex);

        bool inactive = !session->is_active();
        session->close();
        session->close();

        pass = inactive;
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

    EXPECT_TRUE(pass) << "yamux abrupt disconnect cleanup";
}

// ── Test 6: smux 多流并发 ──

TEST(MuxLifecycle, SmuxMultiStream)
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

        tcp::acceptor echo_acceptor2(ex, tcp::endpoint(net::ip::address_v4::loopback(), 0));
        const auto echo_port2 = echo_acceptor2.local_endpoint().port();
        net::co_spawn(ex, echo_server(std::move(echo_acceptor2)), net::detached);

        auto [client_sock, server_sock] = co_await make_socket_pair(ex);

        auto server_transport = psm::transport::make_reliable(std::move(server_sock));
        auto session = std::make_shared<smux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        for (std::uint32_t sid = 1; sid <= 2; ++sid)
        {
            const auto port = (sid == 1) ? echo_port : echo_port2;
            auto syn = build_smux_header(smux::command::syn, 0, sid);
            co_await async_write_raw(client_sock, syn);

            auto addr = make_tcp_address(port);
            auto psh = build_smux_header(smux::command::push, static_cast<std::uint16_t>(addr.size()), sid);
            std::vector<std::byte> frame;
            frame.insert(frame.end(), psh.begin(), psh.end());
            frame.insert(frame.end(), addr.begin(), addr.end());
            co_await async_write_raw(client_sock, frame);
        }

        std::array<std::byte, 4096> read_buf{};
        auto n = co_await async_read_at_least(client_sock, read_buf, 18);
        bool responses_ok = (n >= 18);

        for (std::uint32_t sid = 1; sid <= 2; ++sid)
        {
            const char msg[] = "Stream";
            const auto len = static_cast<std::uint16_t>(std::strlen(msg));
            auto hdr = build_smux_header(smux::command::push, len, sid);
            std::vector<std::byte> frame;
            frame.insert(frame.end(), hdr.begin(), hdr.end());
            for (std::size_t i = 0; i < len; ++i)
            {
                frame.push_back(static_cast<std::byte>(msg[i]));
            }
            co_await async_write_raw(client_sock, frame);
        }

        co_await async_wait(ex, std::chrono::milliseconds(200));

        pass = responses_ok;

        for (std::uint32_t sid = 1; sid <= 2; ++sid)
        {
            auto fin = build_smux_header(smux::command::fin, 0, sid);
            co_await async_write_raw(client_sock, fin);
        }

        client_sock.close();

        co_await wait_for_inactive(session, ex);
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

    EXPECT_TRUE(pass) << "smux multi-stream concurrent";
}

// ── Test 7: yamux RST 重置流 ──

TEST(MuxLifecycle, YamuxRstStream)
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
        auto session = std::make_shared<yamux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        const std::uint32_t stream_id = 5;

        auto address = make_tcp_address(echo_port);
        auto data_syn = yamux::build_syn(stream_id, address);
        std::vector<std::byte> syn_frame;
        syn_frame.insert(syn_frame.end(), data_syn.header.begin(), data_syn.header.end());
        syn_frame.insert(syn_frame.end(), data_syn.payload.begin(), data_syn.payload.end());
        co_await async_write_raw(client_sock, syn_frame);

        std::array<std::byte, 4096> read_buf{};
        co_await async_read_at_least(client_sock, read_buf, 1);

        // RST 重置流
        auto rst = build_yamux_header(yamux::message_type::data, yamux::flags::rst, stream_id, 0);
        co_await async_write_raw(client_sock, rst);

        co_await async_wait(ex, std::chrono::milliseconds(100));

        bool still_active = session->is_active();

        pass = still_active;

        client_sock.close();

        co_await wait_for_inactive(session, ex);
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

    EXPECT_TRUE(pass) << "yamux RST stream reset";
}

// ── Test 8: yamux GoAway ──

TEST(MuxLifecycle, YamuxGoAway)
{
    auto ctx = std::make_unique<LifecycleContext>();

    std::exception_ptr ep;
    bool pass = false;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto ex = ctx->ioc.get_executor();

        auto [client_sock, server_sock] = co_await make_socket_pair(ex);

        auto server_transport = psm::transport::make_reliable(std::move(server_sock));
        auto session = std::make_shared<yamux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        auto go_away = yamux::build_goaway(yamux::away_code::protocol_error);
        co_await async_write_raw(client_sock, go_away);

        // 等待 session 处理 GoAway 并关闭
        co_await wait_for_inactive(session, ex);

        bool closed = !session->is_active();
        client_sock.close();

        pass = closed;
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

    EXPECT_TRUE(pass) << "yamux GoAway session close";
}
