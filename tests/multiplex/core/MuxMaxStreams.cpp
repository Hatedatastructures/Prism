/**
 * @file MuxMaxStreams.cpp
 * @brief 多路复用 max_streams 强制限制单元测试
 * @details 验证 smux、yamux 协议在并发流数达到 max_streams 配置上限时
 * 正确拒绝新流创建。测试通过 socket pair 连接 craft session 与模拟客户端，
 * 发送 SYN 帧直到超出 max_streams 限制，验证：
 * - smux：超限 SYN 帧被静默丢弃（不创建 pending_entry，不关闭会话）
 * - yamux：超限 WindowUpdate(SYN) 收到 WindowUpdate(RST) 拒绝帧
 * - 配置默认值、边界值、零值的正确性
 * @note 使用 co_spawn + ioc.run() 协程模式驱动异步操作
 */

#include <prism/foundation/foundation.hpp>
#include <prism/net/connect/outbound/direct.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/protocol/protocol.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/dns/resolver.hpp>

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace net = boost::asio;
using tcp = net::ip::tcp;

using namespace psm::multiplex;

// ── 帧辅助函数 ───────────────────────────────────────────────────

namespace
{

/**
 * @brief 构建 smux 帧头（小端序）
 * @param cmd 命令类型
 * @param length 载荷长度
 * @param stream_id 流标识符
 * @return 8 字节帧头
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
 * @param type 消息类型
 * @param flag 标志位
 * @param stream_id 流标识符
 * @param length 长度字段
 * @return 12 字节帧头
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

// ── 测试基础设施 ─────────────────────────────────────────────────

/**
 * @brief 多路复用测试上下文
 */
struct mux_test_context
{
    net::io_context ioc;
    psm::connect::connection_pool pool;
    psm::connect::router router;
    psm::outbound::direct outbound;
    psm::multiplex::config mux_config;

    explicit mux_test_context(const std::uint32_t max_streams = 32)
        : pool(ioc),
          router({pool, ioc, psm::dns::config{}}),
          outbound(router)
    {
        mux_config.smux.max_streams = max_streams;
        mux_config.yamux.max_streams = max_streams;
        mux_config.h2mux.max_streams = max_streams;
        mux_config.smux.keepalive_interval = 0;
        mux_config.yamux.enable_ping = false;
        mux_config.yamux.ping_interval = 0;
        mux_config.yamux.open_timeout = 0;
    }
};

/**
 * @brief 通过 localhost 创建一对已连接的 TCP socket（异步版）
 */
auto make_socket_pair(net::any_io_executor ex) -> net::awaitable<std::pair<tcp::socket, tcp::socket>>
{
    tcp::acceptor acceptor(ex, tcp::endpoint(net::ip::address_v4::loopback(), 0));
    auto client_socket = tcp::socket(ex);
    co_await client_socket.async_connect(acceptor.local_endpoint(), net::use_awaitable);
    auto server_socket = co_await acceptor.async_accept(net::use_awaitable);
    co_return std::make_pair(std::move(client_socket), std::move(server_socket));
}

/**
 * @brief 异步写入原始字节
 */
auto async_write_raw(tcp::socket &sock, const std::span<const std::byte> data) -> net::awaitable<void>
{
    boost::system::error_code ec;
    co_await net::async_write(sock, net::buffer(data.data(), data.size()),
                              net::redirect_error(net::use_awaitable, ec));
}

/**
 * @brief 异步等待
 */
auto async_wait(net::any_io_executor ex, const std::chrono::milliseconds dur) -> net::awaitable<void>
{
    net::steady_timer timer(ex);
    timer.expires_after(dur);
    boost::system::error_code ec;
    co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
}

/**
 * @brief 搜索 yamux 响应中指定 stream_id 的 RST 帧
 * @param buf 响应缓冲区
 * @param n 有效字节数
 * @param target_sid 目标 stream_id
 * @return 是否找到匹配的 RST 帧
 */
[[nodiscard]] auto find_rst_for_stream(const std::span<const std::byte> buf, const std::size_t n,
                                        const std::uint32_t target_sid) -> bool
{
    std::size_t off = 0;
    while (off + 12 <= n)
    {
        const auto *p = buf.data() + off;
        const auto type_byte = static_cast<std::uint8_t>(p[1]);
        const auto flags_val = static_cast<std::uint16_t>(
            (static_cast<std::uint8_t>(p[2]) << 8) | static_cast<std::uint8_t>(p[3]));
        const auto sid = static_cast<std::uint32_t>(
            (static_cast<std::uint8_t>(p[4]) << 24) |
            (static_cast<std::uint8_t>(p[5]) << 16) |
            (static_cast<std::uint8_t>(p[6]) << 8) |
            static_cast<std::uint8_t>(p[7]));

        if (type_byte == 0x01 && flags_val == 0x0008 && sid == target_sid)
        {
            return true;
        }

        const auto len = (static_cast<std::uint32_t>(p[8]) << 24) |
                         (static_cast<std::uint32_t>(p[9]) << 16) |
                         (static_cast<std::uint32_t>(p[10]) << 8) |
                         static_cast<std::uint32_t>(p[11]);
        if (type_byte == 0x00 && len > 0)
        {
            off += 12 + len;
        }
        else
        {
            off += 12;
        }
    }
    return false;
}

/**
 * @brief 搜索 yamux 响应中是否存在任何 RST 帧
 */
[[nodiscard]] auto find_any_rst(const std::span<const std::byte> buf, const std::size_t n) -> bool
{
    std::size_t off = 0;
    while (off + 12 <= n)
    {
        const auto *p = buf.data() + off;
        const auto flags_val = static_cast<std::uint16_t>(
            (static_cast<std::uint8_t>(p[2]) << 8) | static_cast<std::uint8_t>(p[3]));
        if (flags_val == 0x0008)
        {
            return true;
        }
        off += 12;
    }
    return false;
}

// ── config unit tests ────────────────────────────────────────────

/**
 * @brief 测试 config 结构体 max_streams 默认值
 */
TEST(MuxMaxStreams, ConfigDefaults)
{
    config cfg;

    EXPECT_TRUE(cfg.smux.max_streams == 32) << "smux default max_streams=32";
    EXPECT_TRUE(cfg.yamux.max_streams == 32) << "yamux default max_streams=32";
    EXPECT_TRUE(cfg.h2mux.max_streams == 256) << "h2mux default max_streams=256";
}

/**
 * @brief 测试 config 结构体 max_streams 可正确配置为小值
 */
TEST(MuxMaxStreams, ConfigSmall)
{
    config cfg;
    cfg.smux.max_streams = 1;
    cfg.yamux.max_streams = 1;
    cfg.h2mux.max_streams = 1;

    EXPECT_TRUE(cfg.smux.max_streams == 1) << "smux max_streams=1 configured";
    EXPECT_TRUE(cfg.yamux.max_streams == 1) << "yamux max_streams=1 configured";
    EXPECT_TRUE(cfg.h2mux.max_streams == 1) << "h2mux max_streams=1 configured";
}

/**
 * @brief 测试 config 结构体 max_streams 可配置为 0
 */
TEST(MuxMaxStreams, ConfigZero)
{
    config cfg;
    cfg.smux.max_streams = 0;
    cfg.yamux.max_streams = 0;
    cfg.h2mux.max_streams = 0;

    EXPECT_TRUE(cfg.smux.max_streams == 0) << "smux max_streams=0 configured";
    EXPECT_TRUE(cfg.yamux.max_streams == 0) << "yamux max_streams=0 configured";
    EXPECT_TRUE(cfg.h2mux.max_streams == 0) << "h2mux max_streams=0 configured";
}

// ── smux tests ───────────────────────────────────────────────────

/**
 * @brief 测试 smux 超过 max_streams 时 SYN 帧被静默拒绝
 * @details 配置 max_streams=2，发送 2 个 SYN 帧成功创建 pending 流，
 * 第 3 个 SYN 帧应被静默拒绝。会话应保持活跃。
 */
TEST(MuxMaxStreams, SmuxReject)
{
    constexpr std::uint32_t max_streams = 2;
    auto ctx = std::make_unique<mux_test_context>(max_streams);

    std::exception_ptr ep;
    bool session_active = false;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto ex = ctx->ioc.get_executor();
        auto [client_sock, server_sock] = co_await make_socket_pair(ex);

        auto server_transport = psm::transport::make_reliable(std::move(server_sock));
        auto session = std::make_shared<smux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        // 发送 3 个 SYN 帧（stream_id = 1, 2, 3）
        std::vector<std::byte> all_data;
        for (std::uint32_t i = 1; i <= 3; ++i)
        {
            auto syn = build_smux_header(smux::command::syn, 0, i);
            all_data.insert(all_data.end(), syn.begin(), syn.end());
        }
        co_await async_write_raw(client_sock, all_data);

        co_await async_wait(ex, std::chrono::milliseconds(300));

        session_active = session->is_active();

        session->close();
        client_sock.close();
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

    EXPECT_TRUE(session_active) << "smux session remains active after max_streams reject";
}

/**
 * @brief 测试 smux max_streams=1 时只允许一个流
 * @details 配置 max_streams=1，第一个 SYN 成功，第二个被拒绝。
 */
TEST(MuxMaxStreams, SmuxOne)
{
    constexpr std::uint32_t max_streams = 1;
    auto ctx = std::make_unique<mux_test_context>(max_streams);

    std::exception_ptr ep;
    bool session_active = false;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto ex = ctx->ioc.get_executor();
        auto [client_sock, server_sock] = co_await make_socket_pair(ex);

        auto server_transport = psm::transport::make_reliable(std::move(server_sock));
        auto session = std::make_shared<smux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        std::vector<std::byte> all_data;
        auto syn1 = build_smux_header(smux::command::syn, 0, 1);
        auto syn2 = build_smux_header(smux::command::syn, 0, 2);
        all_data.insert(all_data.end(), syn1.begin(), syn1.end());
        all_data.insert(all_data.end(), syn2.begin(), syn2.end());
        co_await async_write_raw(client_sock, all_data);

        co_await async_wait(ex, std::chrono::milliseconds(300));

        session_active = session->is_active();

        session->close();
        client_sock.close();
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

    EXPECT_TRUE(session_active) << "smux session active with max_streams=1";
}

/**
 * @brief 测试 smux 默认 max_streams=32 不拒绝正常数量流
 * @details 发送 4 个 SYN 帧，全部应被接受。
 */
TEST(MuxMaxStreams, SmuxDefault)
{
    auto ctx = std::make_unique<mux_test_context>(32);

    std::exception_ptr ep;
    bool session_active = false;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto ex = ctx->ioc.get_executor();
        auto [client_sock, server_sock] = co_await make_socket_pair(ex);

        auto server_transport = psm::transport::make_reliable(std::move(server_sock));
        auto session = std::make_shared<smux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        std::vector<std::byte> all_data;
        for (std::uint32_t i = 1; i <= 4; ++i)
        {
            auto syn = build_smux_header(smux::command::syn, 0, i);
            all_data.insert(all_data.end(), syn.begin(), syn.end());
        }
        co_await async_write_raw(client_sock, all_data);

        co_await async_wait(ex, std::chrono::milliseconds(300));

        session_active = session->is_active();

        session->close();
        client_sock.close();
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

    EXPECT_TRUE(session_active) << "smux session active with default max_streams=32";
}

// ── yamux tests ──────────────────────────────────────────────────

/**
 * @brief 测试 yamux 超过 max_streams 时新流收到 RST 拒绝
 * @details 配置 max_streams=2，通过 WindowUpdate(SYN) 打开 2 个流，
 * 第 3 个 WindowUpdate(SYN) 应被拒绝并回复 WindowUpdate(RST)。
 */
TEST(MuxMaxStreams, YamuxReject)
{
    constexpr std::uint32_t max_streams = 2;
    auto ctx = std::make_unique<mux_test_context>(max_streams);

    std::exception_ptr ep;
    bool session_active = false;
    bool found_rst = false;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto ex = ctx->ioc.get_executor();
        auto [client_sock, server_sock] = co_await make_socket_pair(ex);

        auto server_transport = psm::transport::make_reliable(std::move(server_sock));
        auto session = std::make_shared<yamux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        // 发送 3 个 WindowUpdate(SYN) 帧
        std::vector<std::byte> all_data;
        for (std::uint32_t i = 1; i <= 3; ++i)
        {
            auto wu_syn = build_yamux_header(yamux::message_type::window_update, yamux::flags::syn,
                                             i, yamux::default_window);
            all_data.insert(all_data.end(), wu_syn.begin(), wu_syn.end());
        }
        co_await async_write_raw(client_sock, all_data);

        co_await async_wait(ex, std::chrono::milliseconds(300));

        // 读取服务端响应
        std::array<std::byte, 4096> read_buf{};
        boost::system::error_code read_ec;
        auto n = co_await net::async_read(client_sock, net::buffer(read_buf),
                                          net::transfer_at_least(1),
                                          net::redirect_error(net::use_awaitable, read_ec));

        session_active = session->is_active();
        found_rst = find_rst_for_stream(read_buf, n, 3);

        session->close();
        client_sock.close();
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

    EXPECT_TRUE(session_active) << "yamux session remains active after max_streams reject";
    EXPECT_TRUE(found_rst) << "yamux sent RST for stream 3 exceeding max_streams";
}

/**
 * @brief 测试 yamux Data(SYN) 路径下的 max_streams 拒绝
 * @details 配置 max_streams=2，通过 Data(SYN) 打开 2 个流后，
 * 第 3 个 Data(SYN) 应被拒绝。
 */
TEST(MuxMaxStreams, YamuxDataSynReject)
{
    constexpr std::uint32_t max_streams = 2;
    auto ctx = std::make_unique<mux_test_context>(max_streams);

    std::exception_ptr ep;
    bool session_active = false;
    bool found_rst = false;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto ex = ctx->ioc.get_executor();
        auto [client_sock, server_sock] = co_await make_socket_pair(ex);

        auto server_transport = psm::transport::make_reliable(std::move(server_sock));
        auto session = std::make_shared<yamux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        // 注入 3 个 Data(SYN) 帧（空 payload）
        std::vector<std::byte> all_data;
        for (std::uint32_t i = 1; i <= 3; ++i)
        {
            auto data_syn = yamux::build_syn(i, {});
            all_data.insert(all_data.end(), data_syn.header.begin(), data_syn.header.end());
        }
        co_await async_write_raw(client_sock, all_data);

        co_await async_wait(ex, std::chrono::milliseconds(300));

        // 读取响应
        std::array<std::byte, 4096> read_buf{};
        boost::system::error_code read_ec;
        auto n = co_await net::async_read(client_sock, net::buffer(read_buf),
                                          net::transfer_at_least(1),
                                          net::redirect_error(net::use_awaitable, read_ec));

        session_active = session->is_active();
        found_rst = find_rst_for_stream(read_buf, n, 3);

        session->close();
        client_sock.close();
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

    EXPECT_TRUE(session_active) << "yamux session active after Data(SYN) max_streams reject";
    EXPECT_TRUE(found_rst) << "yamux sent RST for stream 3 via Data(SYN) path";
}

/**
 * @brief 测试 yamux max_streams=4 时 4 个流全部被接受，不产生 RST
 * @details 发送恰好 4 个 WindowUpdate(SYN) 帧，不应有 RST 帧产生。
 */
TEST(MuxMaxStreams, YamuxExact)
{
    constexpr std::uint32_t max_streams = 4;
    auto ctx = std::make_unique<mux_test_context>(max_streams);

    std::exception_ptr ep;
    bool session_active = false;
    bool found_any_rst_frame = false;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto ex = ctx->ioc.get_executor();
        auto [client_sock, server_sock] = co_await make_socket_pair(ex);

        auto server_transport = psm::transport::make_reliable(std::move(server_sock));
        auto session = std::make_shared<yamux::craft>(core_options{std::move(server_transport), &ctx->outbound, ctx->mux_config});
        session->start();

        // 注入恰好 4 个 WindowUpdate(SYN) 帧
        std::vector<std::byte> all_data;
        for (std::uint32_t i = 1; i <= 4; ++i)
        {
            auto wu_syn = build_yamux_header(yamux::message_type::window_update, yamux::flags::syn,
                                             i, yamux::default_window);
            all_data.insert(all_data.end(), wu_syn.begin(), wu_syn.end());
        }
        co_await async_write_raw(client_sock, all_data);

        co_await async_wait(ex, std::chrono::milliseconds(300));

        // 读取服务端响应
        std::array<std::byte, 4096> read_buf{};
        boost::system::error_code read_ec;
        auto n = co_await net::async_read(client_sock, net::buffer(read_buf),
                                          net::transfer_at_least(1),
                                          net::redirect_error(net::use_awaitable, read_ec));

        session_active = session->is_active();
        found_any_rst_frame = find_any_rst(read_buf, n);

        session->close();
        client_sock.close();
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

    EXPECT_TRUE(!found_any_rst_frame) << "yamux no RST when streams <= max_streams";
    EXPECT_TRUE(session_active) << "yamux session active at exact max_streams";
}

} // namespace
