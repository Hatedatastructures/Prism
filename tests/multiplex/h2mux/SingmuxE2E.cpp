/**
 * @file SingmuxE2E.cpp
 * @brief sing-mux h2mux 端到端测试
 * @details 模拟 sing-mux 客户端（mihomo sing-mux 兼容）：
 *          1. 会话头 [version=0][protocol=2(h2mux)]
 *          2. nghttp2 客户端发起 CONNECT stream
 *          3. 首个 DATA 帧携带 StreamRequest + 用户数据
 *          4. 服务端解析目标 → 连接本地 echo server
 *          5. 验证响应 200 + StreamResponse 状态字节 0x00 + 数据回显
 */

#include <prism/foundation/foundation.hpp>
#include <prism/diagnose/log.hpp>

#define private public
#define protected public
#include <prism/protocol/multiplex/h2mux/control.hpp>
#undef protected
#undef private
#include <prism/protocol/multiplex/h2mux/singmux.hpp>
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/connection/outbound/direct.hpp>
#include <prism/net/dns/resolver.hpp>
#include <prism/net/transport/reliable.hpp>

#include <nghttp2/nghttp2.h>

#include <gtest/gtest.h>

#include <memory>

namespace
{
    using control = psm::multiplex::h2mux::control;
    namespace multiplex = psm::multiplex;
    namespace h2mux = psm::multiplex::h2mux;
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    static multiplex::config g_cfg{};

    /// sing-mux 解析器（返回 invalid，等待 DATA 帧 StreamRequest）
    auto make_sing_resolver() -> h2mux::address_resolver
    {
        return [](std::int32_t, const h2mux::h2_headers &) -> h2mux::stream_info
        {
            return {};
        };
    }

    /// 本地 echo server 协程（接受连接并回显）
    net::awaitable<void> DoEchoServer(tcp::acceptor &acceptor)
    {
        while (true)
        {
            auto sock = co_await acceptor.async_accept(net::use_awaitable);
            net::co_spawn(sock.get_executor(), [s = std::move(sock)]() mutable -> net::awaitable<void>
            {
                std::array<std::byte, 4096> buf{};
                while (true)
                {
                    boost::system::error_code ec;
                    const auto n = co_await s.async_read_some(net::buffer(buf), net::redirect_error(net::use_awaitable, ec));
                    if (ec || n == 0)
                        break;
                    co_await s.async_write_some(net::buffer(buf.data(), n), net::redirect_error(net::use_awaitable, ec));
                    if (ec)
                        break;
                }
            }, net::detached);
        }
    }

    /// DATA provider 源（存活至会话结束，nghttp2 在 PAUSE 后仍会调用 provider）
    struct data_source
    {
        const std::vector<std::byte> *buf;
        std::size_t offset{0};
    };

    /// 客户端上下文（发送经缓冲由主协程异步写出）
    struct client_ctx
    {
        psm::transport::shared_transmission transport;
        nghttp2_session *session{nullptr};
        std::vector<std::byte> received;
        std::vector<std::byte> outbound;
        std::unique_ptr<data_source> source;  ///< DATA provider 源（存活至会话结束）
        bool got_200{false};
    };

    auto on_client_send(nghttp2_session *, const uint8_t *data, const size_t len, int, void *user_data) -> ssize_t
    {
        auto *ctx = static_cast<client_ctx *>(user_data);
        ctx->outbound.insert(ctx->outbound.end(),
                             reinterpret_cast<const std::byte *>(data),
                             reinterpret_cast<const std::byte *>(data) + len);
        return static_cast<ssize_t>(len);
    }

    auto on_client_header(nghttp2_session *, const nghttp2_frame *frame, const uint8_t *name,
                          const size_t namelen, const uint8_t *value, const size_t valuelen,
                          uint8_t, void *user_data) -> int
    {
        auto *ctx = static_cast<client_ctx *>(user_data);
        if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
        {
            const std::string_view n(reinterpret_cast<const char *>(name), namelen);
            const std::string_view v(reinterpret_cast<const char *>(value), valuelen);
            if (n == ":status" && v == "200")
                ctx->got_200 = true;
        }
        return 0;
    }

    auto on_client_data(nghttp2_session *, uint8_t, const int32_t, const uint8_t *data,
                        const size_t len, void *user_data) -> int
    {
        auto *ctx = static_cast<client_ctx *>(user_data);
        ctx->received.insert(ctx->received.end(),
                             reinterpret_cast<const std::byte *>(data),
                             reinterpret_cast<const std::byte *>(data) + len);
        return 0;
    }

    /// 构造 nghttp2 data provider（读取 buf 的 offset 之后部分）
    /// 注：数据发完后返回 NGHTTP2_ERR_PAUSE —— 帧暂停且流保持双向打开
    ///     （sing-mux 语义；EOF 会使流进入半关状态，服务端无法回发
    ///      响应 DATA）。source 由 client_ctx 持有，存活至会话结束。
    auto source_read_cb(nghttp2_session *, int32_t, uint8_t *buf, const size_t length,
                        uint32_t *data_flags, nghttp2_data_source *source, void *) -> ssize_t
    {
        auto *ds = static_cast<data_source *>(source->ptr);
        const auto remaining = ds->buf->size() - ds->offset;
        if (remaining == 0)
        {
            return NGHTTP2_ERR_PAUSE;
        }
        const auto to_copy = std::min(length, remaining);
        std::memcpy(buf, ds->buf->data() + ds->offset, to_copy);
        ds->offset += to_copy;
        return static_cast<ssize_t>(to_copy);
    }

    /// 模拟 sing-mux 客户端协程
    net::awaitable<void> DoSingClient(psm::transport::shared_transmission transport,
                                      const tcp::endpoint echo_ep, const std::string &payload,
                                      std::shared_ptr<bool> ok)
    {
        client_ctx ctx;
        ctx.transport = transport;
        ctx.received.reserve(8192);

        nghttp2_session_callbacks *callbacks = nullptr;
        nghttp2_session_callbacks_new(&callbacks);
        nghttp2_session_callbacks_set_send_callback(callbacks, on_client_send);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, on_client_header);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_client_data);
        nghttp2_session_client_new(&ctx.session, callbacks, &ctx);
        nghttp2_session_callbacks_del(callbacks);

        std::error_code ec;

        // SETTINGS + CONNECT 请求（data_prd 随请求提交，避免 HEADERS 带 END_STREAM）
        nghttp2_submit_settings(ctx.session, NGHTTP2_FLAG_NONE, nullptr, 0);
        // 首个 DATA 帧：StreamRequest（TCP IPv4 127.0.0.1:echo_port）+ 用户数据
        std::vector<std::byte> body{std::byte{0}, std::byte{0}, std::byte{1}, std::byte{127},
                                    std::byte{0}, std::byte{0}, std::byte{1}};
        body.push_back(static_cast<std::byte>(echo_ep.port() >> 8));
        body.push_back(static_cast<std::byte>(echo_ep.port() & 0xFF));
        for (const auto c : payload)
            body.push_back(static_cast<std::byte>(c));
        auto authority = std::string("127.0.0.1:") + std::to_string(echo_ep.port());
        std::array<nghttp2_nv, 2> nva{};
        nva[0] = nghttp2_nv{
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":method")),
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>("CONNECT")),
            7, 7, NGHTTP2_NV_FLAG_NONE};
        nva[1] = nghttp2_nv{
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":authority")),
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(authority.data())),
            10, authority.size(), NGHTTP2_NV_FLAG_NONE};
        ctx.source = std::make_unique<data_source>(data_source{&body, 0});
        nghttp2_data_provider dp;
        dp.source.ptr = ctx.source.get();
        dp.read_callback = source_read_cb;
        const auto stream_id = nghttp2_submit_request(ctx.session, nullptr, nva.data(), nva.size(),
                                                      &dp, &ctx);
        if (stream_id < 0)
        {
            *ok = false;
            nghttp2_session_del(ctx.session);
            co_return;
        }

        // 发送（回调积累到 outbound 缓冲）
        ctx.outbound.clear();
        if (nghttp2_session_send(ctx.session) != 0)
        {
            *ok = false;
            nghttp2_session_del(ctx.session);
            co_return;
        }
        if (!ctx.outbound.empty())
        {
            auto first = std::move(ctx.outbound);
            ctx.outbound.clear();
            co_await transport->async_write_some(first, ec);
            if (ec)
            {
                *ok = false;
                nghttp2_session_del(ctx.session);
                co_return;
            }
        }

        // 读取服务端响应（200 + 状态字节 0x00 + 回显）
        std::array<std::byte, 8192> buf{};
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (ctx.received.size() < payload.size() + 1 && std::chrono::steady_clock::now() < deadline)
        {
            std::error_code r_ec;
            const auto n = co_await transport->async_read_some(buf, r_ec);
            if (r_ec || n == 0)
                break;
            if (nghttp2_session_mem_recv(ctx.session,
                                         reinterpret_cast<const uint8_t *>(buf.data()), n) < 0)
                break;
            // 刷新 mem_recv 触发的响应（WINDOW_UPDATE 等）
            if (!ctx.outbound.empty())
            {
                auto pending = std::move(ctx.outbound);
                ctx.outbound.clear();
                co_await transport->async_write_some(pending, ec);
                if (ec)
                    break;
            }
        }

        // 验证：200 + 首字节 0x00（StreamResponse 成功）+ 回显内容
        const bool ok_200 = ctx.got_200;
        const bool ok_size = ctx.received.size() >= 1 + payload.size();
        const bool ok_status = ok_size && ctx.received[0] == std::byte{0};
        const bool ok_echo = ok_size
            && std::string_view(reinterpret_cast<const char *>(ctx.received.data() + 1), payload.size()) == payload;
        *ok = ok_200 && ok_size && ok_status && ok_echo;
        if (!*ok)
        {
            std::fprintf(stderr, "[singmux e2e] got_200=%d recv=%zu ok_size=%d ok_status=%d ok_echo=%d\n",
                         ok_200 ? 1 : 0, ctx.received.size(), ok_size ? 1 : 0,
                         ok_status ? 1 : 0, ok_echo ? 1 : 0);
        }

        nghttp2_session_del(ctx.session);
        co_return;
    }
} // namespace

TEST(SingmuxE2E, TcpStreamEchoViaStreamRequest)
{
    // 初始化诊断日志（控制台输出，便于排查帧循环错误）
    psm::diagnose::config trace_cfg;
    trace_cfg.log_level = "debug";
    trace_cfg.enable_console = true;
    trace_cfg.enable_file = false;
    psm::diagnose::init(trace_cfg);

    net::io_context ioc;

    // 本地 echo server（accept 挂起是常态，结束时 ioc.stop() 终止）
    tcp::acceptor echo_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    const auto echo_ep = echo_acceptor.local_endpoint();
    net::co_spawn(ioc, DoEchoServer(echo_acceptor), net::detached);

    // 服务端-客户端 TCP pair
    tcp::acceptor pair_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    const auto pair_ep = pair_acceptor.local_endpoint();
    psm::transport::shared_transmission server_trans;
    psm::transport::shared_transmission client_trans;
    auto pair_ready = std::make_shared<bool>(false);
    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        auto sock = co_await pair_acceptor.async_accept(net::use_awaitable);
        server_trans = psm::transport::make_reliable(std::move(sock));
        pair_acceptor.close();
    }, net::detached);
    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        tcp::socket sock(ioc);
        co_await sock.async_connect(pair_ep, net::use_awaitable);
        client_trans = psm::transport::make_reliable(std::move(sock));
        *pair_ready = true;
    }, net::detached);

    const std::string payload = "sing-mux echo payload";
    auto client_ok = std::make_shared<bool>(false);

    // 主流程：等 pair 就绪 → 启动 h2mux 服务端 + sing-mux 客户端 → 等待结果 → stop
    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        net::steady_timer t(ioc);
        while (!*pair_ready)
        {
            t.expires_after(std::chrono::milliseconds(10));
            co_await t.async_wait(net::use_awaitable);
        }

        psm::dns::config dns_cfg;
        psm::connect::dialer_options ropts{ioc, dns_cfg};
        auto router = std::make_shared<psm::connect::dialer>(std::move(ropts));
        psm::outbound::direct outbound(*router);
        auto session = std::make_shared<control>(
            multiplex::multiplexer_options{server_trans, &outbound, g_cfg, nullptr},
            make_sing_resolver(), true);
        session->start();

        net::co_spawn(ioc, DoSingClient(client_trans, echo_ep, payload, client_ok), net::detached);

        // 等待客户端完成（5 秒上限）
        net::steady_timer done(ioc);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!*client_ok && std::chrono::steady_clock::now() < deadline)
        {
            done.expires_after(std::chrono::milliseconds(20));
            co_await done.async_wait(net::use_awaitable);
        }

        client_trans->close();
        server_trans->close();
        session->close();
        ioc.stop();
    }, net::detached);

    ioc.run();
    EXPECT_TRUE(*client_ok) << "sing-mux: TCP stream echo via StreamRequest";
}
