/**
 * @file quic_gateway.cpp
 * @brief QUIC 入站网关实现
 * @details 协议认证：
 *          1. Hysteria2：完整 HTTP/3（nghttp3）认证 —— 客户端 quic-go
 *            栈发控制流 SETTINGS + QPACK encoder/decoder 流 + bidi 认证流
 *            （HEADERS 帧 QPACK 编码，可能引用动态表）。
 *          2. TUIC v5：uni 流认证 [VER 0x05][TYPE 0x00][UUID 16][TOKEN 32]。
 *          两者共存时按 uni 流首字节区分：0x04 = h3 SETTINGS（hysteria2），
 *          0x05 = tuic 认证。
 */

#include <prism/diagnose/diagnose.hpp>
#include <prism/foundation/fault/handling.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/protocol/handler.hpp>
#include <prism/protocol/tuic/codec.hpp>
#include <prism/protocol/tuic/handler.hpp>
#include <prism/protocol/vmess/codec/kdf.hpp>
#include <prism/resource/session.hpp>
#include <prism/runtime/front/quic_gateway.hpp>
#include <prism/runtime/session/session.hpp>
#include <prism/user/directory.hpp>

#include <boost/asio/co_spawn.hpp>

#include <algorithm>
#include <cstring>
#include <thread>

using namespace psm::diagnose;

namespace psm::runtime::front
{

    namespace net = boost::asio;
    namespace quic = psm::quic;

    quic_gateway::quic_gateway(const psm::settings &cfg, balancer &dispatcher,
                               psm::memory::vector<std::shared_ptr<psm::resource::worker>> workers)
        : cfg_(cfg), dispatcher_(dispatcher), workers_(std::move(workers))
    {
    }

    void quic_gateway::start()
    {
        const auto &ep = cfg_.instance.addressable;
        const auto addr = net::ip::make_address(ep.host);
        socket_ = std::make_shared<udp::socket>(ioc_, udp::endpoint(addr, ep.port));

        net::co_spawn(
            ioc_, [self = shared_from_this()]() -> net::awaitable<void> { co_await self->receive_loop(); },
            net::detached);

        thread_ = std::make_unique<std::thread>(
            [this]()
            {
                try
                {
                    ioc_.run();
                }
                catch (const std::exception &e)
                {
                    diagnose::error("quic gateway exception: {}", e.what());
                }
            });
        diagnose::info("quic gateway listening on udp {}:{}", ep.host, ep.port);
    }

    void quic_gateway::stop()
    {
        closed_ = true;
        if (socket_)
        {
            boost::system::error_code ec;
            socket_->close(ec);
        }
        ioc_.stop();
        if (thread_ && thread_->joinable())
        {
            thread_->join();
        }
    }

    auto quic_gateway::conn_key(const udp::endpoint &ep) noexcept -> std::uint64_t
    {
        const auto bytes = ep.address().to_v4().to_bytes();
        return (static_cast<std::uint64_t>(bytes[0]) << 40) | (static_cast<std::uint64_t>(bytes[1]) << 32) |
               (static_cast<std::uint64_t>(bytes[2]) << 24) | (static_cast<std::uint64_t>(bytes[3]) << 16) |
               static_cast<std::uint64_t>(ep.port());
    }

    auto quic_gateway::pick_worker(const udp::endpoint &peer) -> std::shared_ptr<psm::resource::worker>
    {
        const auto sel = dispatcher_.select(conn_key(peer));
        return workers_[sel.worker_index % workers_.size()];
    }

    auto quic_gateway::receive_loop() -> net::awaitable<void>
    {
        std::array<std::byte, 65536> buf{};
        while (!closed_)
        {
            boost::system::error_code ec;
            udp::endpoint from;
            const auto n = co_await socket_->async_receive_from(net::buffer(buf.data(), buf.size()), from,
                                                                net::redirect_error(net::use_awaitable, ec));
            if (ec || closed_)
            {
                break;
            }
            co_await on_packet(from, std::span<const std::byte>(buf.data(), n));
        }
    }

    auto quic_gateway::on_packet(const udp::endpoint &from, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        if (data.empty())
        {
            co_return;
        }
        const auto key = conn_key(from);
        auto it = conns_.find(key);
        if (it == conns_.end())
        {
            auto worker = pick_worker(from);
            auto &proc = worker->process;
            if (!proc->ssl)
            {
                diagnose::warn("quic gateway: no SSL context");
                co_return;
            }
            connection_state state;
            state.conn = quic::make_server(quic::server_options{
                .executor = ioc_.get_executor(),
                .peer = from,
                .udp = socket_,
                .ssl_ctx = proc->ssl->native_handle(),
                .mr = psm::memory::current_resource(),
                .prefix = std::make_shared<diagnose::context>(),
            });
            auto conn = state.conn;
            conn->on_stream = [self = shared_from_this(), key](quic::shared_stream stream)
            {
                net::co_spawn(
                    self->ioc_,
                    [self, key, stream]() -> net::awaitable<void>
                    {
                        auto it = self->conns_.find(key);
                        if (it == self->conns_.end())
                        {
                            co_return;
                        }
                        co_await self->on_stream(it->second, std::move(stream));
                    },
                    net::detached);
            };
            conns_.emplace(key, std::move(state));
            co_await conn->handle_datagram(from, data);
            co_return;
        }
        co_await it->second.conn->handle_datagram(from, data);
    }

    auto quic_gateway::on_stream(connection_state &state, quic::shared_stream stream) -> net::awaitable<void>
    {
        const auto h2_enabled = cfg_.stealth.hysteria2.enabled();
        const auto tuic_enabled = cfg_.stealth.tuic.enabled();

        if (!state.authenticated)
        {
            // uni 流：首字节 = 流类型 varint（HTTP/3：0x00 控制流 / 0x02 QPACK encoder /
            // 0x03 QPACK decoder；TUIC 认证流 = VER 0x05）
            if (stream->is_uni())
            {
                std::byte first{};
                std::error_code ec;
                const auto n = co_await stream->async_read_some(std::span<std::byte>(&first, 1), ec);
                if (ec || n == 0)
                {
                    stream->close();
                    co_return;
                }
                const auto fb = static_cast<std::uint8_t>(first);
                if ((fb == 0x00 || fb == 0x02 || fb == 0x03) && h2_enabled)
                {
                    // h3 控制流 / QPACK 流 → 喂 nghttp3（内部按流类型分发）
                    start_h3(state);
                    if (!state.h3)
                    {
                        co_return;
                    }
                    co_spawn(ioc_, h3_read_stream(state, std::move(stream), first, true), net::detached);
                }
                else if (fb == 0x05 && tuic_enabled)
                {
                    co_await authenticate_tuic(state, std::move(stream), first);
                }
                else
                {
                    diagnose::warn("quic gateway: unexpected uni stream 0x{:02x}", fb);
                    stream->close();
                    state.conn->close();
                }
                co_return;
            }

            // bidi 流：读首字节区分协议
            //  0x01 = HTTP/3 HEADERS 帧（hysteria2 认证流）
            //  0x05 = TUIC Connect 帧（v5 版本号）
            std::byte first{};
            std::error_code f_ec;
            const auto f_n = co_await stream->async_read_some(std::span<std::byte>(&first, 1), f_ec);
            if (f_ec || f_n == 0)
            {
                stream->close();
                state.conn->close();
                co_return;
            }
            const auto fb = static_cast<std::uint8_t>(first);
            if (fb == 0x05 && tuic_enabled)
            {
                // TUIC Connect 流：认证完成前缓存（含首字节），认证后分发
                state.pending.emplace_back(std::move(stream), first);
                co_return;
            }
            if (fb != 0x01 || !h2_enabled)
            {
                stream->close();
                state.conn->close();
                co_return;
            }
            // hysteria2 认证流（HEADERS 帧）
            if (state.auth_started)
            {
                state.pending.emplace_back(std::move(stream), first);
                co_return;
            }
            state.auth_started = true;
            start_h3(state);
            if (!state.h3)
            {
                co_return;
            }
            co_spawn(ioc_, h3_read_stream(state, std::move(stream), first, true), net::detached);
            co_return;
        }

        // 认证完成后的数据流
        if (state.type == psm::connect::protocol_type::hysteria2)
        {
            co_await launch_handler(state, std::move(stream));
        }
        else if (state.type == psm::connect::protocol_type::tuic)
        {
            if (stream->is_uni())
            {
                co_await launch_udp_channel(state, std::move(stream));
            }
            else
            {
                co_await launch_handler(state, std::move(stream));
            }
        }
    }

    void quic_gateway::start_h3(connection_state &state)
    {
        if (state.h3)
        {
            return;
        }

        state.h3 = std::make_shared<psm::protocol::hysteria2::h3::server>(psm::memory::current_resource());
        auto conn = state.conn;
        if (!state.h3->init([conn]() -> std::int64_t { return conn->open_uni_stream(); }))
        {
            diagnose::warn("quic gateway: h3 init failed");
            state.h3.reset();
            state.conn->close();
            return;
        }
        state.h3_queue = std::make_unique<h3_channel>(ioc_.get_executor(), 256);
        co_spawn(ioc_, h3_pump(conn_key(state.conn->peer_endpoint())), net::detached);
    }

    auto quic_gateway::h3_pump(std::uint64_t key) -> net::awaitable<void>
    {
        auto self = shared_from_this();
        auto it = self->conns_.find(key);
        if (it == self->conns_.end())
        {
            co_return;
        }
        auto &state = it->second;

        while (!state.authenticated)
        {
            boost::system::error_code ec;
            auto [stream_id, data, fin] =
                co_await state.h3_queue->async_receive(net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                break;
            }

            if (state.h3->feed(stream_id, data, fin) != psm::fault::code::success)
            {
                diagnose::warn("quic gateway: h3 feed failed");
                state.conn->close();
                break;
            }

            // 认证头完整 → 判定 → 提交响应
            if (state.h3->auth_headers_complete() && !state.h3_auth_checked)
            {
                state.h3_auth_checked = true;
                auto ok = state.h3->method() == "POST" && state.h3->path() == "/auth";
                if (ok)
                {
                    ok = false;
                    const auto &users = cfg_.stealth.hysteria2.users;
                    for (const auto &u : users)
                    {
                        if (state.h3->auth() == std::string_view(u.data(), u.size()))
                        {
                            ok = true;
                            break;
                        }
                    }
                }
                if (ok)
                {
                    state.h3->submit_auth_response();
                    state.authenticated = true;
                    state.type = psm::connect::protocol_type::hysteria2;
                    diagnose::debug("quic gateway: hysteria2 authenticated (h3)");
                }
                else
                {
                    diagnose::warn("quic gateway: hysteria2 auth failed");
                    state.conn->close();
                    break;
                }
            }

            // 收集 nghttp3 输出（SETTINGS / QPACK 指令 / 认证响应）写回 QUIC
            psm::memory::vector<psm::protocol::hysteria2::h3::out_packet> out(
                psm::memory::current_resource());
            if (!state.h3->pump_output(out))
            {
                state.conn->close();
                break;
            }
            for (auto &pkt : out)
            {
                co_await state.conn->write_stream_data(pkt.stream_id, pkt.data);
            }
        }

        // 认证完成：分发认证期间缓存的流
        if (state.authenticated)
        {
            for (auto &[s, fb] : state.pending)
            {
                co_await launch_handler(state, std::move(s), std::span<const std::byte>(&fb, 1));
            }
            state.pending.clear();
        }
    }

    auto quic_gateway::h3_read_stream(connection_state &state, quic::shared_stream stream,
                                      const std::byte first, const bool has_first) -> net::awaitable<void>
    {
        auto *queue = state.h3_queue.get();
        const auto sid = stream->id();
        if (has_first)
        {
            psm::memory::vector<std::byte> head(psm::memory::current_resource());
            head.push_back(first);
            queue->try_send(boost::system::error_code{}, sid, std::move(head), false);
            diagnose::info("quic gateway: h3 reader sid={} first sent", sid);
        }

        std::array<std::byte, 4096> buf{};
        while (true)
        {
            std::error_code ec;
            const auto n = co_await stream->async_read_some(std::span<std::byte>(buf), ec);
            if (ec || n == 0)
            {
                psm::memory::vector<std::byte> empty(psm::memory::current_resource());
                queue->try_send(boost::system::error_code{}, sid, std::move(empty), true);
                break;
            }
            psm::memory::vector<std::byte> chunk(psm::memory::current_resource());
            chunk.assign(buf.data(), buf.data() + static_cast<std::ptrdiff_t>(n));
            queue->try_send(boost::system::error_code{}, sid, std::move(chunk), false);
        }
    }

    auto quic_gateway::authenticate_tuic(connection_state &state, quic::shared_stream stream,
                                         const std::byte first) -> net::awaitable<void>
    {
        // 标记认证进行中：期间到达的 bidi Connect 流应缓存到 pending，
        // 避免误入 hysteria2 的 h3 认证分支（其启动 nghttp3 会吞掉 TUIC 帧）
        state.auth_started = true;

        // mihomo 兼容认证：uni stream 发送 [VER 0x05][TYPE 0x00][UUID 16B][TOKEN 32B]
        // 首字节（0x05）已在 on_stream 读出，剩余 49 字节在此补齐
        std::array<std::byte, 50> buf{};
        buf[0] = first;
        std::size_t total = 1;
        while (total < buf.size())
        {
            std::error_code ec;
            const auto n = co_await stream->async_read_some(
                std::span<std::byte>(buf.data() + total, buf.size() - total), ec);
            if (ec || n == 0)
            {
                stream->close();
                state.conn->close();
                co_return;
            }
            total += n;
        }

        const auto *p = reinterpret_cast<const std::uint8_t *>(buf.data());
        auto ok = p[0] == psm::protocol::tuic::version &&
                  p[1] == static_cast<std::uint8_t>(psm::protocol::tuic::command::authenticate);

        if (ok)
        {
            // 按 UUID 查找用户（配置 users 表）
            const auto &users = cfg_.stealth.tuic.users;
            std::string_view password;
            for (const auto &u : users)
            {
                // 配置 uuid 为 36 字符十六进制，转 16 字节原始比较
                std::array<std::uint8_t, 16> raw{};
                if (psm::protocol::vmess::codec::parse_uuid(std::string_view(u.uuid.data(), u.uuid.size()),
                                                            raw) &&
                    std::memcmp(raw.data(), p + 2, 16) == 0)
                {
                    password = std::string_view(u.password.data(), u.password.size());
                    break;
                }
            }
            if (password.empty())
            {
                diagnose::warn("quic gateway: tuic unknown user");
                ok = false;
            }
            else
            {
                // 校验 token：ExportKeyingMaterial(label=UUID原始16字节, context=password)
                auto *ssl = state.conn->native_ssl();
                std::array<std::uint8_t, 32> expected{};
                if (!ssl || SSL_export_keying_material(
                                ssl, expected.data(), expected.size(), reinterpret_cast<const char *>(p + 2),
                                16, reinterpret_cast<const unsigned char *>(password.data()),
                                static_cast<int>(password.size()), 1) != 1)
                {
                    diagnose::warn("quic gateway: tuic exporter unavailable");
                    ok = false;
                }
                else if (std::memcmp(expected.data(), p + 2 + 16, 32) != 0)
                {
                    diagnose::warn("quic gateway: tuic token mismatch");
                    ok = false;
                }
                else
                {
                    diagnose::debug("quic gateway: tuic authenticated");
                }
            }
        }
        else
        {
            diagnose::warn("quic gateway: tuic malformed auth header");
        }

        // 认证成功不写响应（mihomo 客户端不读）；失败关闭连接
        if (!ok)
        {
            stream->close();
            state.conn->close();
            co_return;
        }

        state.authenticated = true;
        state.type = psm::connect::protocol_type::tuic;
        stream->close();

        // 分发认证期间缓存的流
        for (auto &[s, fb] : state.pending)
        {
            if (s->is_uni())
            {
                co_await launch_udp_channel(state, std::move(s));
            }
            else
            {
                co_await launch_handler(state, std::move(s), std::span<const std::byte>(&fb, 1));
            }
        }
        state.pending.clear();
    }

    auto quic_gateway::launch_handler(connection_state &state, quic::shared_stream stream,
                                      const std::span<const std::byte> preread) -> net::awaitable<void>
    {
        auto worker = pick_worker(state.conn->peer_endpoint());

        // 构造会话资源
        auto trace = std::make_shared<diagnose::context>();
        auto meta = std::make_shared<psm::resource::metadata>();
        const auto peer = state.conn->peer_endpoint();
        if (peer.address().is_v4())
        {
            meta->src =
                net::ip::tcp::endpoint(net::ip::address_v4(peer.address().to_v4().to_bytes()), peer.port());
        }

        psm::resource::session::options opts;
        opts.worker = worker;
        opts.conn = psm::runtime::session::detail::next_conn_id();
        opts.buffer = worker->process->cfg->buffer.size;
        opts.inbound = stream;
        opts.src = {};
        opts.trace = trace;
        opts.meta = meta;
        opts.detected = state.type;
        auto sess_res = std::make_shared<psm::resource::session>(std::move(opts));

        psm::protocol::handler_params params(*sess_res, preread);
        auto handler = psm::protocol::make_protocol_handler(state.type, std::move(params));
        if (!handler)
        {
            diagnose::warn("quic gateway: no handler for {}", psm::connect::to_string_view(state.type));
            stream->close();
            state.conn->close();
            co_return;
        }
        worker->traffic.on_connect();
        co_await handler->run();
        worker->traffic.on_disconnect(state.type);
        stream->close();
    }

    auto quic_gateway::launch_udp_channel(connection_state &state, quic::shared_stream stream)
        -> net::awaitable<void>
    {
        auto worker = pick_worker(state.conn->peer_endpoint());

        auto trace = std::make_shared<diagnose::context>();
        auto meta = std::make_shared<psm::resource::metadata>();
        const auto peer = state.conn->peer_endpoint();
        if (peer.address().is_v4())
        {
            meta->src =
                net::ip::tcp::endpoint(net::ip::address_v4(peer.address().to_v4().to_bytes()), peer.port());
        }

        psm::resource::session::options opts;
        opts.worker = worker;
        opts.conn = psm::runtime::session::detail::next_conn_id();
        opts.buffer = worker->process->cfg->buffer.size;
        opts.inbound = stream;
        opts.src = {};
        opts.trace = trace;
        opts.meta = meta;
        opts.detected = psm::connect::protocol_type::tuic;
        auto sess_res = std::make_shared<psm::resource::session>(std::move(opts));

        psm::protocol::handler_params params(*sess_res, {});
        auto handler = std::make_unique<psm::protocol::tuic::udp_handler>(std::move(params));
        worker->traffic.on_connect();
        co_await handler->run();
        worker->traffic.on_disconnect(state.type);
        stream->close();
    }

} // namespace psm::runtime::front
