/**
 * @file resolver.cpp
 * @brief DNS 查询客户端实现
 * @details 实现 resolver 类的全部异步查询方法，包括 UDP、TCP、DoT 和 DoH
 * 四种传输协议。每种协议均包含超时控制、错误处理和响应解析逻辑。
 * resolve() 方法负责协调多上游查询，根据策略选择最优响应。
 *
 * 超时机制：使用 timer 回调取消 socket 实现超时控制。
 * socket 通过 shared_ptr 管理，确保 timer 回调在函数返回后仍安全访问。
 * timer 回调仅在被自然触发时（e != operation_aborted）才取消 socket，
 * 被 timer.cancel() 或析构取消时不操作，避免干扰后续 I/O。
 */
#include <forward-engine/resolve/resolver.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>

#include <openssl/ssl.h>

namespace ngx::resolve
{
    // BoringSSL SNI 回调：设置 TLS ClientHello 中的 server_name 扩展
    static int sni_callback(SSL *ssl, int *, void *arg)
    {
        SSL_set_tlsext_host_name(ssl, static_cast<const char *>(arg));
        return SSL_TLSEXT_ERR_OK;
    }

    // 检查是否为超时错误（timer 回调取消 socket 导致的 operation_aborted）
    static bool is_timeout(const boost::system::error_code &ec)
    {
        return ec == net::error::operation_aborted;
    }

    resolver::resolver(net::io_context &ioc, memory::resource_pointer mr)
        : ioc_(ioc), mr_(mr ? mr : memory::current_resource()), servers_(mr_)
    {
    }

    void resolver::set_servers(const memory::vector<dns_remote> servers)
    {
        servers_ = servers;
    }

    void resolver::set_mode(const resolve_mode mode)
    {
        mode_ = mode;
    }

    void resolver::set_timeout(const uint32_t ms)
    {
        timeout_ms_ = ms;
    }

    auto resolver::resolve(std::string_view domain, qtype qt)
        -> net::awaitable<resolve_result>
    {
        // 构造 DNS 查询报文
        auto query_msg = message::make_query(domain, qt, mr_);

        // 生成半随机 ID：域名哈希 ^ 时间戳低位，降低冲突概率
        const auto domain_hash = std::hash<std::string_view>{}(domain);
        const auto timestamp = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
        query_msg.id = static_cast<uint16_t>(domain_hash ^ timestamp);

        // 无上游服务器时直接返回失败
        if (servers_.empty()) [[unlikely]]
        {
            trace::warn("[Resolve] upstream list is empty, domain={}", domain);
            auto fallback = resolve_result(mr_);
            fallback.error = fault::code::dns_failed;
            co_return fallback;
        }

        // fallback 模式：顺序尝试，前一个失败后才尝试下一个
        if (mode_ == resolve_mode::fallback)
        {
            for (const auto &server : servers_)
            {
                auto result = resolve_result(mr_);
                switch (server.protocol)
                {
                case dns_protocol::udp:
                    result = co_await query_udp(server, query_msg);
                    break;
                case dns_protocol::tcp:
                    result = co_await query_tcp(server, query_msg);
                    break;
                case dns_protocol::tls:
                    result = co_await query_tls(server, query_msg);
                    break;
                case dns_protocol::https:
                    result = co_await query_https(server, query_msg);
                    break;
                }

                trace::debug("[Resolve] query to {} completed: code={}, ips={}, rtt={}ms", server.address,
                             fault::describe(result.error), result.ips.size(), result.rtt_ms);

                if (succeeded(result.error) && !result.ips.empty())
                {
                    co_return result;
                }
            }
            auto fallback = resolve_result(mr_);
            fallback.error = fault::code::dns_failed;
            co_return fallback;
        }

        // first / fastest 模式：并发查询所有上游
        // 使用 shared_ptr 延长生命周期，确保 detached 任务在协程帧销毁后
        // 仍可安全访问 query 和 results（first 模式会提前 co_return）
        auto query_shared = std::make_shared<message>(std::move(query_msg));
        auto results_shared = std::make_shared<memory::vector<resolve_result>>(mr_);
        results_shared->resize(servers_.size());
        for (auto &r : *results_shared)
        {
            r = resolve_result(mr_);
        }

        for (std::size_t i = 0; i < servers_.size(); ++i)
        {
            const auto &server = servers_[i];

            auto task = [this, &server, query_shared, results_shared, i]() -> net::awaitable<void>
            {
                auto &result = (*results_shared)[i];
                switch (server.protocol)
                {
                case dns_protocol::udp:
                    result = co_await query_udp(server, *query_shared);
                    break;
                case dns_protocol::tcp:
                    result = co_await query_tcp(server, *query_shared);
                    break;
                case dns_protocol::tls:
                    result = co_await query_tls(server, *query_shared);
                    break;
                case dns_protocol::https:
                    result = co_await query_https(server, *query_shared);
                    break;
                }

                trace::debug("[Resolve] query to {} completed: code={}, ips={}, rtt={}ms", server.address,
                             fault::describe(result.error), result.ips.size(), result.rtt_ms);
            };
            net::co_spawn(ioc_, std::move(task), net::detached);
        }

        const auto is_pending = [](const resolve_result &r)
        {
            return r.error == fault::code::success && r.ips.empty() && r.server_addr.empty();
        };

        net::steady_timer yield_timer(ioc_);
        while (true)
        {
            // first 模式：收到第一个成功响应即返回
            if (mode_ == resolve_mode::first)
            {
                for (auto &r : *results_shared)
                {
                    if (!is_pending(r) && succeeded(r.error) && !r.ips.empty())
                    {
                        co_return std::move(r);
                    }
                }
            }

            // 等待所有结果完成
            bool all_done = true;
            for (const auto &r : *results_shared)
            {
                if (is_pending(r))
                {
                    all_done = false;
                    break;
                }
            }
            if (all_done)
            {
                break;
            }

            yield_timer.expires_after(std::chrono::milliseconds(0));
            boost::system::error_code ignored;
            co_await yield_timer.async_wait(net::redirect_error(net::use_awaitable, ignored));
        }

        // fastest 模式：选 RTT 最低的成功响应
        resolve_result *best = nullptr;
        for (auto &r : *results_shared)
        {
            if (succeeded(r.error) && !r.ips.empty())
            {
                if (!best || r.rtt_ms < best->rtt_ms)
                {
                    best = &r;
                }
            }
        }
        if (best)
        {
            co_return std::move(*best);
        }

        if (!results_shared->empty())
        {
            co_return std::move(results_shared->front());
        }

        auto fallback = resolve_result(mr_);
        fallback.error = fault::code::dns_failed;
        co_return fallback;
    }

    // query_udp — UDP DNS 查询

    auto resolver::query_udp(const dns_remote &server, const message &query)
        -> net::awaitable<resolve_result>
    {
        const auto start = std::chrono::steady_clock::now();
        auto result = resolve_result(mr_);

        // 1. 解析目标地址
        boost::system::error_code addr_ec;
        const auto addr = net::ip::make_address(server.address, addr_ec);
        if (addr_ec) [[unlikely]]
        {
            trace::error("[Resolve] invalid server address '{}': {}", server.address, addr_ec.message());
            result.error = fault::code::bad_message;
            co_return result;
        }
        net::ip::udp::endpoint target(addr, server.port);

        // 2. 创建 UDP 套接字（shared_ptr 延长生命周期，确保 timer 回调安全）
        auto sock = std::make_shared<net::ip::udp::socket>(ioc_);
        boost::system::error_code sock_ec;
        sock->open(addr.is_v6() ? net::ip::udp::v6() : net::ip::udp::v4(), sock_ec);
        if (sock_ec) [[unlikely]]
        {
            trace::error("[Resolve] failed to open socket: {}", sock_ec.message());
            result.error = fault::code::io_error;
            co_return result;
        }

        // 3. 序列化查询报文
        auto packet = query.pack();

        // 4. 超时控制
        const auto effective_timeout = server.timeout_ms > 0 ? server.timeout_ms : timeout_ms_;
        net::steady_timer timer(ioc_);
        auto arm = [&]
        {
            timer.expires_after(std::chrono::milliseconds(effective_timeout));

            auto cancel_token = [sock](boost::system::error_code e)
            {
                if (e != net::error::operation_aborted)
                    sock->cancel();
            };
            timer.async_wait(cancel_token); // 回调方式没有协程的并发执行生命周期问题，直接捕获 shared_ptr 保证安全
        };

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        memory::vector<uint8_t> response_buf(mr_);
        response_buf.resize(512);

        // 5. 发送
        arm();
        co_await sock->async_send_to(net::buffer(packet), target, token);
        timer.cancel();
        if (ec) [[unlikely]]
        {
            result.error = is_timeout(ec) ? fault::code::timeout : fault::code::io_error;
            co_return result;
        }

        // 6. 接收
        arm();
        net::ip::udp::endpoint sender;
        const auto n = co_await sock->async_receive_from(net::buffer(response_buf), sender, token);
        timer.cancel();
        if (!ec)
        {
            response_buf.resize(n);
        }

        sock->close();

        // 计算 RTT
        const auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        result.rtt_ms = static_cast<uint64_t>(rtt);
        result.server_addr = memory::string(server.address, mr_);

        if (ec) [[unlikely]]
        {
            if (is_timeout(ec))
            {
                trace::warn("[Resolve] query to {} timed out ({}ms)", server.address, effective_timeout);
                result.error = fault::code::timeout;
            }
            else
            {
                trace::warn("[Resolve] query to {} recv failed: {}", server.address, ec.message());
                result.error = fault::code::io_error;
            }
            co_return result;
        }

        // 7. 解析响应报文
        auto resp = message::unpack(std::span<const uint8_t>(response_buf.data(), response_buf.size()), mr_);
        if (!resp || resp->id != query.id) [[unlikely]]
        {
            trace::warn("[Resolve] bad response from {}", server.address);
            result.error = fault::code::bad_message;
            co_return result;
        }

        // 8. 检查 TC 标志（截断）— 自动回退 TCP 重试 (RFC 1035 4.2.1)
        if (resp->tc) [[unlikely]]
        {
            trace::debug("[Resolve] truncated response from {}, retrying via TCP", server.address);
            co_return co_await query_tcp(server, query);
        }

        // 9. 检查 RCODE（0 = NoError, 3 = NXDomain 均视为可处理）
        if (resp->rcode != 0 && resp->rcode != 3) [[unlikely]]
        {
            trace::warn("[Resolve] rcode={} from {}", resp->rcode, server.address);
            result.response = std::move(*resp);
            result.error = fault::code::dns_failed;
            co_return result;
        }

        result.response = std::move(*resp);
        result.ips = result.response.extract_ips();
        result.error = fault::code::success;
        co_return result;
    }

    // query_tcp — TCP DNS 查询

    auto resolver::query_tcp(const dns_remote &server, const message &query)
        -> net::awaitable<resolve_result>
    {
        const auto start = std::chrono::steady_clock::now();
        auto result = resolve_result(mr_);

        // 1. 解析目标地址
        boost::system::error_code addr_ec;
        const auto addr = net::ip::make_address(server.address, addr_ec);
        if (addr_ec) [[unlikely]]
        {
            trace::error("[Resolve] invalid server address '{}': {}", server.address, addr_ec.message());
            result.error = fault::code::bad_message;
            co_return result;
        }
        net::ip::tcp::endpoint target(addr, server.port);

        // 2. 创建 TCP 套接字（shared_ptr 确保 timer 回调安全）
        auto sock = std::make_shared<net::ip::tcp::socket>(ioc_);
        const auto effective_timeout = server.timeout_ms > 0 ? server.timeout_ms : timeout_ms_;
        net::steady_timer timer(ioc_);
        auto arm = [&]
        {
            timer.expires_after(std::chrono::milliseconds(effective_timeout));

            auto cancel_token = [sock](boost::system::error_code e)
            {
                if (e != net::error::operation_aborted)
                    sock->cancel();
            };

            timer.async_wait(cancel_token); // 回调方式没有协程的并发执行生命周期问题，直接捕获 shared_ptr 保证安全
        };

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);

        // 3. TCP 连接
        arm();
        co_await sock->async_connect(target, token);
        timer.cancel();
        if (ec) [[unlikely]]
        {
            trace::warn("[Resolve] connect to {}:{} failed: {}", server.address, server.port, ec.message());
            result.error = is_timeout(ec) ? fault::code::timeout : fault::code::io_error;
            co_return result;
        }

        // 4. 构造 TCP 帧: 2 字节大端长度前缀 + DNS 报文
        auto dns_bytes = query.pack();
        const uint16_t payload_len = static_cast<uint16_t>(dns_bytes.size());
        uint8_t frame_header[2];
        frame_header[0] = static_cast<uint8_t>(payload_len >> 8);
        frame_header[1] = static_cast<uint8_t>(payload_len & 0xFF);

        // 5. 发送 TCP 帧（scatter-gather: 长度前缀 + 报文体）
        std::array<net::const_buffer, 2> write_bufs = {net::buffer(frame_header), net::buffer(dns_bytes)};
        arm();
        co_await net::async_write(*sock, write_bufs, token);
        timer.cancel();
        if (ec) [[unlikely]]
        {
            trace::warn("[Resolve] write to {} failed: {}", server.address, ec.message());
            sock->close();
            result.error = is_timeout(ec) ? fault::code::timeout : fault::code::io_error;
            co_return result;
        }

        // 6. 读取 2 字节长度前缀
        arm();
        uint8_t recv_len[2]{};
        co_await net::async_read(*sock, net::buffer(recv_len, 2), token);
        timer.cancel();
        if (ec) [[unlikely]]
        {
            trace::warn("[Resolve] read length prefix from {} failed: {}", server.address, ec.message());
            sock->close();
            result.error = is_timeout(ec) ? fault::code::timeout : fault::code::io_error;
            co_return result;
        }

        const auto resp_len = static_cast<std::size_t>(
            (static_cast<uint16_t>(recv_len[0]) << 8) | recv_len[1]);

        if (resp_len == 0 || resp_len > 65535) [[unlikely]]
        {
            trace::warn("[Resolve] invalid response length {} from {}", resp_len, server.address);
            sock->close();
            result.error = fault::code::bad_message;
            co_return result;
        }

        // 7. 读取响应体
        arm();
        memory::vector<uint8_t> response_buf(mr_);
        response_buf.resize(resp_len);
        co_await net::async_read(*sock, net::buffer(response_buf), token);
        timer.cancel();
        sock->close();

        // 计算 RTT
        const auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        result.rtt_ms = static_cast<uint64_t>(rtt);
        result.server_addr = memory::string(server.address, mr_);

        if (ec) [[unlikely]]
        {
            if (is_timeout(ec))
            {
                trace::warn("[Resolve] read body from {} timed out", server.address);
                result.error = fault::code::timeout;
            }
            else
            {
                trace::warn("[Resolve] read body from {} failed: {}", server.address, ec.message());
                result.error = fault::code::io_error;
            }
            co_return result;
        }

        // 8. 解析响应报文
        auto resp = unpack_tcp(std::span<const uint8_t>(response_buf.data(), response_buf.size()), mr_);
        if (!resp || resp->id != query.id) [[unlikely]]
        {
            trace::warn("[Resolve] bad response from {}", server.address);
            result.error = fault::code::bad_message;
            co_return result;
        }

        // 9. 检查 RCODE
        if (resp->rcode != 0 && resp->rcode != 3) [[unlikely]]
        {
            trace::warn("[Resolve] rcode={} from {}", resp->rcode, server.address);
            result.response = std::move(*resp);
            result.error = fault::code::dns_failed;
            co_return result;
        }

        result.response = std::move(*resp);
        result.ips = result.response.extract_ips();
        result.error = fault::code::success;
        co_return result;
    }

    // query_tls — DNS over TLS 查询

    auto resolver::query_tls(const dns_remote &server, const message &query)
        -> net::awaitable<resolve_result>
    {
        const auto start = std::chrono::steady_clock::now();
        auto result = resolve_result(mr_);

        // 1. 解析目标地址
        boost::system::error_code addr_ec;
        const auto addr = net::ip::make_address(server.address, addr_ec);
        if (addr_ec) [[unlikely]]
        {
            trace::error("[Resolve] invalid server address '{}': {}", server.address, addr_ec.message());
            result.error = fault::code::bad_message;
            co_return result;
        }
        net::ip::tcp::endpoint target(addr, server.port);

        // 2. TCP 连接（shared_ptr 确保 timer 回调安全）
        const auto effective_timeout = server.timeout_ms > 0 ? server.timeout_ms : timeout_ms_;
        net::steady_timer timer(ioc_);

        auto sock = std::make_shared<net::ip::tcp::socket>(ioc_);
        auto arm_sock = [&]
        {
            timer.expires_after(std::chrono::milliseconds(effective_timeout));

            auto cancel_token = [sock](boost::system::error_code e)
            {
                if (e != net::error::operation_aborted)
                    sock->cancel();
            };

            timer.async_wait(cancel_token);
        };

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);

        arm_sock();
        co_await sock->async_connect(target, token);
        timer.cancel();
        if (ec) [[unlikely]]
        {
            trace::warn("[Resolve] TCP connect to {}:{} failed: {}", server.address, server.port, ec.message());
            result.error = is_timeout(ec) ? fault::code::timeout : fault::code::io_error;
            co_return result;
        }

        // 3. 配置 TLS 上下文
        ssl::context ssl_ctx(ssl::context::tls);
        ssl_ctx.set_default_verify_paths();

        if (server.no_check_certificate)
        {
            ssl_ctx.set_verify_mode(ssl::verify_none);
        }
        else
        {
            ssl_ctx.set_verify_mode(ssl::verify_peer);
        }

        // 设置 SNI 主机名
        if (!server.hostname.empty())
        {
            SSL_CTX_set_tlsext_servername_arg(
                ssl_ctx.native_handle(),
                const_cast<char *>(server.hostname.c_str()));
            SSL_CTX_set_tlsext_servername_callback(
                ssl_ctx.native_handle(),
                sni_callback);
        }

        // 4. TLS 握手（shared_ptr 延长 SSL stream 生命周期）
        auto ssl_sock = std::make_shared<ssl::stream<net::ip::tcp::socket>>(std::move(*sock), ssl_ctx);
        auto &ssl = *ssl_sock;

        auto arm_ssl = [&]
        {
            timer.expires_after(std::chrono::milliseconds(effective_timeout));

            auto cancel_token = [ssl_sock](boost::system::error_code e)
            {
                if (e != net::error::operation_aborted)
                    ssl_sock->lowest_layer().cancel();
            };
            timer.async_wait(cancel_token);
        };

        arm_ssl();
        co_await ssl.async_handshake(ssl::stream_base::client, token);
        timer.cancel();
        if (ec) [[unlikely]]
        {
            trace::warn("[Resolve] TLS handshake to {} failed: {}", server.address, ec.message());
            result.error = fault::code::tls_handshake_failed;
            co_return result;
        }

        // 5. 构造 TCP 帧: 2 字节大端长度前缀 + DNS 报文
        auto dns_bytes = query.pack();
        const uint16_t payload_len = static_cast<uint16_t>(dns_bytes.size());
        uint8_t frame_header[2];
        frame_header[0] = static_cast<uint8_t>(payload_len >> 8);
        frame_header[1] = static_cast<uint8_t>(payload_len & 0xFF);

        // 6. 发送 TCP 帧（通过 TLS）
        std::array<net::const_buffer, 2> write_bufs = {net::buffer(frame_header), net::buffer(dns_bytes)};
        arm_ssl();
        co_await net::async_write(ssl, write_bufs, token);
        timer.cancel();
        if (ec) [[unlikely]]
        {
            trace::warn("[Resolve] write to {} failed: {}", server.address, ec.message());
            ssl.lowest_layer().close();
            result.error = is_timeout(ec) ? fault::code::timeout : fault::code::io_error;
            co_return result;
        }

        // 7. 读取 2 字节长度前缀
        arm_ssl();
        uint8_t recv_len[2]{};
        co_await net::async_read(ssl, net::buffer(recv_len, 2), token);
        timer.cancel();
        if (ec) [[unlikely]]
        {
            trace::warn("[Resolve] read length prefix from {} failed: {}", server.address, ec.message());
            ssl.lowest_layer().close();
            result.error = is_timeout(ec) ? fault::code::timeout : fault::code::io_error;
            co_return result;
        }

        const auto resp_len = static_cast<std::size_t>((static_cast<uint16_t>(recv_len[0]) << 8) | recv_len[1]);

        if (resp_len == 0 || resp_len > 65535) [[unlikely]]
        {
            trace::warn("[Resolve] invalid response length {} from {}", resp_len, server.address);
            ssl.lowest_layer().close();
            result.error = fault::code::bad_message;
            co_return result;
        }

        // 8. 读取响应体
        arm_ssl();
        memory::vector<uint8_t> response_buf(mr_);
        response_buf.resize(resp_len);
        co_await net::async_read(ssl, net::buffer(response_buf), token);
        timer.cancel();
        ssl.lowest_layer().close();

        // 计算 RTT
        const auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        result.rtt_ms = static_cast<uint64_t>(rtt);
        result.server_addr = memory::string(server.address, mr_);

        if (ec) [[unlikely]]
        {
            if (is_timeout(ec))
            {
                trace::warn("[Resolve] read body from {} timed out", server.address);
                result.error = fault::code::timeout;
            }
            else
            {
                trace::warn("[Resolve] read body from {} failed: {}", server.address, ec.message());
                result.error = fault::code::io_error;
            }
            co_return result;
        }

        // 9. 解析响应报文
        auto resp = unpack_tcp(std::span<const uint8_t>(response_buf.data(), response_buf.size()), mr_);
        if (!resp || resp->id != query.id) [[unlikely]]
        {
            trace::warn("[Resolve] bad response from {}", server.address);
            result.error = fault::code::bad_message;
            co_return result;
        }

        // 10. 检查 RCODE
        if (resp->rcode != 0 && resp->rcode != 3) [[unlikely]]
        {
            trace::warn("[Resolve] rcode={} from {}", resp->rcode, server.address);
            result.response = std::move(*resp);
            result.error = fault::code::dns_failed;
            co_return result;
        }

        result.response = std::move(*resp);
        result.ips = result.response.extract_ips();
        result.error = fault::code::success;
        co_return result;
    }

    // query_https — DNS over HTTPS 查询

    auto resolver::query_https(const dns_remote &server, const message &query)
        -> net::awaitable<resolve_result>
    {
        const auto start = std::chrono::steady_clock::now();
        auto result = resolve_result(mr_);

        // 1. 解析目标地址
        boost::system::error_code addr_ec;
        const auto addr = net::ip::make_address(server.address, addr_ec);
        if (addr_ec) [[unlikely]]
        {
            trace::error("[Resolve] invalid server address '{}': {}", server.address, addr_ec.message());
            result.error = fault::code::bad_message;
            co_return result;
        }
        net::ip::tcp::endpoint target(addr, server.port);

        // 2. TCP 连接
        const auto effective_timeout = server.timeout_ms > 0 ? server.timeout_ms : timeout_ms_;
        net::steady_timer timer(ioc_);

        auto sock = std::make_shared<net::ip::tcp::socket>(ioc_);
        auto arm_sock = [&]
        {
            timer.expires_after(std::chrono::milliseconds(effective_timeout));

            auto cancel_token = [sock](boost::system::error_code e)
            {
                if (e != net::error::operation_aborted)
                    sock->cancel();
            };
            timer.async_wait(cancel_token);
        };

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);

        arm_sock();
        co_await sock->async_connect(target, token);
        timer.cancel();
        if (ec) [[unlikely]]
        {
            trace::warn("[Resolve] TCP connect to {}:{} failed: {}", server.address, server.port, ec.message());
            result.error = is_timeout(ec) ? fault::code::timeout : fault::code::io_error;
            co_return result;
        }

        // 3. 配置 TLS 上下文
        ssl::context ssl_ctx(ssl::context::tls);
        ssl_ctx.set_default_verify_paths();

        if (server.no_check_certificate)
        {
            ssl_ctx.set_verify_mode(ssl::verify_none);
        }
        else
        {
            ssl_ctx.set_verify_mode(ssl::verify_peer);
        }

        const auto host_header = server.hostname.empty() ? server.address : server.hostname;
        if (!server.hostname.empty())
        {
            SSL_CTX_set_tlsext_servername_arg(
                ssl_ctx.native_handle(),
                const_cast<char *>(server.hostname.c_str()));
            SSL_CTX_set_tlsext_servername_callback(
                ssl_ctx.native_handle(),
                sni_callback);
        }

        // 4. TLS 握手
        auto ssl_sock = std::make_shared<ssl::stream<net::ip::tcp::socket>>(std::move(*sock), ssl_ctx);
        auto &ssl = *ssl_sock;

        auto arm_ssl = [&]
        {
            timer.expires_after(std::chrono::milliseconds(effective_timeout));

            auto cancel_token = [ssl_sock](boost::system::error_code e)
            { 
                if (e != net::error::operation_aborted) 
                    ssl_sock->lowest_layer().cancel(); 
            };
            timer.async_wait(cancel_token);
        };

        arm_ssl();
        co_await ssl.async_handshake(ssl::stream_base::client, token);
        timer.cancel();
        if (ec) [[unlikely]]
        {
            trace::warn("[Resolve] TLS handshake to {} failed: {}", server.address, ec.message());
            result.error = fault::code::tls_handshake_failed;
            co_return result;
        }

        // 5. 构造 HTTP POST 请求 (RFC 8484)
        auto dns_payload = query.pack();
        memory::string http_request(mr_);
        http_request.reserve(256 + dns_payload.size());
        http_request.append("POST ");
        http_request.append(server.http_path);
        http_request.append(" HTTP/1.1\r\n");
        http_request.append("Host: ");
        http_request.append(host_header);
        http_request.append("\r\n");
        http_request.append("Content-Type: application/dns-message\r\n");
        http_request.append("Content-Length: ");
        http_request.append(std::to_string(dns_payload.size()));
        http_request.append("\r\n");
        http_request.append("Accept: application/dns-message\r\n");
        http_request.append("Connection: close\r\n");
        http_request.append("\r\n");

        // 6. 发送 HTTP 请求头 + DNS 报文体
        std::array<net::const_buffer, 2> write_bufs = {net::buffer(http_request), net::buffer(dns_payload)};
        arm_ssl();
        co_await net::async_write(ssl, write_bufs, token);
        timer.cancel();
        if (ec) [[unlikely]]
        {
            trace::warn("[Resolve] write to {} failed: {}", server.address, ec.message());
            ssl.lowest_layer().close();
            result.error = is_timeout(ec) ? fault::code::timeout : fault::code::io_error;
            co_return result;
        }

        // 7. 读取 HTTP 响应头（循环读取直到 "\r\n\r\n"）
        arm_ssl();
        memory::vector<uint8_t> recv_buf(mr_);
        recv_buf.resize(4096);
        memory::string header_data(mr_);
        std::size_t content_length = 0;

        while (header_data.find("\r\n\r\n") == memory::string::npos)
        {
            const auto n = co_await ssl.async_read_some(net::buffer(recv_buf), token);
            if (ec) [[unlikely]]
            {
                break;
            }
            header_data.append(reinterpret_cast<const char *>(recv_buf.data()), n);
            if (header_data.size() > 65536) [[unlikely]]
            {
                ec = boost::system::errc::make_error_code(boost::system::errc::value_too_large);
                break;
            }
        }
        timer.cancel();

        if (ec) [[unlikely]]
        {
            trace::warn("[Resolve] read headers from {} failed: {}", server.address, ec.message());
            ssl.lowest_layer().close();
            result.error = is_timeout(ec) ? fault::code::timeout : fault::code::io_error;
            co_return result;
        }

        // 8. 解析 HTTP 响应头
        const auto header_end = header_data.find("\r\n\r\n");
        if (header_end == memory::string::npos) [[unlikely]]
        {
            trace::warn("[Resolve] malformed response from {}", server.address);
            ssl.lowest_layer().close();
            result.error = fault::code::bad_message;
            co_return result;
        }

        const auto header_view = std::string_view(header_data).substr(0, header_end);

        // 检查 HTTP 状态码（必须为 200）
        if (!header_view.starts_with("HTTP/1.1 200") && !header_view.starts_with("HTTP/1.0 200"))
        {
            const auto line_end = header_view.find("\r\n");
            const auto status_line = header_view.substr(0, line_end != std::string_view::npos ? line_end : header_view.size());
            trace::warn("[Resolve] unexpected HTTP status from {}: {}", server.address, status_line);
            ssl.lowest_layer().close();
            result.error = fault::code::bad_message;
            co_return result;
        }

        // 提取 Content-Length
        const auto cl_key = std::string_view("Content-Length: ");
        const auto cl_pos = header_view.find(cl_key);
        if (cl_pos != std::string_view::npos)
        {
            auto cl_value = header_view.substr(cl_pos + cl_key.size());
            const auto cl_end = cl_value.find("\r\n");
            if (cl_end != std::string_view::npos)
            {
                cl_value = cl_value.substr(0, cl_end);
            }
            content_length = 0;
            for (const auto ch : cl_value)
            {
                if (ch >= '0' && ch <= '9')
                {
                    content_length = content_length * 10 + static_cast<std::size_t>(ch - '0');
                }
                else
                {
                    break;
                }
            }
        }

        // 9. 收集响应体数据
        memory::vector<uint8_t> body_buf(mr_);
        const auto body_start = header_end + 4;
        if (body_start < header_data.size())
        {
            const auto already = header_data.size() - body_start;
            body_buf.resize(already);
            std::memcpy(body_buf.data(), header_data.data() + body_start, already);
        }

        // 按需读取剩余的响应体
        if (body_buf.size() < content_length && content_length > 0)
        {
            const auto remaining = content_length - body_buf.size();
            body_buf.resize(content_length);

            arm_ssl();
            co_await net::async_read(ssl, net::buffer(body_buf.data() + body_buf.size() - remaining, remaining), token);
            timer.cancel();

            if (ec) [[unlikely]]
            {
                trace::warn("[Resolve] read body from {} failed: {}", server.address, ec.message());
                ssl.lowest_layer().close();
                result.error = is_timeout(ec) ? fault::code::timeout : fault::code::io_error;
                co_return result;
            }
        }

        // 10. 关闭连接
        ssl.lowest_layer().close();

        // 计算 RTT
        const auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        result.rtt_ms = static_cast<uint64_t>(rtt);
        result.server_addr = memory::string(server.address, mr_);

        // 11. 解析 DNS 响应报文
        if (body_buf.empty()) [[unlikely]]
        {
            trace::warn("[Resolve] empty response body from {}", server.address);
            result.error = fault::code::bad_message;
            co_return result;
        }

        auto resp = message::unpack(std::span<const uint8_t>(body_buf.data(), body_buf.size()), mr_);
        if (!resp || resp->id != query.id) [[unlikely]]
        {
            trace::warn("[Resolve] bad response from {}", server.address);
            result.error = fault::code::bad_message;
            co_return result;
        }

        // 12. 检查 RCODE
        if (resp->rcode != 0 && resp->rcode != 3) [[unlikely]]
        {
            trace::warn("[Resolve] rcode={} from {}", resp->rcode, server.address);
            result.response = std::move(*resp);
            result.error = fault::code::dns_failed;
            co_return result;
        }

        result.response = std::move(*resp);
        result.ips = result.response.extract_ips();
        result.error = fault::code::success;
        co_return result;
    }

} // namespace ngx::resolve
