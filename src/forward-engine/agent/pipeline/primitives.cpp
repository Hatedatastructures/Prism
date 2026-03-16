#include <forward-engine/agent/pipeline/primitives.hpp>
#include <forward-engine/transport/reliable.hpp>
#include <forward-engine/transport/secure.hpp>

namespace ngx::agent::pipeline::primitives
{
    auto ssl_handshake(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<std::pair<gist::code, shared_ssl_stream>>
    {
        if (!ctx.server.ssl_ctx)
        {
            trace::error("[Primitives] TLS handshake failed: SSL context is null");
            co_return std::make_pair(gist::code::not_supported, nullptr);
        }

        if (!ctx.inbound)
        {   // 入站指针为空
            trace::error("[Primitives] TLS handshake failed: inbound transmission is null");
            co_return std::make_pair(gist::code::io_error, nullptr);
        }
        // 原有可能是 tcp socket 派生的 reliable 类，用 ssl_connector 来模拟一个 boost 库的 网路 io 接口
        ssl_connector connector(std::move(ctx.inbound), data); // 套用适配器抹平差异
        // 从 boost 库架构来看就是 tcp 上加一层 ssl
        // 从我的架构来看就是封装底层 socket 的 tcp(继承 transmission 的 reliable 需要来抹平 tcp 与 udp 差别）
        // 在套上一层适配器接口层来模拟 boost 库的网络 io 接口(connector),然后在套上 ssl 层，在创建共享智能指针
        auto stream = std::make_shared<ssl_stream>(std::move(connector), *ctx.server.ssl_ctx);

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        co_await stream->async_handshake(ssl::stream_base::server, token);
        if (ec)
        {
            trace::warn("[Primitives] TLS handshake failed: {}", ec.message());
            co_return std::make_pair(gist::to_code(ec), nullptr);
        }

        trace::debug("[Primitives] TLS handshake completed successfully");
        co_return std::make_pair(gist::code::success, stream);
    }

    auto dial(std::shared_ptr<distribution::router> router, std::string_view label,
              const protocol::analysis::target &target, const bool allow_reverse, const bool require_open)
        -> net::awaitable<std::pair<gist::code, transport::transmission_pointer>>
    {
        trace::debug("[Pipeline] {} dialing upstream: {}:{}", label, target.host, target.port);

        auto ec = gist::code::success;
        transport::unique_sock socket;

        if (allow_reverse && !target.positive)
        {   // 允许使用反向代码并且解析到的目标地址支持反向代理
            auto [route_ec, routed] = co_await router->async_reverse(target.host);
            ec = route_ec;
            socket = std::move(routed);
        }
        else
        {
            auto [route_ec, routed] = co_await router->async_forward(target.host, target.port);
            ec = route_ec;
            socket = std::move(routed);
        }

        if (gist::failed(ec))
        {
            trace::warn("[Pipeline] {} route failed: {}, target: {}:{}", label, gist::describe(ec),
             target.host, target.port);
            co_return std::make_pair(ec, nullptr);
        }

        if (require_open && (!socket || !socket->is_open()))
        {
            trace::error("[Pipeline] {} route to upstream failed (connection invalid).", label);
            co_return std::make_pair(gist::code::connection_refused, nullptr);
        }

        trace::debug("[Pipeline] {} upstream connected: {}:{}", label, target.host, target.port);
        co_return std::make_pair(ec, transport::make_reliable(std::move(*socket)));
    }

    preview::preview(transport::transmission_pointer inner, std::span<const std::byte> preread)
        : inner_(std::move(inner)), preread_buffer_(preread.begin(), preread.end(), memory::current_resource())
    {
    }

    bool preview::is_reliable() const noexcept
    {
        return inner_ && inner_->is_reliable();
    }

    auto preview::executor() const -> executor_type
    {
        if (!inner_)
        {
            trace::error("[Preview] executor called with null inner transmission");
            throw std::runtime_error("preview::executor called with null inner transmission");
        }
        return inner_->executor();
    }

    auto preview::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (offset_ < preread_buffer_.size())
        {
            const auto remaining = preread_buffer_.size() - offset_;
            const auto to_copy = (std::min)(remaining, buffer.size());
            if (to_copy > 0)
            {
                std::memcpy(buffer.data(), preread_buffer_.data() + offset_, to_copy);
                offset_ += to_copy;
            }
            ec.clear();
            co_return to_copy;
        }

        if (!inner_)
        {
            ec = std::make_error_code(std::errc::bad_file_descriptor);
            co_return 0;
        }

        co_return co_await inner_->async_read_some(buffer, ec);
    }

    auto preview::async_write_some(const std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (!inner_)
        {
            ec = std::make_error_code(std::errc::bad_file_descriptor);
            co_return 0;
        }
        co_return co_await inner_->async_write_some(buffer, ec);
    }

    void preview::close()
    {
        if (inner_)
        {
            inner_->close();
        }
    }

    void preview::cancel()
    {
        if (inner_)
        {
            inner_->cancel();
        }
    }
} // namespace ngx::agent::pipeline::primitives
