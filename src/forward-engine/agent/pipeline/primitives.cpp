#include <forward-engine/agent/pipeline/primitives.hpp>
#include <forward-engine/channel/transport/reliable.hpp>
#include <forward-engine/channel/transport/secure.hpp>
#include <forward-engine/trace.hpp>

namespace ngx::agent::pipeline::primitives
{
    auto ssl_handshake(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<std::pair<fault::code, shared_ssl_stream>>
    {
        if (!ctx.server.ssl_ctx)
        {
            co_return std::make_pair(fault::code::not_supported, nullptr);
        }

        if (!ctx.inbound)
        {
            co_return std::make_pair(fault::code::io_error, nullptr);
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
            co_return std::make_pair(fault::to_code(ec), nullptr);
        }

        co_return std::make_pair(fault::code::success, stream);
    }

    auto dial(std::shared_ptr<resolve::router> router, std::string_view label,
              const protocol::analysis::target &target, const bool allow_reverse, const bool require_open)
        -> net::awaitable<std::pair<fault::code, channel::transport::transmission_pointer>>
    {
        auto ec = fault::code::success;
        channel::unique_sock socket;

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

        if (fault::failed(ec))
        {
            trace::warn("[Pipeline] {} route failed: {}, target: {}:{}", label, fault::describe(ec),
             target.host, target.port);
            co_return std::make_pair(ec, nullptr);
        }

        if (require_open && (!socket || !socket->is_open()))
        {
            co_return std::make_pair(fault::code::connection_refused, nullptr);
        }

        co_return std::make_pair(ec, channel::transport::make_reliable(std::move(socket)));
    }

    preview::preview(channel::transport::transmission_pointer inner, std::span<const std::byte> preread)
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
