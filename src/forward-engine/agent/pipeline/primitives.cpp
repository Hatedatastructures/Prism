#include <forward-engine/agent/pipeline/primitives.hpp>
#include <forward-engine/transport/reliable.hpp>

namespace ngx::agent::pipeline::primitives
{
    auto dial(std::shared_ptr<distribution::router> router, std::string_view label,
              const protocol::analysis::target &target, const bool allow_reverse,
              const bool require_open)
        -> net::awaitable<std::pair<gist::code, transport::transmission_pointer>>
    {
        auto ec = gist::code::success;
        transport::unique_sock socket;

        if (allow_reverse && !target.positive)
        {
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
            trace::warn("[Pipeline] {} route failed: {}", label, gist::describe(ec));
            co_return std::make_pair(ec, nullptr);
        }

        if (require_open && (!socket || !socket->is_open()))
        {
            trace::error("[Pipeline] {} route to upstream failed (connection invalid).", label);
            co_return std::make_pair(gist::code::connection_refused, nullptr);
        }

        trace::debug("[Pipeline] {} upstream connected.", label);
        co_return std::make_pair(ec, transport::make_reliable(std::move(*socket)));
    }

    preview::preview(transport::transmission_pointer inner, std::span<const std::byte> preread)
        : inner_(std::move(inner)), preread_(preread)
    {
    }

    bool preview::is_reliable() const noexcept
    {
        return inner_ && inner_->is_reliable();
    }

    auto preview::executor() const -> executor_type
    {
        return inner_->executor();
    }

    auto preview::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (offset_ < preread_.size())
        {
            const auto remaining = preread_.size() - offset_;
            const auto to_copy = (std::min)(remaining, buffer.size());
            if (to_copy > 0)
            {
                std::memcpy(buffer.data(), preread_.data() + offset_, to_copy);
                offset_ += to_copy;
            }
            ec.clear();
            co_return to_copy;
        }

        co_return co_await inner_->async_read_some(buffer, ec);
    }

    auto preview::async_write_some(const std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
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
