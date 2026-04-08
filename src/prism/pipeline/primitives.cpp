#include <prism/pipeline/primitives.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/channel/transport/encrypted.hpp>
#include <chrono>
#include <string_view>

constexpr std::string_view SslStr = "[Primitives.SSL]";
constexpr std::string_view DialStr = "[Primitives.Dial]";
constexpr std::string_view TunnelStr = "[Primitives.Tunnel]";

namespace psm::pipeline::primitives
{
    using psm::agent::session_context;
    auto ssl_handshake(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<std::pair<fault::code, shared_ssl_stream>>
    {

        if (!ctx.server.ssl_ctx)
        {
            trace::warn("{} No SSL context configured", SslStr);
            co_return std::make_pair(fault::code::not_supported, nullptr);
        }

        if (!ctx.inbound)
        {
            trace::warn("{} No inbound transmission for TLS handshake", SslStr);
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
            trace::warn("{} TLS handshake failed: {} ({})", SslStr, ec.message(), ec.value());
            co_return std::make_pair(fault::to_code(ec), nullptr);
        }

        trace::debug("{} TLS handshake succeeded", SslStr);
        co_return std::make_pair(fault::code::success, stream);
    }

    // 检查目标地址是否为 IPv6 字面量
    inline bool is_ipv6_literal(const std::string_view host) noexcept
    {
        boost::system::error_code ec;
        const auto addr = net::ip::make_address(host, ec);
        return !ec && addr.is_v6();
    }

    auto dial(std::shared_ptr<resolve::router> router, std::string_view label,
              const protocol::analysis::target &target, const bool allow_reverse, const bool require_open)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        // 拒绝 IPv6 地址字面量（仅在禁用 IPv6 时）
        if (router->ipv6_disabled() && is_ipv6_literal(target.host))
        {
            trace::debug("{} {} rejecting IPv6 literal: {}:{}", DialStr, label, target.host, target.port);
            co_return std::make_pair(fault::code::ipv6_disabled, nullptr);
        }

        // 路由到目标
        fault::code ec;
        channel::pooled_connection conn;
        if (allow_reverse && !target.positive)
        {
            auto result = co_await router->async_reverse(target.host);
            ec = result.first;
            conn = std::move(result.second);
        }
        else
        {
            auto result = co_await router->async_forward(target.host, target.port);
            ec = result.first;
            conn = std::move(result.second);
        }

        if (fault::failed(ec))
        {
            trace::warn("{} {} route failed: {}, target: {}:{}", DialStr, label,
                        fault::describe(ec), target.host, target.port);
            co_return std::make_pair(ec, nullptr);
        }

        if (require_open && !conn.valid())
        {
            trace::warn("{} {} socket not open, target: {}:{}", DialStr, label, target.host, target.port);
            co_return std::make_pair(fault::code::connection_refused, nullptr);
        }

        trace::info("{} {} success, target: {}:{}", DialStr, label, target.host, target.port);
        co_return std::make_pair(ec, channel::transport::make_reliable(std::move(conn)));
    }

    preview::preview(shared_transmission inner, std::span<const std::byte> preread, memory::resource_pointer mr)
        : inner_(std::move(inner)), preread_buffer_(preread.begin(), preread.end(), mr ? mr : memory::current_resource())
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

    auto tunnel(shared_transmission inbound, shared_transmission outbound, const session_context &ctx, const bool complete_write)
        -> net::awaitable<void>
    {
        using trans = shared_transmission;
        // 记录开始时间
        const auto start_time = std::chrono::steady_clock::now();

        // 分配缓冲区
        auto *mr = ctx.frame_arena.get();
        const auto array_size = (std::max)(ctx.buffer_size, 2U);
        memory::vector<std::byte> buffer(array_size, mr ? mr : memory::current_resource());
        // 切割缓冲区为两半，分别用于两个方向的转发
        const auto half = buffer.size() / 2;
        const auto left = std::span(buffer).first(half);
        const auto right = std::span(buffer).last(half);

        // 传输统计：[0] = 上行, [1] = 下行
        std::array<std::size_t, 2> total_bytes{0, 0};

        struct forward_context
        {
            const trans &from;
            const trans &to;
            const std::span<std::byte> scratch;
            const std::size_t idx;
        };

        // 单向转发协程
        auto forward = [complete_write, &total_bytes](forward_context context)
            -> net::awaitable<void>
        {
            std::error_code ec;
            while (true)
            {
                const auto transferred = co_await context.from->async_read_some(context.scratch, ec);
                if (ec || transferred == 0)
                    co_return;

                total_bytes[context.idx] += transferred;

                const auto data = context.scratch.first(transferred);
                std::size_t written;
                if (complete_write)
                {
                    written = co_await context.to->async_write(data, ec);
                }
                else
                {
                    written = co_await context.to->async_write_some(data, ec);
                }

                if (ec || (complete_write && written < transferred))
                    co_return;
            }
        };

        // 并行双向转发，任一方向完成时取消另一方向
        using namespace boost::asio::experimental::awaitable_operators;
        co_await (forward({inbound, outbound, left, 0}) || forward({outbound, inbound, right, 1}));

        // 计算耗时
        const auto end_time = std::chrono::steady_clock::now();

        // 输出传输统计
        if (const auto up = total_bytes[0], down = total_bytes[1]; up > 0 || down > 0)
        {
            trace::info("{} [{}] Transfer: Upload {} B, Download {} B, duration: {} ms", TunnelStr, ctx.session_id, up,
                        down, std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());
        }

        shut_close(inbound);
        shut_close(outbound);
    }
} // namespace psm::pipeline::primitives
