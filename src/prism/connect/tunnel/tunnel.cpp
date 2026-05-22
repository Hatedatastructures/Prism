#include <prism/connect/tunnel/tunnel.hpp>
#include <prism/connect/util.hpp>
#include <prism/memory/container.hpp>
#include <prism/memory/pool.hpp>
#include <prism/trace.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <array>
#include <chrono>

constexpr std::string_view TunnelStr = "[Connect.Tunnel]";

namespace psm::connect
{
    auto tunnel(shared_transmission inbound, shared_transmission outbound, const context::session &ctx, const bool complete_write)
        -> net::awaitable<void>
    {
        using trans = shared_transmission;
        const auto start_time = std::chrono::steady_clock::now();

        auto *mr = memory::system::thread_local_pool();
        const auto array_size = (std::max)(ctx.buffer_size, 2U);
        memory::vector<std::byte> buffer(array_size, mr ? mr : memory::current_resource());
        const auto half = buffer.size() / 2;
        const auto left = std::span(buffer).first(half);
        const auto right = std::span(buffer).last(half);

        std::array<std::size_t, 2> total_bytes{0, 0};

        struct forward_context
        {
            const trans &from;
            const trans &to;
            const std::span<std::byte> scratch;
            const std::size_t idx;
        };

        auto forward_data = [complete_write, &total_bytes](forward_context context)
            -> net::awaitable<void>
        {
            const bool is_download = (context.idx == 1);
            trace::debug("{} forward[{}]: started, complete_write={}",
                        TunnelStr, is_download ? "download" : "upload", complete_write);

            std::error_code ec;
            while (true)
            {
                const auto transferred = co_await context.from->async_read_some(context.scratch, ec);
                if (ec || transferred == 0)
                {
                    trace::debug("{} forward[{}]: read done, transferred={}, ec={}",
                                TunnelStr, is_download ? "download" : "upload", transferred, ec.message());
                    co_return;
                }

                total_bytes[context.idx] += transferred;
                trace::debug("{} forward[{}]: read {} bytes, total now {}",
                            TunnelStr, is_download ? "download" : "upload", transferred, total_bytes[context.idx]);

                const auto data = context.scratch.first(transferred);
                std::size_t written;
                if (complete_write)
                {
                    trace::debug("{} forward[{}]: calling async_write({} bytes)",
                                TunnelStr, is_download ? "download" : "upload", data.size());
                    written = co_await context.to->async_write(data, ec);
                    trace::debug("{} forward[{}]: async_write returned written={}, ec={}",
                                TunnelStr, is_download ? "download" : "upload", written, ec.message());
                }
                else
                {
                    written = co_await context.to->async_write_some(data, ec);
                }

                if (ec || (complete_write && written < transferred))
                {
                    trace::debug("{} forward[{}]: write done/failed, written={}, expected={}",
                                TunnelStr, is_download ? "download" : "upload", written, transferred);
                    co_return;
                }
            }
        };

        using namespace boost::asio::experimental::awaitable_operators;
        co_await (forward_data({inbound, outbound, left, 0}) || forward_data({outbound, inbound, right, 1}));

        const auto end_time = std::chrono::steady_clock::now();
        if (const auto up = total_bytes[0], down = total_bytes[1]; up > 0 || down > 0)
        {
            trace::info("{} [{}] Transfer: Upload {} B, Download {} B, duration: {} ms", TunnelStr, ctx.session_id, up,
                        down, std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());
        }

        shut_close(inbound);
        shut_close(outbound);
    }

} // namespace psm::connect
