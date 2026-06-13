#include <prism/stealth/common.hpp>

#include <prism/proto/protocol/tls/record.hpp>

#include <cstring>

namespace psm::stealth::common
{

    auto read_tls_frame(net::ip::tcp::socket &sock, std::error_code &ec_out,
                            net::steady_timer *deadline)
        -> net::awaitable<std::optional<memory::vector<std::byte>>>
    {
        ec_out.clear();

        // 设置超时定时器：30 秒后关闭 socket
        if (deadline)
        {
            deadline->expires_after(std::chrono::seconds(30));
            auto on_timeout = [&sock](const boost::system::error_code &timer_ec)
            {
                if (!timer_ec)
                {
                    boost::system::error_code ignored;
                    sock.cancel(ignored);
                }
            };
            deadline->async_wait(std::move(on_timeout));
        }

        // 注意：避免使用 structured binding (auto [a, b] = co_await ...)
        // 实测 GCC 16 + Boost.Asio 1.89 awaitable 协程帧内存对齐存在 bug，
        // structured binding 临时对象的 pmr::vector 字段会读到上一轮残留数据，
        // 导致析构时 deallocate 跳转到无效 memory_resource 虚表 → 段错误。
        auto result = co_await tls::record::read(sock);
        const auto &read_ec = result.first;
        const auto &rec = result.second;

        if (deadline)
        {
            deadline->cancel();
        }

        if (fault::failed(read_ec))
        {
            ec_out = std::make_error_code(std::errc::connection_reset);
            co_return std::nullopt;
        }

        co_return rec.serialize();
    }
} // namespace psm::stealth::common
