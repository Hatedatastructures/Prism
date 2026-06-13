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

        auto [read_ec, rec] = co_await tls::record::read(sock);

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
