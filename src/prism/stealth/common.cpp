#include <prism/stealth/common.hpp>

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

        // 读取 5 字节 TLS 记录头
        boost::system::error_code ec;
        std::array<std::byte, 5> header{};
        auto header_n = co_await net::async_read(
            sock, net::buffer(header.data(), 5),
            net::redirect_error(net::use_awaitable, ec));

        if (ec)
        {
            if (deadline)
            {
                deadline->cancel();
            }
            ec_out = ec;
            co_return std::nullopt;
        }

        // safe: casting byte buffer to uint8_t to parse TLS record header fields
        const auto *raw = reinterpret_cast<const std::uint8_t *>(header.data());
        const std::uint16_t record_length = (static_cast<std::uint16_t>(raw[3]) << 8) | raw[4];

        // 分配 header + payload 完整帧
        memory::vector<std::byte> frame(5 + record_length);
        std::memcpy(frame.data(), header.data(), 5);

        if (record_length > 0)
        {
            auto payload = std::span<std::byte>(frame.data() + 5, record_length);
            auto payload_n = co_await net::async_read(
                sock, net::buffer(payload.data(), payload.size()),
                net::redirect_error(net::use_awaitable, ec));

            if (ec)
            {
                if (deadline)
                {
                    deadline->cancel();
                }
                ec_out = ec;
                co_return std::nullopt;
            }
        }

        if (deadline)
        {
            deadline->cancel();
        }

        co_return frame;
    }
} // namespace psm::stealth::common
