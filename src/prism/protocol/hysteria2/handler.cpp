/**
 * @file handler.cpp
 * @brief Hysteria2 协议处理器实现
 */

#include <prism/diagnose/diagnose.hpp>
#include <prism/foundation/fault/handling.hpp>
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/connection/tunnel/forward/basic.hpp>
#include <prism/net/connection/tunnel/forward/pipeline.hpp>
#include <prism/net/connection/util.hpp>
#include <prism/protocol/hysteria2/codec.hpp>
#include <prism/protocol/hysteria2/handler.hpp>
#include <prism/settings/settings.hpp>

#include <boost/asio/co_spawn.hpp>

#include <charconv>

using namespace psm::diagnose;

namespace psm::protocol::hysteria2
{

    namespace net = boost::asio;
    using udp = net::ip::udp;

    handler::handler(protocol::handler_params params) : res_(params.res), data_(params.data)
    {
    }

    auto handler::run() -> net::awaitable<void>
    {
        auto trace = res_.trace;
        auto inbound = res_.inbound;
        if (!inbound)
        {
            if (trace)
            {
                diagnose::warn(trace, "hysteria2: missing inbound");
            }
            co_return;
        }
        res_.inbound = nullptr;

        // 读取首帧判定 TCP / UDP
        std::array<std::byte, 4096> buf{};
        std::error_code ec;
        auto total = static_cast<std::size_t>(0);
        if (!data_.empty())
        {
            std::memcpy(buf.data(), data_.data(), std::min(buf.size(), data_.size()));
            total = std::min(buf.size(), data_.size());
        }
        else
        {
            total = co_await inbound->async_read_some(std::span<std::byte>(buf), ec);
            if (ec || total == 0)
            {
                co_return;
            }
        }

        std::uint64_t frame_type = 0;
        const auto off = decode_varint(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(buf.data()), total),
            frame_type);

        // TCP 请求帧（0x401）
        if (off != 0 && frame_type == frame_type_tcp)
        {
            psm::protocol::hysteria2::tcp_request req;
            std::size_t payload_offset = 0;
            if (!parse_tcp_request(
                    std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(buf.data()), total),
                    req, payload_offset))
            {
                if (trace)
                {
                    diagnose::warn(trace, "hysteria2: bad tcp frame");
                }
                co_return;
            }

            psm::connect::target target(res_.arena.get());
            const auto colon = req.address.find_last_of(':');
            if (colon == memory::string::npos)
            {
                co_return;
            }
            target.host.assign(req.address.data(), colon);
            target.port.assign(req.address.data() + colon + 1, req.address.size() - colon - 1);
            target.positive = true;
            if (trace)
            {
                diagnose::access(trace, "hysteria2 CONNECT -> {}", req.address);
            }

            // hysteria2 协议：服务器必须先回 TCP 响应帧（同一流上），随后才是数据。
            // 格式：[status 1B=0 成功][message len varint=0][padding len varint=0]
            std::array<std::byte, 3> tcp_resp{std::byte{0}, std::byte{0}, std::byte{0}};
            std::error_code resp_ec;
            co_await transport::async_write(*inbound, tcp_resp, resp_ec);
            if (resp_ec)
            {
                co_return;
            }

            // 剥掉 CONNECT 帧头：仅转发载荷，避免帧头泄漏到上游
            auto wrapped = psm::transport::wrap_with_preview(
                std::move(inbound),
                std::span<const std::byte>(buf.data() + payload_offset, total - payload_offset));
            res_.inbound = nullptr;
            co_await psm::connect::forward_pipeline(
                res_, target, psm::connect::pipeline_options{std::move(wrapped), trace});
            co_return;
        }

        // UDP 消息流
        co_await handle_udp(std::move(inbound), std::span<const std::byte>(buf.data(), total));
    }

    auto handler::handle_udp(psm::transport::shared_transmission inbound,
                             const std::span<const std::byte> head) -> net::awaitable<void>
    {
        auto trace = res_.trace;
        auto route = res_.worker->outbound->make_router();

        // UDP 收发协程共用：堆分配防 detached 协程悬垂
        auto usock = std::make_shared<udp::socket>(inbound->executor(), udp::endpoint(udp::v4(), 0));

        // 首帧解析（head 里可能已有数据）
        auto pending = psm::memory::vector<std::byte>(head.begin(), head.end(), res_.arena.get());
        auto session_id = std::make_shared<std::atomic<std::uint32_t>>(0);

        // UDP 接收协程：UDP socket → 组消息 → 写回流（值捕获 usock/session_id 保活）
        net::co_spawn(
            inbound->executor(),
            [inbound, usock, session_id]() -> net::awaitable<void>
            {
                std::array<std::byte, 4096> rbuf{};
                udp::endpoint from;
                while (true)
                {
                    boost::system::error_code rec;
                    const auto n =
                        co_await usock->async_receive_from(net::buffer(rbuf.data(), rbuf.size()), from,
                                                           net::redirect_error(net::use_awaitable, rec));
                    if (rec)
                    {
                        break;
                    }

                    // 组装 UDP 消息：SessionID(4) PacketID(2) FragID(1) FragCount(1) AddrLen(varint) Addr Data
                    std::array<std::byte, 512> hdr{};
                    auto *hp = reinterpret_cast<std::uint8_t *>(hdr.data());
                    std::size_t hl = 0;
                    const auto host_str = from.address().to_string();
                    const auto port_str = std::to_string(from.port());
                    const auto addr = host_str + ":" + port_str;
                    const auto sid = session_id->load(std::memory_order_relaxed);

                    hp[hl++] = static_cast<std::uint8_t>((sid >> 24) & 0xFF);
                    hp[hl++] = static_cast<std::uint8_t>((sid >> 16) & 0xFF);
                    hp[hl++] = static_cast<std::uint8_t>((sid >> 8) & 0xFF);
                    hp[hl++] = static_cast<std::uint8_t>(sid & 0xFF);
                    hp[hl++] = 0;
                    hp[hl++] = 0;
                    hp[hl++] = 0;
                    hp[hl++] = 1;
                    std::array<std::uint8_t, 8> len_buf{};
                    const auto len_n = encode_varint(static_cast<std::uint64_t>(addr.size()), len_buf);
                    std::memcpy(hp + hl, len_buf.data(), len_n);
                    hl += len_n;
                    std::memcpy(hp + hl, addr.data(), addr.size());
                    hl += addr.size();

                    std::error_code wr;
                    co_await inbound->async_write_some(std::span<const std::byte>(hdr.data(), hl), wr);
                    if (wr)
                    {
                        break;
                    }
                    co_await inbound->async_write_some(std::span<const std::byte>(rbuf.data(), n), wr);
                    if (wr)
                    {
                        break;
                    }
                }
            },
            net::detached);

        // UDP 发送循环：流 → 解析 → 路由 → UDP 发送
        while (true)
        {
            if (pending.empty())
            {
                std::array<std::byte, 4096> ibuf{};
                std::error_code iec;
                const auto n = co_await inbound->async_read_some(std::span<std::byte>(ibuf), iec);
                if (iec || n == 0)
                {
                    break;
                }
                pending.assign(ibuf.data(), ibuf.data() + n);
            }

            psm::protocol::hysteria2::udp_message msg;
            if (!parse_udp_message(
                    std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(pending.data()),
                                                  pending.size()),
                    msg))
            {
                pending.clear();
                continue;
            }
            session_id->store(msg.session_id, std::memory_order_relaxed);
            pending.erase(pending.begin(),
                          pending.begin() + static_cast<std::ptrdiff_t>(msg.data_offset + msg.data_len));

            const auto colon = msg.address.find_last_of(':');
            if (colon == memory::string::npos)
            {
                continue;
            }
            const std::string_view host(msg.address.data(), colon);
            const std::string_view port(msg.address.data() + colon + 1, msg.address.size() - colon - 1);
            auto [r_ec, target_ep] = co_await route(host, port);
            if (fault::failed(r_ec))
            {
                continue;
            }

            boost::system::error_code sec;
            co_await usock->async_send_to(net::buffer(pending.data() + msg.data_offset, msg.data_len),
                                          target_ep, net::redirect_error(net::use_awaitable, sec));
        }

        boost::system::error_code cec;
        usock->close(cec);
    }

} // namespace psm::protocol::hysteria2
