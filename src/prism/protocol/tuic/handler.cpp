/**
 * @file handler.cpp
 * @brief TUIC v5 协议处理器实现
 */

#include <prism/diagnose/diagnose.hpp>
#include <prism/foundation/fault/handling.hpp>
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/connection/tunnel/forward/basic.hpp>
#include <prism/net/connection/tunnel/forward/pipeline.hpp>
#include <prism/net/connection/util.hpp>
#include <prism/protocol/tuic/codec.hpp>
#include <prism/protocol/tuic/handler.hpp>
#include <prism/settings/settings.hpp>

#include <boost/asio/co_spawn.hpp>

#include <charconv>
#include <unordered_map>

using namespace psm::diagnose;

namespace psm::protocol::tuic
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
                diagnose::warn(trace, "tuic: missing inbound");
            }
            co_return;
        }
        res_.inbound = nullptr;

        std::array<std::byte, 4096> buf{};
        std::error_code ec;
        auto total = static_cast<std::size_t>(0);
        if (!data_.empty())
        {
            std::memcpy(buf.data(), data_.data(), std::min(buf.size(), data_.size()));
            total = std::min(buf.size(), data_.size());
        }

        // 循环读取直到取得完整 Connect 帧（可能含 preread 首字节）
        psm::protocol::tuic::connect_frame req;
        std::size_t frame_len = 0;
        while (true)
        {
            if (parse_connect(
                    std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(buf.data()), total),
                    req, frame_len))
            {
                break;
            }
            if (total >= buf.size())
            {
                if (trace)
                {
                    diagnose::warn(trace, "tuic: oversized connect frame");
                }
                co_return;
            }
            const auto n = co_await inbound->async_read_some(
                std::span<std::byte>(buf.data() + total, buf.size() - total), ec);
            if (ec || n == 0)
            {
                if (trace)
                {
                    diagnose::warn(trace, "tuic: short connect frame");
                }
                co_return;
            }
            total += n;
        }

        psm::connect::target target(res_.arena.get());
        target.host = psm::protocol::common::addr_to_str(req.destination, res_.arena.get());
        char port_buf[8];
        const auto [pe, pec] =
            std::to_chars(port_buf, port_buf + sizeof(port_buf), static_cast<std::uint32_t>(req.port));
        target.port.assign(port_buf, std::distance(port_buf, pe));
        target.positive = true;
        if (trace)
        {
            diagnose::access(trace, "tuic CONNECT -> {}:{}", target.host, target.port);
        }

        // 剥掉 Connect 帧头：仅转发载荷，避免帧头泄漏到上游
        auto wrapped = psm::transport::wrap_with_preview(
            std::move(inbound), std::span<const std::byte>(buf.data() + frame_len, total - frame_len));
        co_await psm::connect::forward_pipeline(res_, target,
                                                psm::connect::pipeline_options{std::move(wrapped), trace});
    }

    udp_handler::udp_handler(protocol::handler_params params) : res_(params.res), data_(params.data)
    {
    }

    auto udp_handler::run() -> net::awaitable<void>
    {
        auto trace = res_.trace;
        auto inbound = res_.inbound;
        if (!inbound)
        {
            if (trace)
            {
                diagnose::warn(trace, "tuic: missing udp channel");
            }
            co_return;
        }
        res_.inbound = nullptr;

        auto route = res_.worker->outbound->make_router();
        std::unordered_map<std::uint16_t, std::shared_ptr<udp::socket>> sockets;

        // 客户端 → 服务器：Packet 帧解析 → UDP 发送
        while (true)
        {
            std::array<std::byte, 65536> buf{};
            std::error_code ec;
            const auto n = co_await inbound->async_read_some(std::span<std::byte>(buf), ec);
            if (ec || n == 0)
            {
                break;
            }

            std::size_t offset = 0;
            while (offset + 2 <= n)
            {
                const auto *fp = reinterpret_cast<const std::uint8_t *>(buf.data() + offset);
                const auto remaining = n - offset;
                // VER TYPE
                if (fp[0] != version || fp[1] != static_cast<std::uint8_t>(command::packet))
                {
                    break;
                }
                offset += 2;
                if (remaining < 2 + 2 + 2 + 1 + 1 + 2)
                {
                    break;
                }

                const auto assoc_id = static_cast<std::uint16_t>((fp[2] << 8) | fp[3]);
                const auto pkt_id = static_cast<std::uint16_t>((fp[4] << 8) | fp[5]);
                (void)pkt_id;
                const auto frag_total = fp[6];
                const auto frag_id = fp[7];
                const auto size = static_cast<std::uint16_t>((fp[8] << 8) | fp[9]);
                offset += 8;
                if (frag_total != 1 || frag_id != 0)
                {
                    // 不支持分片，丢弃该包
                    offset += static_cast<std::size_t>(size) + 4;
                    continue;
                }

                // fp[10]=ATYP fp[11..]=ADDR
                const auto atyp = fp[10];
                std::size_t addr_start = 11;
                std::size_t addr_data_len = 0;
                if (atyp == static_cast<std::uint8_t>(address_type::domain))
                {
                    addr_data_len = fp[11];
                    addr_start = 12;
                }
                else if (atyp == static_cast<std::uint8_t>(address_type::ipv4))
                {
                    addr_data_len = 4;
                }
                else if (atyp == static_cast<std::uint8_t>(address_type::ipv6))
                {
                    addr_data_len = 16;
                }
                else
                {
                    break;
                }
                offset += 2;
                if (remaining < offset + addr_data_len + 2 + static_cast<std::size_t>(size))
                {
                    break;
                }

                std::string host;
                if (atyp == static_cast<std::uint8_t>(address_type::domain))
                {
                    host.assign(reinterpret_cast<const char *>(fp + addr_start), addr_data_len);
                }
                else if (atyp == static_cast<std::uint8_t>(address_type::ipv4))
                {
                    net::ip::address_v4::bytes_type bytes{};
                    std::memcpy(bytes.data(), fp + addr_start, 4);
                    host = net::ip::address_v4(bytes).to_string();
                }
                else
                {
                    std::array<std::uint8_t, 16> bytes{};
                    std::memcpy(bytes.data(), fp + addr_start, 16);
                    host = net::ip::address_v6(bytes).to_string();
                }
                const auto port = static_cast<std::uint16_t>((fp[addr_start + addr_data_len] << 8) |
                                                             fp[addr_start + addr_data_len + 1]);
                offset += addr_data_len + 2;
                const auto *data = fp + addr_start + addr_data_len + 2;
                offset += static_cast<std::size_t>(size);

                auto [r_ec, target_ep] = co_await route(host, std::to_string(port));
                if (fault::failed(r_ec))
                {
                    continue;
                }

                auto it = sockets.find(assoc_id);
                if (it == sockets.end())
                {
                    auto usock =
                        std::make_shared<udp::socket>(inbound->executor(), udp::endpoint(udp::v4(), 0));
                    // 回包协程：assoc_id 的 UDP 回包 → 组 Packet 帧 → 写流
                    auto sid = assoc_id;
                    auto chan = inbound;
                    net::co_spawn(
                        inbound->executor(),
                        [chan, usock, sid]() -> net::awaitable<void>
                        {
                            std::array<std::byte, 65536> rbuf{};
                            udp::endpoint from;
                            while (true)
                            {
                                boost::system::error_code rec;
                                const auto rn = co_await usock->async_receive_from(
                                    net::buffer(rbuf.data(), rbuf.size()), from,
                                    net::redirect_error(net::use_awaitable, rec));
                                if (rec)
                                {
                                    break;
                                }

                                // VER TYPE ASSOC_ID PKT_ID FRAG_TOTAL FRAG_ID SIZE ATYP(0xFF) DATA
                                const auto rdata = static_cast<std::size_t>(rn);
                                std::array<std::byte, 70000> hdr{};
                                auto *hp = reinterpret_cast<std::uint8_t *>(hdr.data());
                                hp[0] = version;
                                hp[1] = static_cast<std::uint8_t>(command::packet);
                                hp[2] = static_cast<std::uint8_t>(sid >> 8);
                                hp[3] = static_cast<std::uint8_t>(sid & 0xFF);
                                hp[4] = 0;
                                hp[5] = 0;
                                hp[6] = 1;
                                hp[7] = 0;
                                hp[8] = static_cast<std::uint8_t>(rdata >> 8);
                                hp[9] = static_cast<std::uint8_t>(rdata & 0xFF);
                                hp[10] = static_cast<std::uint8_t>(address_type::none);
                                hp[11] = 0;
                                hp[12] = 0;
                                std::memcpy(hp + 13, rbuf.data(), rdata);
                                std::error_code wr;
                                co_await chan->async_write_some(
                                    std::span<const std::byte>(hdr.data(), 13 + rdata), wr);
                                if (wr)
                                {
                                    break;
                                }
                            }
                        },
                        net::detached);
                    it = sockets.emplace(assoc_id, usock).first;
                }

                boost::system::error_code sec;
                co_await it->second->async_send_to(net::buffer(data, static_cast<std::size_t>(size)),
                                                   target_ep, net::redirect_error(net::use_awaitable, sec));
            }
        }

        for (auto &[id, s] : sockets)
        {
            (void)id;
            boost::system::error_code cec;
            s->close(cec);
        }
    }

} // namespace psm::protocol::tuic
