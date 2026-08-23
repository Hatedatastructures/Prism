/**
 * @file udp_tunnel.hpp
 * @brief VLESS UDP 命令服务端数据面（UDP over 流，对齐生产 frame_loop 模型）
 * @details TCP 流上承载 UDP 帧：[ATYP 1B][ADDR var][PORT 2B BE][payload]
 *          - 帧循环：读流一帧 → 解析目标 → 真实 UDP socket 转发 →
 *            收上游回包 → 封帧写回流
 *          - 空闲超时（idle_timeout）关闭隧道
 *          - 流 EOF/错误（客户端断开）同步终止
 * @note 对齐生产端 protocol::common::frame_loop（Trojan/VLESS 共用）；
 *       帧无长度字段，单帧单次读约定（一次 write 一帧）。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <common/core/error.hpp>
#include <common/core/middleware/context.hpp>
#include <common/protocols/vless/codec.hpp>
#include <common/protocols/vless/conn.hpp>
#include <common/protocols/vless/types.hpp>

namespace preview::vless
{

    namespace net = boost::asio;

    /**
     * @struct udp_tunnel_options
     * @brief UDP 隧道选项
     */
    struct udp_tunnel_options
    {
        /// 空闲超时（0 = 禁用回收）
        std::chrono::milliseconds idle_timeout{std::chrono::seconds(60)};
        /// 目标解析回调：vless 地址 → UDP 端点（nullptr = 按 IP/域名直解）
        std::function<net::awaitable<std::pair<error, net::ip::udp::endpoint>>(
            const address &)>
            resolve{};
        /// 流量统计 sink（数据面退出时上报；nullptr = 不统计）
        preview::middleware::context::traffic_sink *traffic{nullptr};
        /// 统计身份（与 traffic 配套；对齐 relay 上报口径）
        std::string identity{};
    };

    /**
     * @class udp_tunnel
     * @brief VLESS UDP 命令数据面（服务端）
     * @details 持有已握手的流连接；帧循环在流上读取 UDP 帧并
     *          经真实 UDP socket 转发到目标，回包封帧写回流。
     *          空闲超时与流 EOF 双重守护，任一触发即关闭全部资源。
     */
    class udp_tunnel : public std::enable_shared_from_this<udp_tunnel>
    {
    public:
        /**
         * @brief 构造
         * @param stream 已握手的 VLESS 流连接（所有权移交）
         * @param opts 隧道选项
         */
        explicit udp_tunnel(std::shared_ptr<conn<>> stream, udp_tunnel_options opts)
            : stream_(std::move(stream)), opts_(std::move(opts)), egress_(stream_->executor())
        {
        }

        /**
         * @brief 运行数据面（帧循环直至空闲超时或流 EOF）
         * @return 无（结束后所有资源已关闭）
         * @details 协程内自捕获 shared_from_this 保持对象存活，
         *          允许 detached 派发；任一退出路径统一走 close() 收口。
         */
        [[nodiscard]] auto run() -> net::awaitable<void>
        {
            auto self = shared_from_this();
            net::steady_timer idle(stream_->executor());
            // 大缓冲堆分配，避免协程帧膨胀与逐轮零初始化
            std::vector<std::byte> rx(65535);
            std::vector<std::byte> up(65535);
            std::vector<std::uint8_t> tx;
            // 流量口径对齐 relay：up = 客户端→上游载荷，down = 上游→客户端载荷
            std::size_t sent_bytes = 0;
            std::size_t recv_bytes = 0;
            while (true)
            {
                std::error_code r_ec;
                const auto rx_span = std::span<std::byte>(rx);
                auto read = stream_->async_read_some(rx_span, r_ec);
                std::size_t n = 0;
                if (opts_.idle_timeout.count() > 0)
                {
                    idle.expires_after(opts_.idle_timeout);
                    using boost::asio::experimental::awaitable_operators::operator||;
                    auto result = co_await (std::move(read) || idle.async_wait(net::use_awaitable));
                    if (result.index() == 1)
                    {
                        break; // 空闲超时
                    }
                    n = std::get<0>(std::move(result));
                }
                else
                {
                    n = co_await std::move(read); // 0 = 禁用回收
                }
                if (r_ec)
                {
                    break;
                }
                idle.cancel();
                if (n == 0)
                {
                    break; // 流 EOF
                }

                // 解帧：ATYP + ADDR + PORT + payload（帧无长度字段）
                address target;
                std::span<const std::uint8_t> payload;
                const auto p_err = parse_udp_pkt(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(rx.data()), n),
                    target, payload);
                if (p_err != error::none)
                {
                    continue; // 非法帧丢弃（对齐生产端语义）
                }

                // 目标解析 → 转发载荷
                auto target_ep = co_await resolve_target(target);
                if (target_ep.first != error::none)
                {
                    continue;
                }
                boost::system::error_code w_ec;
                if (!egress_.is_open())
                {
                    egress_.open(target_ep.second.protocol(), w_ec);
                }
                if (w_ec)
                {
                    break;
                }
                co_await egress_.async_send_to(
                    net::buffer(payload.data(), payload.size()), target_ep.second,
                    net::redirect_error(net::use_awaitable, w_ec));
                if (w_ec)
                {
                    break;
                }
                sent_bytes += payload.size();

                // 上游回包 → 封帧 → 写回流（静默上游受空闲超时保护，不会挂住隧道）
                net::ip::udp::endpoint src_ep;
                boost::system::error_code u_ec;
                const auto up_n = co_await recv_upstream(up, src_ep, u_ec);
                if (!up_n || u_ec)
                {
                    break;
                }
                const auto src_addr = endpoint_to_address(src_ep);
                build_udp_pkt(
                    src_addr,
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(up.data()), *up_n),
                    tx);
                std::error_code s_ec;
                auto tx_span = std::span(tx);
                std::size_t done = 0;
                while (done < tx.size())
                {
                    const auto written = co_await stream_->async_write_some(
                        as_bytes(tx_span.subspan(done)), s_ec);
                    if (s_ec)
                    {
                        break;
                    }
                    done += written;
                }
                if (s_ec)
                {
                    break;
                }
                // 回包按载荷字节数计（对齐 relay：失败不计入，不含帧头）
                recv_bytes += *up_n;
            }
            close();
            if (opts_.traffic != nullptr)
            {
                opts_.traffic->report(opts_.identity, sent_bytes, recv_bytes);
            }
            co_return;
        }

        /**
         * @brief 关闭（幂等）：UDP socket + 流连接
         */
        void close()
        {
            boost::system::error_code ec;
            egress_.close(ec);
            if (stream_)
            {
                stream_->close();
            }
        }

    private:
        /**
         * @brief 上游回包接收（与空闲定时器竞速）
         * @param buf 接收缓冲
         * @param ep 源端点输出
         * @param ec 错误码输出
         * @return 字节数；nullopt = 空闲超时（上游静默）
         * @note idle_timeout 为 0 时禁用超时，直接阻塞等待接收。
         */
        [[nodiscard]] auto recv_upstream(std::span<std::byte> buf, net::ip::udp::endpoint &ep,
                                         boost::system::error_code &ec)
            -> net::awaitable<std::optional<std::size_t>>
        {
            using boost::asio::experimental::awaitable_operators::operator||;
            if (opts_.idle_timeout.count() <= 0)
            {
                co_return co_await egress_.async_receive_from(
                    net::buffer(buf), ep, net::redirect_error(net::use_awaitable, ec));
            }
            net::steady_timer wd(stream_->executor());
            wd.expires_after(opts_.idle_timeout);
            auto recv = egress_.async_receive_from(
                net::buffer(buf), ep, net::redirect_error(net::use_awaitable, ec));
            auto result = co_await (std::move(recv) || wd.async_wait(net::use_awaitable));
            if (result.index() == 1)
            {
                co_return std::nullopt; // 上游静默
            }
            co_return std::get<0>(std::move(result));
        }

        /**
         * @brief 解析目标地址为 UDP 端点
         * @param target 帧内目标地址
         * @return 错误码与端点
         */
        [[nodiscard]] auto resolve_target(const address &target)
            -> net::awaitable<std::pair<error, net::ip::udp::endpoint>>
        {
            if (opts_.resolve)
            {
                co_return co_await opts_.resolve(target);
            }
            // 默认：IP 直解，域名尝试（失败返回 bad_address）
            boost::system::error_code ec;
            const auto ip = net::ip::make_address(target.host, ec);
            if (ec)
            {
                co_return std::pair{error::bad_address, net::ip::udp::endpoint{}};
            }
            co_return std::pair{error::none,
                                net::ip::udp::endpoint(ip, target.port)};
        }

        /**
         * @brief UDP 端点转 vless 地址（回包源地址封帧用）
         * @param ep 端点
         * @return vless 地址
         */
        [[nodiscard]] static auto endpoint_to_address(const net::ip::udp::endpoint &ep)
            -> address
        {
            address out;
            if (ep.address().is_v4())
            {
                out.type = address_type::ipv4;
            }
            else
            {
                out.type = address_type::ipv6;
            }
            out.host = ep.address().to_string();
            out.port = ep.port();
            return out;
        }

        std::shared_ptr<conn<>> stream_; ///< VLESS 流连接（已握手）
        udp_tunnel_options opts_;        ///< 隧道选项
        net::ip::udp::socket egress_;    ///< 出站 UDP socket（上游）
    };

} // namespace preview::vless
