/**
 * @file UdpAssoc.hpp
 * @brief SOCKS5 UDP ASSOCIATE 服务端数据面（RFC 1928 真实 UDP 语义）
 * @details TCP 控制通道握手完成后，由本服务接管 UDP 数据面：
 *          - Bind 本地 UDP 端口，BND 地址通过 TCP 应答返回客户端
 *          - 帧循环：收客户端帧 → 解帧（RSV/FRAG/ATYP/ADDR/PORT）→
 *            转发载荷到目标端点 → 收上游回包 → 封帧回客户端源端点
 *          - 空闲超时（IdleTimeout）关闭关联，TCP 控制连接断开时同步终止
 * @note 与 Dgram.hpp（帧 over 流的编解码测试模型）不同，本服务
 *       使用真实 UDP socket，对齐生产端 Socks5::handler::async_associate。
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

#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Utility/TrafficSink.hpp>
#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Socks5/Conn.hpp>
#include <preview/Protocols/Socks5/Types.hpp>

namespace Preview::Socks5
{

    namespace net = boost::asio;

    /**
     * @struct UdpAssocOptions
     * @brief UDP 关联数据面选项
     */
    struct UdpAssocOptions
    {
        /// 空闲超时（0 = 禁用回收）
        std::chrono::milliseconds IdleTimeout{std::chrono::seconds(60)};
        /// 目标解析回调：socks5 地址 → UDP 端点（nullptr = 按 IP/域名直解）
        std::function<net::awaitable<std::pair<Error, net::ip::udp::endpoint>>(
            const Address &)>
            resolve{};
        /// 流量统计 sink（数据面退出时上报；nullptr = 不统计）
        Preview::Foundation::TrafficSink *traffic{nullptr};
        /// 统计身份（与 traffic 配套；对齐 relay 上报口径）
        std::string identity{};
    };

    /**
     * @class UdpAssoc
     * @brief SOCKS5 UDP ASSOCIATE 数据面服务
     * @details 持有已握手的 TCP 控制连接；Bind 本地 UDP 端口后
     *          通过 TCP 发送 BND 应答，随后进入双向帧循环。
     *          运行期由 idle timer 与 TCP 控制通道 EOF 双重守护，
     *          任一触发即关闭全部资源。
     */
    class UdpAssoc : public std::enable_shared_from_this<UdpAssoc>
    {
    public:
        /**
         * @brief 构造
         * @param Executor 执行器
         * @param Tcp 已握手的 TCP 控制连接（所有权移交）
         * @param opts 数据面选项
         */
        UdpAssoc(net::any_io_executor Executor, std::shared_ptr<Conn<>> Tcp,
                  UdpAssocOptions opts)
            : Ex_(std::move(Executor)), Tcp_(std::move(Tcp)), Opts_(std::move(opts)),
              Ingress_(Ex_), Egress_(Ex_)
        {
        }

        /**
         * @brief 绑定本地 UDP 端口并发送 BND 应答
         * @return 错误码（成功后 BindEndpoint() 有效）
         * @note 失败路径会立即关闭已 Open 的 UDP socket。
         */
        [[nodiscard]] auto BindAndReply() -> net::awaitable<Error>
        {
            boost::system::error_code ec;
            Ingress_.open(net::ip::udp::v4(), ec);
            if (ec)
            {
                CloseSockets();
                co_return Error::IoError;
            }
            Egress_.open(net::ip::udp::v4(), ec);
            if (ec)
            {
                CloseSockets();
                co_return Error::IoError;
            }
            Ingress_.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), ec);
            if (ec)
            {
                CloseSockets();
                co_return Error::IoError;
            }
            const auto Local = Ingress_.local_endpoint(ec);
            if (ec)
            {
                CloseSockets();
                co_return Error::IoError;
            }
            Address bnd;
            bnd.Type = AddressType::Ipv4;
            bnd.Host = Local.address().to_string();
            bnd.Port = Local.port();
            co_return co_await Tcp_->SendAssocReply(ReplyCode::Success, bnd);
        }

        /**
         * @brief 获取 BND 端点（BindAndReply 成功后有效）
         * @return 本地 UDP 端点
         */
        [[nodiscard]] auto BindEndpoint() const -> net::ip::udp::endpoint
        {
            return Ingress_.local_endpoint();
        }

        /**
         * @brief 运行数据面（帧循环 + 控制通道守护，任一结束即收尾）
         * @return 无（结束后所有资源已关闭）
         */
        [[nodiscard]] auto Run() -> net::awaitable<void>
        {
            using boost::asio::experimental::awaitable_operators::operator||;

            auto FrameLoop = [self = shared_from_this()]() mutable
                -> net::awaitable<void>
            {
                co_await self->FrameLoop();
            };
            auto TcpWatch = [self = shared_from_this()]() mutable
                -> net::awaitable<void>
            {
                co_await self->TcpWatch();
            };

            co_await (FrameLoop() || TcpWatch());

            Close();
            // FrameLoop 可能被 TcpWatch 侧取消，计数器放成员保证跨取消存活
            if (Opts_.traffic != nullptr)
            {
                Opts_.traffic->Report(Opts_.identity, SentBytes_, RecvBytes_);
            }
            co_return;
        }

        /**
         * @brief 关闭（幂等）：UDP socket + TCP 控制连接
         */
        void Close()
        {
            boost::system::error_code ec;
            Ingress_.close(ec);
            Egress_.close(ec);
            if (Tcp_)
            {
                Tcp_->Close();
            }
        }

    private:
        /**
         * @brief 数据面帧循环：解帧转发 + 回包封帧
         * @details 每次网络等待（收客户端帧 / 收上游回包）都与空闲定时器竞速，
         *          任一阶段超时即终止；TCP 控制断开由 TcpWatch 并行守护。
         */
        [[nodiscard]] auto FrameLoop() -> net::awaitable<void>
        {
            net::steady_timer idle(Ex_);
            // 大缓冲堆分配，避免协程帧膨胀（对齐 UdpRelay 方向）
            std::vector<std::byte> Rx(65535);
            std::vector<std::byte> up(65535);
            std::vector<std::uint8_t> wire;
            while (true)
            {
                // 收客户端帧（受空闲超时保护）
                net::ip::udp::endpoint ClientEp;
                boost::system::error_code REc;
                const auto N = co_await RecvGuarded(Ingress_, idle, Rx, ClientEp, REc);
                if (REc || !N)
                {
                    co_return; // 错误或空闲超时
                }

                // 解帧：RSV/FRAG 校验 + 目标地址 + 载荷
                Address Target;
                std::span<const std::uint8_t> payload;
                const auto PErr = ParseUdpDatagram(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(Rx.data()), *N),
                    Target, payload);
                if (PErr != Error::None)
                {
                    continue; // 非法帧丢弃（对齐生产端语义）
                }

                // 目标解析 → 转发载荷
                auto TargetEp = co_await ResolveTarget(Target);
                if (TargetEp.first != Error::None)
                {
                    continue;
                }
                boost::system::error_code WEc;
                co_await Egress_.async_send_to(net::buffer(payload.data(), payload.size()),
                                               TargetEp.second,
                                               net::redirect_error(net::use_awaitable, WEc));
                if (WEc)
                {
                    co_return;
                }
                SentBytes_ += payload.size();

                // 收上游回包（受空闲超时保护；静默上游不会挂住关联）
                net::ip::udp::endpoint SrcEp;
                boost::system::error_code UEc;
                const auto UpN = co_await RecvGuarded(Egress_, idle, up, SrcEp, UEc);
                if (UEc || !UpN)
                {
                    co_return;
                }
                const auto SrcAddr = EndpointToAddress(SrcEp);
                BuildUdpDatagram(
                    SrcAddr,
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(up.data()), *UpN),
                    wire);
                boost::system::error_code SEc;
                co_await Ingress_.async_send_to(
                    net::buffer(wire.data(), wire.size()), ClientEp,
                    net::redirect_error(net::use_awaitable, SEc));
                if (SEc)
                {
                    co_return;
                }
                // 回包按载荷字节数计（对齐 relay：失败不计入，不含帧头）
                RecvBytes_ += *UpN;
            }
        }

        /**
         * @brief 关闭 UDP 数据面 socket（保留 TCP 控制连接，可继续发送应答）
         */
        void CloseSockets() noexcept
        {
            boost::system::error_code ec;
            Ingress_.close(ec);
            Egress_.close(ec);
        }

        /**
         * @brief 单次网络接收（与空闲定时器竞速）
         * @param sock 接收 socket（入站或出站）
         * @param idle 空闲定时器（每次调用重新武装）
         * @param buf 接收缓冲
         * @param ep 源端点输出
         * @param ec 错误码输出
         * @return 实际字节数；nullopt = 空闲超时
         * @note IdleTimeout 为 0 时禁用超时，直接阻塞等待接收。
         */
        [[nodiscard]] auto RecvGuarded(net::ip::udp::socket &sock, net::steady_timer &idle,
                                        std::span<std::byte> buf, net::ip::udp::endpoint &ep,
                                        boost::system::error_code &ec)
            -> net::awaitable<std::optional<std::size_t>>
        {
            using boost::asio::experimental::awaitable_operators::operator||;
            if (Opts_.IdleTimeout.count() <= 0)
            {
                co_return co_await sock.async_receive_from(
                    net::buffer(buf), ep, net::redirect_error(net::use_awaitable, ec));
            }
            idle.expires_after(Opts_.IdleTimeout);
            auto Recv = sock.async_receive_from(
                net::buffer(buf), ep, net::redirect_error(net::use_awaitable, ec));
            auto Wait = idle.async_wait(net::use_awaitable);
            auto Result = co_await (std::move(Recv) || std::move(Wait));
            idle.cancel();
            if (Result.index() == 1)
            {
                co_return std::nullopt; // 空闲超时
            }
            co_return std::get<0>(Result);
        }

        /**
         * @brief 控制通道守护：TCP 关闭（EOF/错误）即终止数据面
         */
        [[nodiscard]] auto TcpWatch() -> net::awaitable<void>
        {
            std::array<std::byte, 1> Probe{};
            std::error_code ec;
            (void)co_await Tcp_->async_read_some(std::span(Probe), ec);
            co_return;
        }

        /**
         * @brief 解析目标地址为 UDP 端点
         * @param Target 帧内目标地址
         * @return 错误码与端点
         */
        [[nodiscard]] auto ResolveTarget(const Address &Target)
            -> net::awaitable<std::pair<Error, net::ip::udp::endpoint>>
        {
            if (Opts_.resolve)
            {
                co_return co_await Opts_.resolve(Target);
            }
            // 默认：IP 直解，域名尝试（失败返回 bad_address）
            boost::system::error_code ec;
            const auto Ip = net::ip::make_address(Target.Host, ec);
            if (ec)
            {
                co_return std::pair{Error::BadAddress, net::ip::udp::endpoint{}};
            }
            co_return std::pair{Error::None,
                                net::ip::udp::endpoint(Ip, Target.Port)};
        }

        /**
         * @brief UDP 端点转 socks5 地址（回包源地址封帧用）
         * @param ep 端点
         * @return socks5 地址
         */
        [[nodiscard]] static auto EndpointToAddress(const net::ip::udp::endpoint &ep)
            -> Address
        {
            Address out;
            if (ep.address().is_v4())
            {
                out.Type = AddressType::Ipv4;
            }
            else
            {
                out.Type = AddressType::Ipv6;
            }
            out.Host = ep.address().to_string();
            out.Port = ep.port();
            return out;
        }

        net::any_io_executor Ex_;                       ///< 执行器
        std::shared_ptr<Conn<>> Tcp_;                   ///< TCP 控制连接（已握手）
        UdpAssocOptions Opts_;                        ///< 数据面选项
        net::ip::udp::socket Ingress_;                  ///< 入站 UDP socket（BND）
        net::ip::udp::socket Egress_;                   ///< 出站 UDP socket（上游）
        /// 客户端→上游载荷字节（up 口径，对齐 relay）
        std::size_t SentBytes_{0};
        /// 上游→客户端载荷字节（down 口径，对齐 relay）
        std::size_t RecvBytes_{0};
    };

} // namespace Preview::Socks5
