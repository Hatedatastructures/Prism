/**
 * @file UdpTunnel.hpp
 * @brief VLESS UDP 命令服务端数据面（UDP over 流，对齐生产 FrameLoop 模型）
 * @details TCP 流上承载 UDP 帧：[ATYP 1B][ADDR var][PORT 2B BE][payload]
 *          - 帧循环：读流一帧 → 解析目标 → 真实 UDP socket 转发 →
 *            收上游回包 → 封帧写回流
 *          - 空闲超时（IdleTimeout）关闭隧道
 *          - 流 EOF/错误（客户端断开）同步终止
 * @note 对齐生产端 Protocol::common::FrameLoop（Trojan/VLESS 共用）；
 *       帧无长度字段，单帧单次读约定（一次 Write 一帧）。
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

#include <common/Core/Error.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Protocols/Vless/Codec.hpp>
#include <common/Protocols/Vless/Conn.hpp>
#include <common/Protocols/Vless/Types.hpp>

namespace Preview::Vless
{

    namespace net = boost::asio;

    /**
     * @struct UdpTunnelOptions
     * @brief UDP 隧道选项
     */
    struct UdpTunnelOptions
    {
        /// 空闲超时（0 = 禁用回收）
        std::chrono::milliseconds IdleTimeout{std::chrono::seconds(60)};
        /// 目标解析回调：vless 地址 → UDP 端点（nullptr = 按 IP/域名直解）
        std::function<net::awaitable<std::pair<Error, net::ip::udp::endpoint>>(
            const Address &)>
            resolve{};
        /// 流量统计 sink（数据面退出时上报；nullptr = 不统计）
        Preview::Middleware::Context::TrafficSink *traffic{nullptr};
        /// 统计身份（与 traffic 配套；对齐 relay 上报口径）
        std::string identity{};
    };

    /**
     * @class UdpTunnel
     * @brief VLESS UDP 命令数据面（服务端）
     * @details 持有已握手的流连接；帧循环在流上读取 UDP 帧并
     *          经真实 UDP socket 转发到目标，回包封帧写回流。
     *          空闲超时与流 EOF 双重守护，任一触发即关闭全部资源。
     */
    class UdpTunnel : public std::enable_shared_from_this<UdpTunnel>
    {
    public:
        /**
         * @brief 构造
         * @param Stream 已握手的 VLESS 流连接（所有权移交）
         * @param opts 隧道选项
         */
        explicit UdpTunnel(std::shared_ptr<Conn<>> Stream, UdpTunnelOptions opts)
            : Stream_(std::move(Stream)), Opts_(std::move(opts)), Egress_(Stream_->Executor())
        {
        }

        /**
         * @brief 运行数据面（帧循环直至空闲超时或流 EOF）
         * @return 无（结束后所有资源已关闭）
         * @details 协程内自捕获 shared_from_this 保持对象存活，
         *          允许 detached 派发；任一退出路径统一走 Close() 收口。
         */
        [[nodiscard]] auto Run() -> net::awaitable<void>
        {
            auto Self = shared_from_this();
            net::steady_timer idle(Stream_->Executor());
            // 大缓冲堆分配，避免协程帧膨胀与逐轮零初始化
            std::vector<std::byte> Rx(65535);
            std::vector<std::byte> up(65535);
            std::vector<std::uint8_t> tx;
            // 流量口径对齐 relay：up = 客户端→上游载荷，down = 上游→客户端载荷
            std::size_t SentBytes = 0;
            std::size_t RecvBytes = 0;
            while (true)
            {
                std::error_code REc;
                const auto RxSpan = std::span<std::byte>(Rx);
                auto Read = Stream_->async_read_some(RxSpan, REc);
                std::size_t N = 0;
                if (Opts_.IdleTimeout.count() > 0)
                {
                    idle.expires_after(Opts_.IdleTimeout);
                    using boost::asio::experimental::awaitable_operators::operator||;
                    auto Result = co_await (std::move(Read) || idle.async_wait(net::use_awaitable));
                    if (Result.index() == 1)
                    {
                        break; // 空闲超时
                    }
                    N = std::get<0>(std::move(Result));
                }
                else
                {
                    N = co_await std::move(Read); // 0 = 禁用回收
                }
                if (REc)
                {
                    break;
                }
                idle.cancel();
                if (N == 0)
                {
                    break; // 流 EOF
                }

                // 解帧：ATYP + ADDR + PORT + payload（帧无长度字段）
                Address Target;
                std::span<const std::uint8_t> payload;
                const auto PErr = ParseUdpPkt(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(Rx.data()), N),
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
                if (!Egress_.is_open())
                {
                    Egress_.open(TargetEp.second.protocol(), WEc);
                }
                if (WEc)
                {
                    break;
                }
                co_await Egress_.async_send_to(
                    net::buffer(payload.data(), payload.size()), TargetEp.second,
                    net::redirect_error(net::use_awaitable, WEc));
                if (WEc)
                {
                    break;
                }
                SentBytes += payload.size();

                // 上游回包 → 封帧 → 写回流（静默上游受空闲超时保护，不会挂住隧道）
                net::ip::udp::endpoint SrcEp;
                boost::system::error_code UEc;
                const auto UpN = co_await RecvUpstream(up, SrcEp, UEc);
                if (!UpN || UEc)
                {
                    break;
                }
                const auto SrcAddr = EndpointToAddress(SrcEp);
                BuildUdpPkt(
                    SrcAddr,
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(up.data()), *UpN),
                    tx);
                std::error_code SEc;
                auto TxSpan = std::span(tx);
                std::size_t Done = 0;
                while (Done < tx.size())
                {
                    const auto Written = co_await Stream_->async_write_some(
                        AsBytes(TxSpan.subspan(Done)), SEc);
                    if (SEc)
                    {
                        break;
                    }
                    if (Written == 0)
                    {
                        SEc = std::make_error_code(std::errc::broken_pipe); // 底层零字节写入，防死循环
                        break;
                    }
                    Done += Written;
                }
                if (SEc)
                {
                    break;
                }
                // 回包按载荷字节数计（对齐 relay：失败不计入，不含帧头）
                RecvBytes += *UpN;
            }
            Close();
            if (Opts_.traffic != nullptr)
            {
                Opts_.traffic->Report(Opts_.identity, SentBytes, RecvBytes);
            }
            co_return;
        }

        /**
         * @brief 关闭（幂等）：UDP socket + 流连接
         */
        void Close()
        {
            boost::system::error_code ec;
            Egress_.close(ec);
            if (Stream_)
            {
                Stream_->Close();
            }
        }

    private:
        /**
         * @brief 上游回包接收（与空闲定时器竞速）
         * @param buf 接收缓冲
         * @param ep 源端点输出
         * @param ec 错误码输出
         * @return 字节数；nullopt = 空闲超时（上游静默）
         * @note IdleTimeout 为 0 时禁用超时，直接阻塞等待接收。
         */
        [[nodiscard]] auto RecvUpstream(std::span<std::byte> buf, net::ip::udp::endpoint &ep,
                                         boost::system::error_code &ec)
            -> net::awaitable<std::optional<std::size_t>>
        {
            using boost::asio::experimental::awaitable_operators::operator||;
            if (Opts_.IdleTimeout.count() <= 0)
            {
                co_return co_await Egress_.async_receive_from(
                    net::buffer(buf), ep, net::redirect_error(net::use_awaitable, ec));
            }
            net::steady_timer wd(Stream_->Executor());
            wd.expires_after(Opts_.IdleTimeout);
            auto Recv = Egress_.async_receive_from(
                net::buffer(buf), ep, net::redirect_error(net::use_awaitable, ec));
            auto Result = co_await (std::move(Recv) || wd.async_wait(net::use_awaitable));
            if (Result.index() == 1)
            {
                co_return std::nullopt; // 上游静默
            }
            co_return std::get<0>(std::move(Result));
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
         * @brief UDP 端点转 vless 地址（回包源地址封帧用）
         * @param ep 端点
         * @return vless 地址
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

        std::shared_ptr<Conn<>> Stream_; ///< VLESS 流连接（已握手）
        UdpTunnelOptions Opts_;        ///< 隧道选项
        net::ip::udp::socket Egress_;    ///< 出站 UDP socket（上游）
    };

} // namespace Preview::Vless
