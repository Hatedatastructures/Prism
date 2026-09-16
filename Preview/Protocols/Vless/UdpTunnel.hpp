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
#include <system_error>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Vless/Conn.hpp>
#include <Preview/Protocols/Vless/Types.hpp>

namespace Preview::Vless
{

    namespace Net = boost::asio;

    /**
     * @struct UdpTunnelOptions
     * @brief UDP 隧道选项
     */
    struct UdpTunnelOptions
    {
        /// 空闲超时（0 = 禁用回收）
        std::chrono::milliseconds IdleTimeout{std::chrono::seconds(60)};
        /// 目标解析回调：vless 地址 → UDP 端点（nullptr = 按 IP/域名直解）
        std::function<Net::awaitable<std::pair<Error, Net::ip::udp::endpoint>>(
            const Address &)>
            resolve{};
        /// 流量统计 sink（数据面退出时上报；nullptr = 不统计）
        Preview::Foundation::TrafficSink *traffic{nullptr};
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
         * @param Options 隧道选项
         */
        explicit UdpTunnel(std::shared_ptr<Conn<>> Stream, UdpTunnelOptions Options)
            : Stream_(std::move(Stream)), Opts_(std::move(Options)),
              Egress_(ExecutorFor(Stream_))
        {
        }

        /**
         * @brief 运行数据面（帧循环直至空闲超时或流 EOF）
         * @return 无（结束后所有资源已关闭）
         * @details 协程内自捕获 shared_from_this 保持对象存活，
         *          允许 detached 派发；任一退出路径统一走 Close() 收口。
         */
        [[nodiscard]] auto Run() -> Net::awaitable<void>
        {
            auto Self = shared_from_this();
            if (!Stream_ || Stream_->TransportType() != Preview::Transmission::Type::Udp)
            {
                Close();
                co_return;
            }
            Net::steady_timer IdleTimer(Stream_->Executor());
            // 大缓冲堆分配，避免协程帧膨胀与逐轮零初始化
            std::vector<std::byte> Rx(65535);
            std::vector<std::byte> UpstreamBuffer(65535);
            std::vector<std::uint8_t> TxWire;
            // 流量口径对齐 relay：upstream = 客户端→上游载荷，downstream = 上游→客户端载荷
            std::size_t SentBytes = 0;
            std::size_t RecvBytes = 0;
            while (true)
            {
                std::error_code ReadError;
                const auto RxSpan = std::span<std::byte>(Rx);
                auto Read = Stream_->async_read_some(RxSpan, ReadError);
                std::size_t N = 0;
                if (Opts_.IdleTimeout.count() > 0)
                {
                    IdleTimer.expires_after(Opts_.IdleTimeout);
                    using boost::asio::experimental::awaitable_operators::operator||;
                    auto Result = co_await (
                        std::move(Read) || IdleTimer.async_wait(Net::use_awaitable));
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
                if (ReadError)
                {
                    break;
                }
                IdleTimer.cancel();
                if (N == 0 || N > Rx.size())
                {
                    break; // 流 EOF
                }

                // 解帧：ATYP + ADDR + PORT + payload（帧无长度字段）
                Address Target;
                std::span<const std::uint8_t> Payload;
                const auto PErr = ParseUdpPkt(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(Rx.data()), N),
                    Target,
                    Payload);
                if (PErr != Error::None)
                {
                    continue; // 非法帧丢弃（对齐生产端语义）
                }

                // 目标解析 → 转发载荷
                auto TargetEndpoint = co_await ResolveTarget(Target);
                if (TargetEndpoint.first != Error::None)
                {
                    continue;
                }
                boost::system::error_code WriteError;
                if (!Egress_.is_open())
                {
                    Egress_.open(TargetEndpoint.second.protocol(), WriteError);
                }
                if (WriteError)
                {
                    break;
                }
                co_await Egress_.async_send_to(
                    Net::buffer(Payload.data(), Payload.size()),
                    TargetEndpoint.second,
                    Net::redirect_error(Net::use_awaitable, WriteError));
                if (WriteError)
                {
                    break;
                }
                SentBytes += Payload.size();

                // 上游回包 → 封帧 → 写回流（静默上游受空闲超时保护，不会挂住隧道）
                Net::ip::udp::endpoint SourceEndpoint;
                boost::system::error_code UpstreamError;
                const auto UpstreamSize = co_await RecvUpstream(
                    UpstreamBuffer,
                    SourceEndpoint,
                    UpstreamError);
                if (!UpstreamSize || UpstreamError)
                {
                    break;
                }
                const auto SourceAddress = EndpointToAddress(SourceEndpoint);
                BuildUdpPkt(
                    SourceAddress,
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(UpstreamBuffer.data()),
                        *UpstreamSize),
                    TxWire);
                if (TxWire.empty())
                {
                    break;
                }
                std::error_code SendError;
                auto TxSpan = std::span(TxWire);
                std::size_t Done = 0;
                while (Done < TxWire.size())
                {
                    const auto Written = co_await Stream_->async_write_some(
                        AsBytes(TxSpan.subspan(Done)),
                        SendError);
                    if (SendError)
                    {
                        break;
                    }
                    if (Written == 0)
                    {
                        SendError = std::make_error_code(std::errc::broken_pipe); // 底层零字节写入，防死循环
                        break;
                    }
                    if (Written > TxWire.size() - Done)
                    {
                        SendError = std::make_error_code(std::errc::value_too_large);
                        break;
                    }
                    Done += Written;
                }
                if (SendError)
                {
                    break;
                }
                // 回包按载荷字节数计（对齐 relay：失败不计入，不含帧头）
                RecvBytes += *UpstreamSize;
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
        auto Close() -> void
        {
            boost::system::error_code ErrorCode;
            Egress_.close(ErrorCode);
            if (Stream_)
            {
                Stream_->Close();
            }
        }

    private:
        [[nodiscard]] static auto ExecutorFor(const std::shared_ptr<Conn<>> &Stream)
            -> Net::any_io_executor
        {
            if (Stream)
            {
                return Stream->Executor();
            }
            return {};
        }

        /**
         * @brief 上游回包接收（与空闲定时器竞速）
         * @param Buffer 接收缓冲
         * @param Endpoint 源端点输出
         * @param ErrorCode 错误码输出
         * @return 字节数；nullopt = 空闲超时（上游静默）
         * @note IdleTimeout 为 0 时禁用超时，直接阻塞等待接收。
         */
        [[nodiscard]] auto RecvUpstream(
            std::span<std::byte> Buffer,
            Net::ip::udp::endpoint &Endpoint,
            boost::system::error_code &ErrorCode)
            -> Net::awaitable<std::optional<std::size_t>>
        {
            using boost::asio::experimental::awaitable_operators::operator||;
            if (Opts_.IdleTimeout.count() <= 0)
            {
                co_return co_await Egress_.async_receive_from(
                    Net::buffer(Buffer),
                    Endpoint,
                    Net::redirect_error(Net::use_awaitable, ErrorCode));
            }
            Net::steady_timer Watchdog(Stream_->Executor());
            Watchdog.expires_after(Opts_.IdleTimeout);
            auto Recv = Egress_.async_receive_from(
                Net::buffer(Buffer),
                Endpoint,
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            auto Result = co_await (
                std::move(Recv) || Watchdog.async_wait(Net::use_awaitable));
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
            -> Net::awaitable<std::pair<Error, Net::ip::udp::endpoint>>
        {
            if (Opts_.resolve)
            {
                co_return co_await Opts_.resolve(Target);
            }
            // 默认仅支持 IP 直解；域名由调用方通过 resolve 回调解析。
            boost::system::error_code ErrorCode;
            const auto Ip = Net::ip::make_address(Target.Host, ErrorCode);
            if (ErrorCode)
            {
                co_return std::pair{Error::BadAddress, Net::ip::udp::endpoint{}};
            }
            co_return std::pair{Error::None,
                                Net::ip::udp::endpoint(Ip, Target.Port)};
        }

        /**
         * @brief UDP 端点转 vless 地址（回包源地址封帧用）
         * @param Endpoint 端点
         * @return vless 地址
         */
        [[nodiscard]] static auto EndpointToAddress(const Net::ip::udp::endpoint &Endpoint)
            -> Address
        {
            Address Output;
            if (Endpoint.address().is_v4())
            {
                Output.Type = AddressType::Ipv4;
            }
            else
            {
                Output.Type = AddressType::Ipv6;
            }
            Output.Host = Endpoint.address().to_string();
            Output.Port = Endpoint.port();
            return Output;
        }

        std::shared_ptr<Conn<>> Stream_; ///< VLESS 流连接（已握手）
        UdpTunnelOptions Opts_;        ///< 隧道选项
        Net::ip::udp::socket Egress_;    ///< 出站 UDP socket（上游）
    };

} // namespace Preview::Vless
