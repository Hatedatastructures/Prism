/**
 * @file UdpAssoc.hpp
 * @brief SOCKS5 UDP ASSOCIATE 服务端数据面（RFC 1928 真实 UDP 语义）
 * @details TCP 控制通道握手完成后，由本服务接管 UDP 数据面：
 *          - Bind 本地 UDP 端口，BND 地址通过 TCP 应答返回客户端
 *          - 帧循环：收客户端帧 → 解帧（RSV/FRAG/ATYP/ADDR/PORT）→
 *            转发载荷到目标端点 → 收上游回包 → 封帧回客户端源端点
 *          - 空闲超时与 TCP 控制连接断开都请求统一 retirement owner 关闭关联
 * @note 与 Dgram.hpp（帧 over 流的编解码测试模型）不同，本服务
 *       使用真实 UDP socket，对齐生产端 Socks5::handler::async_associate。
 */

#pragma once
#include <Prism/Contract/Ingress/DatagramSession.hpp>
#include <Prism/Protocols/Common/DatagramObservation.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Protocols/Common/DatagramDeadline.hpp>
#include <Prism/Protocols/Socks5/UdpAssocRetirement.hpp>
#include <Prism/Protocols/Socks5/UdpAssocBindGate.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>
#include <expected>
#include <span>
#include <tuple>
#include <utility>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Lifecycle/TaskState.hpp>
#include <Prism/Protocols/Socks5/AddressCodec.hpp>
#include <Prism/Protocols/Socks5/AuthCodec.hpp>
#include <Prism/Protocols/Socks5/BeastCodec.hpp>
#include <Prism/Protocols/Socks5/MessageCodec.hpp>
#include <Prism/Protocols/Socks5/TransportCodec.hpp>
#include <Prism/Protocols/Socks5/Conn.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>

namespace Prism::Socks5
{

    namespace Net = boost::asio;

    /**
     * @struct UdpAssocOptions
     * @brief UDP 关联数据面选项
     */
    struct UdpAssocOptions
    {
        /// 空闲超时（0 = 禁用回收）
        std::chrono::milliseconds IdleTimeout{std::chrono::seconds(60)};
        /// 目标解析回调：socks5 地址 → UDP 端点（nullptr = 按 IP/域名直解）
        std::function<Net::awaitable<std::expected<Net::ip::udp::endpoint,
            Prism::Fault::Failure>>(const Address &)>
            Resolve{};
        /// owning 流量统计 sink；为空时不统计。
        std::shared_ptr<Prism::Foundation::TrafficSink> Traffic{};
        Prism::Lifecycle::TaskIdentity TaskIdentity{};
        Prism::AccountId AccountId{};
        /// 首个有效数据报的实际目标（供会话请求日志使用）
        std::function<void(const Address &)> OnFirstTarget{};
        std::function<void(const Prism::Protocols::DatagramSummary&)> OnSessionEnd{};
    };

    /**
     * @class UdpAssoc
     * @brief SOCKS5 UDP ASSOCIATE 数据面服务
     * @details 持有已握手的 TCP 控制连接；Bind 本地 UDP 端口后
     *          通过 TCP 发送 BND 应答，随后进入双向帧循环。
     *          运行期由 idle timer 与 TCP 控制通道 EOF 双重守护，
     *          任一触发都请求统一 retirement owner 关闭资源；只有 Activity()->Drain()
     *          在原 executor 上观察到所有操作和 TCP 各层完成后才确认退休。
     */
    class UdpAssoc : public Prism::Contract::DatagramSession, public std::enable_shared_from_this<UdpAssoc>
    {
    public:
        /**
         * @brief 构造
         * @param Executor 执行器
         * @param Tcp 已握手的 TCP 控制连接（所有权移交）
         * @param Options 数据面选项
         */
        UdpAssoc(Net::any_io_executor Executor, std::shared_ptr<Conn<>> Tcp,
                  UdpAssocOptions Options);

        /**
         * @brief 通过唯一 bind gate 共享 BND 写入与 typed 结果。
         * @return BND wire 字节数或协议码、Native cause 与 partial progress。
         * @note 每个调用在 gate 内持 operation reservation 至真实退栈。
         */
        [[nodiscard]] auto BindAndReply() -> Net::awaitable<ReplyResult<std::size_t>>;

        /**
         * @brief 获取 BND 端点（BindAndReply 成功后有效）
         * @return 本地 UDP 端点
         */
        [[nodiscard]] auto BindEndpoint() const -> Net::ip::udp::endpoint
        {
            return BindGate_->LocalEndpoint();
        }

        [[nodiscard]] auto DatagramCount() const noexcept -> std::size_t { return DatagramCount_; }

        [[nodiscard]] auto SentBytes() const noexcept -> std::size_t { return SentBytes_; }

        [[nodiscard]] auto ReceivedBytes() const noexcept -> std::size_t { return RecvBytes_; }

        /**
         * @brief 运行数据面（帧循环 + 控制通道守护，任一结束即收尾）
         * @return 首个 typed 失败；只有真实 Drain 成功后才返回成功。
         */
        /** @brief 在控制流 executor 上运行一次；取消传播到解析及全部 I/O。 */
        [[nodiscard]] auto Run()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override;

        /** @brief 返回拥有 TCP 各层及 UDP 操作预约的真实关闭与退栈能力。 */
        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override;

        /** @brief 可跨线程请求取消；最终错误和完成由 Activity()->Drain() 返回。 */
        auto Cancel() noexcept -> void override;

    private:
        auto Execute() -> Net::awaitable<Prism::Fault::Code>;

    private:
        [[nodiscard]] auto RunCore() -> Net::awaitable<Prism::Fault::Code>;

    public:
        /** @brief 可跨线程请求原 executor 关闭；错误与真实退栈由 Activity()->Drain() 交付。 */
        auto Close() noexcept -> void override;

    private:
        auto PinRetirementOwner() const noexcept -> void;

        auto RequestRetirement(const bool Cancelled = false) noexcept -> void;

        auto Report() noexcept -> void;

        auto RequestCancellationRetirement() noexcept -> void;

        [[nodiscard]] auto ObserveNativeError(
            const boost::system::error_code &ErrorCode) noexcept -> Prism::Fault::Code;

    private:
        struct ReceiveOptions
        {
            Net::ip::udp::socket &Socket;
            Net::steady_timer &Idle;
            std::span<std::byte> Buffer;
            Net::ip::udp::endpoint &Endpoint;
            boost::system::error_code &Error;
        };

        /**
         * @brief 数据面帧循环：解帧转发 + 回包封帧
         * @details 每次网络等待（收客户端帧 / 收上游回包）都与空闲定时器竞速，
         *          任一阶段超时即终止；TCP 控制断开由 TcpWatch 并行守护。
         */
        struct AcceptedDatagram final
        {
            Address Target;
            std::span<const std::uint8_t> Payload;
            Net::ip::udp::endpoint Peer;
        };

        struct ReplyWorkspace final
        {
            std::vector<std::byte> Payload = std::vector<std::byte>(65535);
            std::vector<std::uint8_t> Wire;
        };

        [[nodiscard]] auto FrameLoop() -> Net::awaitable<Prism::Fault::Code>;

        /** @brief 接收窗口和应答工作区借用到返回；解析、双向发送与接收共享期限。 */
        auto Exchange(const AcceptedDatagram& Packet, ReplyWorkspace& Reply)
            -> Net::awaitable<Prism::Fault::Code>;

        /**
         * @brief 单次网络接收（与空闲定时器竞速）
         * @param Options 接收 socket、缓冲区、定时器和输出状态
         * @return 实际字节数；nullopt = 空闲超时
         * @note IdleTimeout 为 0 时禁用超时，直接阻塞等待接收。
         */
        [[nodiscard]] auto RecvGuarded(ReceiveOptions Options)
            -> Net::awaitable<std::optional<std::size_t>>;

        /**
         * @brief 控制通道守护：TCP 关闭（EOF/错误）即终止数据面
         */
        [[nodiscard]] auto TcpWatch() -> Net::awaitable<Prism::Fault::Code>;

        /**
         * @brief 解析目标地址为 UDP 端点
         * @param Target 帧内目标地址
         * @return 错误码与端点
         */
        [[nodiscard]] auto ResolveTarget(const Address &Target)
            -> Net::awaitable<std::expected<Net::ip::udp::endpoint, Prism::Fault::Failure>>;

        Net::any_io_executor Ex_;                       ///< 执行器
        std::shared_ptr<UdpAssocRetirement> Retirement_; ///< TCP 全层、UDP socket 与 Run 退役 owner
        std::shared_ptr<UdpAssocBindGate> BindGate_;      ///< 一次性 bind/reply 与 waiter 结果 owner
        UdpAssocOptions Opts_;                          ///< 数据面选项
        Prism::Foundation::TrafficObservation Observation_;
        /// 客户端→上游载荷字节（up 口径，对齐 relay）
        std::size_t SentBytes_{0};
        /// 上游→客户端载荷字节（down 口径，对齐 relay）
        std::size_t RecvBytes_{0};
        std::size_t DatagramCount_{0}; ///< 已解析的有效客户端数据报数
        bool FirstTargetReported_{false}; ///< 是否已报告首个有效目标
        bool Reported_{false}; ///< 观察和会话结束回调只允许一次
    };

} // namespace Prism::Socks5
