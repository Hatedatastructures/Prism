/**
 * @file Handler.hpp
 * @brief 协议处理器接口（对象式封装，对标 mihomo Proxy）
 */

#pragma once

#include <functional>
#include <string>
#include <string_view>

#include <boost/asio/awaitable.hpp>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Account/Lease.hpp>
#include <Preview/Net/Target.hpp>
#include <Preview/Runtime/Contract/DataPlane.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Runtime::Handler
{

    namespace Net = boost::asio;

    /**
     * @struct AcceptResult
     * @brief 协议握手结果（目标地址 + 数据面通道 + 拨号后回调）
     */
    struct AcceptResult
    {
        /// 握手错误码（none = 成功）
        Preview::Error err{Preview::Error::None};
        /// 客户端请求的目标地址（host/port 文本）
        Preview::Network::Target Target;
        /// typed 账户身份；无账户时为空值
        Preview::AccountId AccountId{};
        /// 握手完成的数据面通道（失败时为空）
        Preview::SharedTransmission Transmission;
        /// 已认证的用户身份（协议未提供时留空）
        std::string identity;
        /// 协议握手是否已经完成认证；为真时 Session 不再重复执行通用认证中间件
        bool ProtocolAuthenticated{false};
        /// 协议认证是否还需要绑定 typed 账户租约；静态凭据不需要租约。
        bool AccountLeaseRequired{false};
        /// typed 协议数据面；新 handler 应优先填充该字段。
        Preview::Runtime::ProtocolDataPlane DataPlane{};
        /// 协议认证成功后持有的账户租约
        Preview::Account::AccountLease AccountLease{};
        /// true 时 Transmission 形态按协议而异：SOCKS5=TCP 控制连接、Trojan/VMess=Dgram<> 装饰器、VLESS=裸流，udp_service 需按协议 dynamic_pointer_cast
        bool IsDgram{false};
        /// 上游拨号完成后的回调（如 SOCKS5 延迟 CONNECT 应答；空 = 无需回调）
        std::function<Net::awaitable<void>(Preview::Fault::Code)> PostDial;
    };

    /**
     * @struct ProtocolHandler
     * @brief 入站协议处理器接口（对象式封装，对标 mihomo Proxy）
     */
    struct ProtocolHandler
    {
        virtual ~ProtocolHandler() = default;

        /**
         * @brief 执行协议握手
         * @param Inbound 已识别协议的入站传输
         * @return 握手结果（目标地址、数据面通道与拨号后回调）
         */
        virtual auto Accept(Preview::SharedTransmission Inbound)
            -> Net::awaitable<AcceptResult> = 0;

        /**
         * @brief 处理器名称
         * @return 协议名（如 "socks5"/"trojan"，用于日志与诊断）
         */
        [[nodiscard]] virtual auto Name() const -> std::string_view = 0;
    };

} // namespace Preview::Runtime::Handler
