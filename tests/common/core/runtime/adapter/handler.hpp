/**
 * @file handler.hpp
 * @brief 协议处理器接口（对象式封装，对标 mihomo Proxy）
 */

#pragma once

#include <functional>
#include <string>
#include <string_view>

#include <common/core/error.hpp>
#include <common/core/fault/code.hpp>
#include <common/core/net/target.hpp>
#include <common/core/transmission.hpp>

namespace preview::runtime::handler
{

    namespace net = boost::asio;

    /**
     * @struct AcceptResult
     * @brief 协议握手结果（目标地址 + 数据面通道 + 拨号后回调）
     */
    struct AcceptResult
    {
        /// 握手错误码（none = 成功）
        preview::error err{preview::error::none};
        /// 客户端请求的目标地址（host/port 文本）
        preview::network::target target;
        /// 握手完成的数据面通道（失败时为空）
        preview::shared_transmission transmission;
        /// 已认证的用户身份（协议未提供时留空）
        std::string identity;
        /// true 时 transmission 形态按协议而异：SOCKS5=TCP 控制连接、Trojan/VMess=dgram<> 装饰器、VLESS=裸流，udp_service 需按协议 dynamic_pointer_cast
        bool is_dgram{false};
        /// 上游拨号完成后的回调（如 SOCKS5 延迟 CONNECT 应答；空 = 无需回调）
        std::function<net::awaitable<void>(preview::fault::code)> post_dial;
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
         * @param inbound 已识别协议的入站传输
         * @return 握手结果（目标地址、数据面通道与拨号后回调）
         */
        virtual auto accept(preview::shared_transmission inbound)
            -> net::awaitable<AcceptResult> = 0;

        /**
         * @brief 处理器名称
         * @return 协议名（如 "socks5"/"trojan"，用于日志与诊断）
         */
        [[nodiscard]] virtual auto name() const -> std::string_view = 0;
    };

} // namespace preview::runtime::handler
