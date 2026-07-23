/**
 * @file handler.hpp
 * @brief 协议处理器抽象基类 + 工厂
 * @details 定义统一的协议处理器接口，消除 session::diversion 中的 switch-case。
 *          每种协议（HTTP/SOCKS5/Trojan/VLESS/SS2022）实现 handler 子类，
 *          由工厂函数 make_protocol_handler 创建。
 *
 *          handler_params 只持 session_resources& + data span 两个字段，
 *          worker 级和 session 级资源通过 session_resources 透传获取。
 */

#pragma once

#include <prism/net/connect/types.hpp>
#include <prism/resource/session.hpp>

#include <boost/asio.hpp>

#include <cstddef>
#include <memory>
#include <span>

namespace psm::protocol
{

    using psm::connect::protocol_type;
    using psm::connect::target;

    namespace net = boost::asio;

    /**
     * @class protocol_handler
     * @brief 协议处理器抽象基类
     */
    class protocol_handler
    {
    public:
        virtual ~protocol_handler() noexcept = default;

        /**
         * @brief 执行协议处理（握手 → 解析目标 → 拨号 → 隧道转发）
         */
        virtual auto run() -> net::awaitable<void> = 0;
    };

    /**
     * @struct handler_params
     * @brief 协议处理器构造参数（2 字段瘦身后形态）
     * @details res 持 session_resources 引用，data 是预读数据。
     *          trace 折叠进 session_resources.trace_ctx()，不再单独传。
     */
    struct handler_params
    {
        psm::resource::session &res;  ///< 会话资源（含 worker 级 + session 级）
        std::span<const std::byte> data;         ///< 预读数据

        explicit handler_params(psm::resource::session &r, std::span<const std::byte> d)
            : res(r), data(d) {}
    };

    /**
     * @brief 创建协议处理器
     */
    [[nodiscard]] auto make_protocol_handler(
        protocol_type type, handler_params params) -> std::unique_ptr<protocol_handler>;

} // namespace psm::protocol
