/**
 * @file forward.hpp
 * @brief 正向代理转发
 * @details 组合 dial + tunnel 操作，提供完整的 TCP 隧道转发流程。
 */
#pragma once

#include <boost/asio.hpp>
#include <prism/context/context.hpp>
#include <prism/transport/transmission.hpp>
#include <prism/protocol/common/target.hpp>

namespace psm::connect
{
    namespace net = boost::asio;
    using shared_transmission = transport::shared_transmission;

    /**
     * @struct forward_options
     * @brief 正向代理转发选项
     * @details 组合拨号+隧道转发所需的全部参数。
     */
    struct forward_options
    {
        std::string_view label;               ///< 协议标签，用于日志记录
        const protocol::target &target;       ///< 目标地址信息
        shared_transmission inbound;          ///< 入站传输对象
    };

    /**
     * @brief 拨号连接上游并建立双向隧道
     * @param ctx 会话上下文，提供路由器和会话信息
     * @param opts 转发选项（标签、目标、入站传输）
     * @return 协程对象，隧道结束后完成
     * @details 组合 dial + tunnel 操作，所有协议的 TCP 隧道转发共用此函数。
     * 先通过路由器建立到目标的上游连接，连接成功后进入双向隧道转发。
     */
    auto forward(context::session &ctx, forward_options opts) -> net::awaitable<void>;

} // namespace psm::connect
