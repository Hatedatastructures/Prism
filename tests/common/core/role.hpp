/**
 * @file role.hpp
 * @brief 协议连接角色
 * @details 定义协议中继器的角色枚举，区分服务端（接收握手）与
 * 客户端（发起握手）。测试库中同一条传输链上需要两端互操作，
 * 通过 role 控制 handshake() 的握手方向。
 */

#pragma once

namespace preview
{

    /// 协议连接角色
    enum class role
    {
        /// 服务端：接收对端握手请求并响应（对齐主库默认行为）
        server,
        /// 客户端：主动发起握手
        client,
    };

} // namespace preview
