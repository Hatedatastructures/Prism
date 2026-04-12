/**
 * @file config.hpp
 * @brief VLESS 协议配置结构
 * @details 定义 VLESS 协议的配置参数。用户认证已统一到
 * agent::authentication 中，VLESS 通过 account::directory
 * 查询 UUID 凭证。
 */

#pragma once

namespace psm::protocol::vless
{
    /**
     * @struct config
     * @brief VLESS 协议配置
     * @details VLESS 协议当前无需独立配置参数。用户认证已统一到
     * agent::authentication::user::uuid 字段，启动时自动注册到
     * account::directory。
     */
    struct config
    {
    };
} // namespace psm::protocol::vless
