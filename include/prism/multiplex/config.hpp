/**
 * @file config.hpp
 * @brief 多路复用通用配置
 * @details 定义多路复用层的协议选择和全局开关，各协议的完整配置参数
 * 分别定义在对应子目录的 config.hpp 中（smux::config、yamux::config）。
 *
 * @note 默认配置适用于大多数场景，可根据实际需求调整
 */
#pragma once

#include <cstdint>

#include <prism/multiplex/smux/config.hpp>
#include <prism/multiplex/yamux/config.hpp>

namespace psm::multiplex
{
    /**
     * @enum protocol_type
     * @brief 多路复用协议类型
     * @details 定义支持的多路复用协议枚举，用于 sing-mux 协商后选择具体实现。
     */
    enum class protocol_type : std::uint8_t
    {
        smux = 0,  // xtaci/smux v1 + sing-mux 协商
        yamux = 1  // Hashicorp/yamux + sing-mux 协商
    }; // enum protocol_type

    /**
     * @struct config
     * @brief 多路复用配置入口
     * @details 聚合协议选择、全局开关和各协议独立配置。
     * 协议特有参数见 smux::config 和 yamux::config。
     */
    struct config
    {
        protocol_type protocol = protocol_type::smux; // 多路复用协议类型

        bool enabled = false; // 是否启用多路复用服务端

        smux::config smux; // smux 协议配置
        yamux::config yamux; // yamux 协议配置
    }; // struct config

} // namespace psm::multiplex
