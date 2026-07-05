/**
 * @file config.hpp
 * @brief Native TLS 兜底方案配置
 * @details 定义 native 方案的运行时配置，控制启用状态和
 * 无 SNI 匹配时的默认兜底行为。Native 是纯本地 TLS 握手，
 * 不连接外部后端，不会污染 socket。
 */
#pragma once

#include <prism/foundation/memory/container.hpp>


namespace psm::stealth::native
{

    /**
     * @struct config
     * @brief Native TLS 兜底方案配置
     * @details 控制 native 方案的启用状态和无 SNI 时的行为。
     * enabled 为 false 时 native 不参与任何检测和执行。
     * default_tls 指定无 SNI 匹配时的兜底方案名。
     */
    struct config
    {
        bool enabled = true; ///< 是否启用 native 兜底
    };
} // namespace psm::stealth::native
