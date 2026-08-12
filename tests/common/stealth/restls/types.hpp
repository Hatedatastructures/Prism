/**
 * @file types.hpp
 * @brief Restls 协议基础类型
 * @details Restls 是 TLS 探测抵抗伪装方案（对齐 restls-client-go）：
 *          - 服务端用 BLAKE3 keyed 派生 server_mask 加密首个 TLS 记录
 *          - 每条应用数据记录带 8 字节 auth_mac + 4 字节 XOR mask
 *          - 方向标签：server-to-client / client-to-server
 *          本测试库实现纯逻辑认证编解码（不含真实 TLS 传输）。
 * @note 参考 restls-client-go 协议规范。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace psmtest::restls
{

    /// 握手阶段 MAC 长度（server_mask）
    inline constexpr std::size_t hs_maclen = 16;

    /// 应用数据 MAC 长度（auth_mac）
    inline constexpr std::size_t appdata_maclen = 8;

    /// XOR 掩码长度
    inline constexpr std::size_t mask_len = 4;

    /// 认证头总长 = auth_mac + mask
    inline constexpr std::size_t auth_hdrlen = appdata_maclen + mask_len;

    /// 方向标签
    inline constexpr std::string_view dir_toclient = "server-to-client";
    inline constexpr std::string_view dir_toserver = "client-to-server";

    /// BLAKE3 derive_key 上下文
    inline constexpr std::string_view secret_ctx = "restls-traffic-key";

    /// 数据流方向
    enum class flow_direction : std::uint8_t
    {
        /// 服务端 → 客户端
        to_client,
        /// 客户端 → 服务端
        to_server,
    };

} // namespace psmtest::restls
