/**
 * @file h3_auth.hpp
 * @brief Hysteria2 HTTP/3 认证辅助（QPACK 头块 + HTTP/3 HEADERS 帧）
 * @details 实现 mihomo 客户端兼容的最小 HTTP/3 认证：
 *          1. 解析请求流上的 HEADERS 帧（QPACK 解码）
 *          2. 提取 Hysteria-Auth 头并校验
 *          3. 编码认证响应 HEADERS 帧（:status 233 + Hysteria-UDP/CC-RX/Padding）
 *          仅支持认证所需的最小帧集，不做通用 HTTP/3。
 */

#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/hysteria2/qpack.hpp>

#include <cstdint>
#include <span>
#include <string_view>

namespace psm::protocol::hysteria2::h3
{

    /// Hysteria2 认证相关常量
    inline constexpr std::uint64_t frame_headers = 0x01;    ///< HTTP/3 HEADERS 帧类型
    inline constexpr std::uint64_t frame_data = 0x00;       ///< HTTP/3 DATA 帧类型
    inline constexpr std::uint64_t frame_settings = 0x04;   ///< HTTP/3 SETTINGS 帧类型
    inline constexpr std::uint16_t status_auth_ok = 233;    ///< Hysteria2 认证成功状态码

    /**
     * @struct auth_request
     * @brief 解码后的认证请求
     */
    struct auth_request
    {
        memory::string method;    ///< :method
        memory::string host;      ///< :authority
        memory::string path;      ///< :path
        memory::string auth;      ///< Hysteria-Auth 头
        std::uint64_t rx{0};      ///< Hysteria-CC-RX 头

        explicit auth_request(memory::resource_pointer mr)
            : method(mr), host(mr), path(mr), auth(mr)
        {
        }
    };

    /**
     * @brief 解析认证请求 HEADERS 帧载荷（QPACK 块 → 头字段）
     * @param data HEADERS 帧载荷（QPACK 编码头块）
     * @param out 输出认证请求
     * @param mr 内存资源
     * @return 是否成功（含 :method POST / :path /auth 校验）
     */
    [[nodiscard]] auto parse_auth_request(std::span<const std::uint8_t> data, auth_request &out,
                                          memory::resource_pointer mr) -> bool;

    /**
     * @brief 编码认证响应 HEADERS 帧（含帧头 + QPACK 块）
     * @param status 状态码（233）
     * @param udp_enabled 是否启用 UDP
     * @param rx 拥塞控制接收速率（0 = 无限制）
     * @param out 输出缓冲区
     * @return 写入字节数，0 失败
     * @details 输出完整 HTTP/3 HEADERS 帧：
     *          [frame type varint=1][length varint][QPACK 块]
     */
    [[nodiscard]] auto encode_auth_response(std::uint16_t status, bool udp_enabled,
                                            std::uint64_t rx, std::span<std::byte> out)
        -> std::size_t;

} // namespace psm::protocol::hysteria2::h3
