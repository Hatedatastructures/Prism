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

#include <cstring>

#include <array>
#include <charconv>

#include <common/core/memory/container.hpp>
#include <common/core/http3/qpack.hpp>

#include <cstdint>
#include <span>
#include <string_view>

namespace psm::protocol::hysteria2::h3 {

    /// Hysteria2 认证相关常量
    inline constexpr std::uint64_t frame_headers = 0x01;  ///< HTTP/3 HEADERS 帧类型
    inline constexpr std::uint64_t frame_data = 0x00;     ///< HTTP/3 DATA 帧类型
    inline constexpr std::uint64_t frame_settings = 0x04; ///< HTTP/3 SETTINGS 帧类型
    inline constexpr std::uint16_t status_auth_ok = 233;  ///< Hysteria2 认证成功状态码

    /**
     * @struct auth_request
     * @brief 解码后的认证请求
     */
    struct auth_request
    {
        memory::string method; ///< :method
        memory::string host;   ///< :authority
        memory::string path;   ///< :path
        memory::string auth;   ///< Hysteria-Auth 头
        std::uint64_t rx{0};   ///< Hysteria-CC-RX 头

        explicit auth_request(memory::resource_pointer mr) : method(mr), host(mr), path(mr), auth(mr)
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
    [[nodiscard]] auto encode_auth_response(std::uint16_t status, bool udp_enabled, std::uint64_t rx,
                                            std::span<std::byte> out) -> std::size_t;



    namespace
    {
        /**
         * @brief 查找头字段
         * @param fields 头字段列表
         * @param name 目标字段名
         * @return 匹配的字段值，未找到返回空视图
         */
        [[nodiscard]] auto find_header(const memory::vector<qpack::header_field> &fields,
                                       const std::string_view name) -> std::string_view
        {
            for (const auto &f : fields)
            {
                if (f.name == name)
                {
                    return std::string_view(f.value.data(), f.value.size());
                }
            }
            return {};
        }
    } // namespace

    inline auto parse_auth_request(const std::span<const std::uint8_t> data, auth_request &out,
                                   const memory::resource_pointer mr) -> bool
    {
        auto fields = qpack::decode_header_block(data, mr);

        out.method.assign(find_header(fields, ":method"));
        out.host.assign(find_header(fields, ":authority"));
        out.path.assign(find_header(fields, ":path"));
        out.auth.assign(find_header(fields, "hysteria-auth"));

        const auto rx_str = find_header(fields, "hysteria-cc-rx");
        out.rx = 0;
        if (!rx_str.empty())
        {
            std::from_chars(rx_str.data(), rx_str.data() + rx_str.size(), out.rx);
        }

        // 认证请求必须匹配 POST https://hysteria/auth
        return out.method == "POST" && out.path == "/auth" && !out.auth.empty();
    }

    inline auto encode_auth_response(const std::uint16_t status, const bool udp_enabled, const std::uint64_t rx,
                                     const std::span<std::byte> out) -> std::size_t
    {
        // QPACK 块：前缀 + :status + Hysteria-UDP + Hysteria-CC-RX + Hysteria-Padding
        std::array<std::uint8_t, 512> block{};
        std::size_t offset = qpack::encode_prefix(block);

        // :status 字段（静态表无 233 条目，用字面量）
        char status_buf[4];
        const auto [se, sec] = std::to_chars(status_buf, status_buf + sizeof(status_buf), status);
        const auto status_str = std::string_view(status_buf, static_cast<std::size_t>(se - status_buf));
        offset += qpack::encode_literal(
            ":status", status_str, std::span<std::uint8_t>(block.data() + offset, block.size() - offset));

        // Hysteria-UDP: true
        offset +=
            qpack::encode_literal("hysteria-udp", udp_enabled ? "true" : "false",
                                  std::span<std::uint8_t>(block.data() + offset, block.size() - offset));

        // Hysteria-CC-RX: <rx>
        char rx_buf[24];
        const auto [re, rec] = std::to_chars(rx_buf, rx_buf + sizeof(rx_buf), rx);
        const auto rx_str = std::string_view(rx_buf, static_cast<std::size_t>(re - rx_buf));
        offset += qpack::encode_literal(
            "hysteria-cc-rx", rx_str, std::span<std::uint8_t>(block.data() + offset, block.size() - offset));

        // Hysteria-Padding: 0（客户端解析用，填 0 表示无 padding）
        offset += qpack::encode_literal(
            "hysteria-padding", "0", std::span<std::uint8_t>(block.data() + offset, block.size() - offset));

        // HTTP/3 帧头：type=HEADERS(1) + length
        std::size_t n = 0;
        if (out.size() < 2 + offset)
        {
            return 0;
        }
        out[n++] = static_cast<std::byte>(frame_headers); // varint 1
        // length varint（offset < 128 通常成立；超长用多字节编码）
        auto len_rest = offset;
        if (len_rest < 128)
        {
            out[n++] = static_cast<std::byte>(len_rest);
        }
        else
        {
            // 通用 varint 编码（保留前缀位 0x00）
            out[n++] = static_cast<std::byte>(static_cast<std::uint8_t>(len_rest & 0x7F) | 0x80);
            len_rest >>= 7;
            while (len_rest >= 128)
            {
                if (out.size() <= n)
                {
                    return 0;
                }
                out[n++] = static_cast<std::byte>(static_cast<std::uint8_t>((len_rest & 0x7F) | 0x80));
                len_rest >>= 7;
            }
            if (out.size() <= n)
            {
                return 0;
            }
            out[n++] = static_cast<std::byte>(len_rest);
        }
        if (out.size() < n + offset)
        {
            return 0;
        }
        std::memcpy(out.data() + n, block.data(), offset);
        return n + offset;
    }


} // namespace psm::protocol::hysteria2::h3
