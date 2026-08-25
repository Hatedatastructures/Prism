/**
 * @file Auth.hpp
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

#include <common/Core/Memory/Container.hpp>
#include <common/Protocols/Http3/Qpack.hpp>

#include <cstdint>
#include <span>
#include <string_view>

namespace Preview::Http3 {

    /// Hysteria2 认证相关常量
    inline constexpr std::uint64_t FrameHeaders = 0x01;  ///< HTTP/3 HEADERS 帧类型
    inline constexpr std::uint64_t FrameData = 0x00;     ///< HTTP/3 DATA 帧类型
    inline constexpr std::uint64_t FrameSettings = 0x04; ///< HTTP/3 SETTINGS 帧类型
    inline constexpr std::uint16_t StatusAuthOk = 233;  ///< Hysteria2 认证成功状态码

    /**
     * @struct AuthRequest
     * @brief 解码后的认证请求
     */
    struct AuthRequest
    {
        std::string Method; ///< :Method
        std::string Host;  ///< :authority
        std::string Path;   ///< :Path
        std::string Auth;   ///< Hysteria-Auth 头
        std::uint64_t Rx{0};   ///< Hysteria-CC-RX 头

        explicit AuthRequest(Preview::Memory::ResourcePointer mr) : Method(mr), Host(mr), Path(mr), Auth(mr)
        {
        }
    };

    /**
     * @brief 解析认证请求 HEADERS 帧载荷（QPACK 块 → 头字段）
     * @param Data HEADERS 帧载荷（QPACK 编码头块）
     * @param out 输出认证请求
     * @param mr 内存资源
     * @return 是否成功（含 :Method POST / :Path /Auth 校验）
     */
    [[nodiscard]] auto ParseAuthRequest(std::span<const std::uint8_t> Data, AuthRequest &out,
                                          Preview::Memory::ResourcePointer mr) -> bool;

    /**
     * @brief 编码认证响应 HEADERS 帧（含帧头 + QPACK 块）
     * @param status 状态码（233）
     * @param udp_enabled 是否启用 UDP
     * @param Rx 拥塞控制接收速率（0 = 无限制）
     * @param out 输出缓冲区
     * @return 写入字节数，0 失败
     * @details 输出完整 HTTP/3 HEADERS 帧：
     *          [Frame Type varint=1][length varint][QPACK 块]
     */
    [[nodiscard]] auto EncodeAuthResponse(std::uint16_t status, bool udp_enabled, std::uint64_t Rx,
                                            std::span<std::byte> out) -> std::size_t;



    namespace
    {
        /**
         * @brief 查找头字段
         * @param fields 头字段列表
         * @param Name 目标字段名
         * @return 匹配的字段值，未找到返回空视图
         */
        [[nodiscard]] auto FindHeader(const std::vector<Qpack::HeaderField> &fields,
                                       const std::string_view Name) -> std::string_view
        {
            for (const auto &f : fields)
            {
                if (f.Name == Name)
                {
                    return std::string_view(f.value.data(), f.value.size());
                }
            }
            return {};
        }
    } // namespace

    inline auto ParseAuthRequest(std::span<const std::uint8_t> Data, AuthRequest &out,
                                   const Preview::Memory::ResourcePointer mr) -> bool
    {
        auto fields = Qpack::DecodeHeaderBlock(Data, mr);

        out.Method.assign(FindHeader(fields, ":Method"));
        out.Host.assign(FindHeader(fields, ":authority"));
        out.Path.assign(FindHeader(fields, ":Path"));
        out.Auth.assign(FindHeader(fields, "hysteria-Auth"));

        const auto RxStr = FindHeader(fields, "hysteria-cc-Rx");
        out.Rx = 0;
        if (!RxStr.empty())
        {
            std::from_chars(RxStr.data(), RxStr.data() + RxStr.size(), out.Rx);
        }

        // 认证请求必须匹配 POST https://hysteria/Auth
        return out.Method == "POST" && out.Path == "/Auth" && !out.Auth.empty();
    }

    inline auto EncodeAuthResponse(const std::uint16_t status, const bool udp_enabled, const std::uint64_t Rx,
                                     const std::span<std::byte> out) -> std::size_t
    {
        // QPACK 块：前缀 + :status + Hysteria-UDP + Hysteria-CC-RX + Hysteria-Padding
        std::array<std::uint8_t, 512> block{};
        std::size_t offset = Qpack::EncodePrefix(block);

        // :status 字段（静态表无 233 条目，用字面量）
        char status_buf[4];
        const auto [se, sec] = std::to_chars(status_buf, status_buf + sizeof(status_buf), status);
        const auto StatusStr = std::string_view(status_buf, static_cast<std::size_t>(se - status_buf));
        offset += Qpack::EncodeLiteral(
            ":status", StatusStr, std::span<std::uint8_t>(block.data() + offset, block.size() - offset));

        // Hysteria-UDP: true
        const char *udp_value = "false";
        if (udp_enabled)
        {
            udp_value = "true";
        }
        offset +=
            Qpack::EncodeLiteral("hysteria-udp", udp_value,
                                  std::span<std::uint8_t>(block.data() + offset, block.size() - offset));

        // Hysteria-CC-RX: <Rx>
        char rx_buf[24];
        const auto [re, rec] = std::to_chars(rx_buf, rx_buf + sizeof(rx_buf), Rx);
        const auto RxStr = std::string_view(rx_buf, static_cast<std::size_t>(re - rx_buf));
        offset += Qpack::EncodeLiteral(
            "hysteria-cc-Rx", RxStr, std::span<std::uint8_t>(block.data() + offset, block.size() - offset));

        // Hysteria-Padding: 0（客户端解析用，填 0 表示无 padding）
        offset += Qpack::EncodeLiteral(
            "hysteria-padding", "0", std::span<std::uint8_t>(block.data() + offset, block.size() - offset));

        // HTTP/3 帧头：Type=HEADERS(1) + length
        std::size_t n = 0;
        if (out.size() < 2 + offset)
        {
            return 0;
        }
        out[n++] = static_cast<std::byte>(FrameHeaders); // varint 1
        // length varint（offset < 128 通常成立；超长用多字节编码）
        auto LenRest = offset;
        if (LenRest < 128)
        {
            out[n++] = static_cast<std::byte>(LenRest);
        }
        else
        {
            // 通用 varint 编码（保留前缀位 0x00）
            out[n++] = static_cast<std::byte>(static_cast<std::uint8_t>(LenRest & 0x7F) | 0x80);
            LenRest >>= 7;
            while (LenRest >= 128)
            {
                if (out.size() <= n)
                {
                    return 0;
                }
                out[n++] = static_cast<std::byte>(static_cast<std::uint8_t>((LenRest & 0x7F) | 0x80));
                LenRest >>= 7;
            }
            if (out.size() <= n)
            {
                return 0;
            }
            out[n++] = static_cast<std::byte>(LenRest);
        }
        if (out.size() < n + offset)
        {
            return 0;
        }
        std::memcpy(out.data() + n, block.data(), offset);
        return n + offset;
    }


} // namespace Preview::Http3
