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
     * @brief 写入 HTTP/3 varint（RFC 9000 §16：高 2 位为长度码，其余大端）
     * @param out 输出缓冲区
     * @param[in,out] N 写入偏移，成功后推进实际写入字节数
     * @param Value 待编码值
     * @return 是否写入成功（缓冲不足或值溢出返回 false）
     * @note 与 HPACK/QPACK 整数编码不同：H3 帧头 varint 首字节高 2 位是长度码，
     *       裸写 ≥0x40 的单字节会被对端误读为多字节 varint
     */
    [[nodiscard]] inline auto WriteFrameVarint(std::span<std::byte> out, std::size_t &N,
                                               const std::uint64_t Value) -> bool
    {
        std::size_t Need = 1;
        std::uint8_t Tag = 0x00;
        if (Value <= 0x3F)
        {
            Need = 1;
        }
        else if (Value <= 0x3FFF)
        {
            Need = 2;
            Tag = 0x40;
        }
        else if (Value <= 0x3FFFFFFF)
        {
            Need = 4;
            Tag = 0x80;
        }
        else if (Value <= 0x3FFFFFFFFFFFFFFFULL)
        {
            Need = 8;
            Tag = 0xC0;
        }
        else
        {
            return false;
        }
        if (out.size() < N + Need)
        {
            return false;
        }
        for (std::size_t I = 0; I < Need; ++I)
        {
            const auto Shift = 8 * (Need - 1 - I);
            auto Byte = static_cast<std::uint8_t>((Value >> Shift) & 0xFF);
            if (I == 0)
            {
                Byte |= Tag;
            }
            out[N++] = static_cast<std::byte>(Byte);
        }
        return true;
    }

    /**
     * @struct AuthRequest
     * @brief 解码后的认证请求
     */
    struct AuthRequest
    {
        Preview::Memory::String Method; ///< :method
        Preview::Memory::String Host;   ///< :authority
        Preview::Memory::String Path;   ///< :path
        Preview::Memory::String Auth;   ///< Hysteria-Auth 头
        std::uint64_t Rx{0};            ///< Hysteria-CC-RX 头

        explicit AuthRequest(Preview::Memory::ResourcePointer mr) : Method(mr), Host(mr), Path(mr), Auth(mr)
        {
        }
    };

    /**
     * @brief 解析认证请求 HEADERS 帧载荷（QPACK 块 → 头字段）
     * @param Data HEADERS 帧载荷（QPACK 编码头块）
     * @param out 输出认证请求
     * @param mr 内存资源
     * @return 是否成功（含 :method POST / :path /Auth 校验）
     */
    [[nodiscard]] auto ParseAuthRequest(std::span<const std::uint8_t> Data, AuthRequest &out,
                                          Preview::Memory::ResourcePointer mr) -> bool;

    /**
     * @brief 编码认证响应 HEADERS 帧（含帧头 + QPACK 块）
     * @param status 状态码（233）
     * @param UdpEnabled 是否启用 UDP
     * @param Rx 拥塞控制接收速率（0 = 无限制）
     * @param out 输出缓冲区
     * @return 写入字节数，0 失败
     * @details 输出完整 HTTP/3 HEADERS 帧：
     *          [Frame Type varint=1][length varint][QPACK 块]
     */
    [[nodiscard]] auto EncodeAuthResponse(std::uint16_t status, bool UdpEnabled, std::uint64_t Rx,
                                            std::span<std::byte> out) -> std::size_t;



    namespace
    {
        /**
         * @brief 查找头字段
         * @param fields 头字段列表
         * @param Name 目标字段名
         * @return 匹配的字段值，未找到返回空视图
         */
        [[nodiscard]] auto FindHeader(const Preview::Memory::vector<Qpack::HeaderField> &Fields,
                                       const std::string_view Name) -> std::string_view
        {
            for (const auto &f : Fields)
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
        auto Fields = Qpack::DecodeHeaderBlock(Data, mr);

        out.Method.assign(FindHeader(Fields, ":method"));
        out.Host.assign(FindHeader(Fields, ":authority"));
        out.Path.assign(FindHeader(Fields, ":path"));
        out.Auth.assign(FindHeader(Fields, "hysteria-auth"));

        const auto RxStr = FindHeader(Fields, "hysteria-cc-rx");
        out.Rx = 0;
        if (!RxStr.empty())
        {
            std::from_chars(RxStr.data(), RxStr.data() + RxStr.size(), out.Rx);
        }

        // 认证请求必须匹配 POST https://hysteria/Auth
        return out.Method == "POST" && out.Path == "/Auth" && !out.Auth.empty();
    }

    inline auto EncodeAuthResponse(const std::uint16_t status, const bool UdpEnabled, const std::uint64_t Rx,
                                     const std::span<std::byte> out) -> std::size_t
    {
        // QPACK 块：前缀 + :status + Hysteria-UDP + Hysteria-CC-RX + Hysteria-Padding
        std::array<std::uint8_t, 512> block{};
        std::size_t Offset = Qpack::EncodePrefix(block);

        // :status 字段（静态表无 233 条目，用字面量）
        char StatusBuf[4];
        const auto [se, sec] = std::to_chars(StatusBuf, StatusBuf + sizeof(StatusBuf), status);
        const auto StatusStr = std::string_view(StatusBuf, static_cast<std::size_t>(se - StatusBuf));
        Offset += Qpack::EncodeLiteral(
            ":status", StatusStr, std::span<std::uint8_t>(block.data() + Offset, block.size() - Offset));

        // Hysteria-UDP: true
        const char *UdpValue = "false";
        if (UdpEnabled)
        {
            UdpValue = "true";
        }
        Offset +=
            Qpack::EncodeLiteral("hysteria-udp", UdpValue,
                                  std::span<std::uint8_t>(block.data() + Offset, block.size() - Offset));

        // Hysteria-CC-RX: <Rx>
        char RxBuf[24];
        const auto [re, rec] = std::to_chars(RxBuf, RxBuf + sizeof(RxBuf), Rx);
        const auto RxStr = std::string_view(RxBuf, static_cast<std::size_t>(re - RxBuf));
        Offset += Qpack::EncodeLiteral(
            "hysteria-cc-rx", RxStr, std::span<std::uint8_t>(block.data() + Offset, block.size() - Offset));

        // Hysteria-Padding: 0（客户端解析用，填 0 表示无 padding）
        Offset += Qpack::EncodeLiteral(
            "hysteria-padding", "0", std::span<std::uint8_t>(block.data() + Offset, block.size() - Offset));

        // HTTP/3 帧头：Type=HEADERS(1) + length varint（RFC 9000 §16 格式）
        std::size_t N = 0;
        if (!WriteFrameVarint(out, N, FrameHeaders) || !WriteFrameVarint(out, N, Offset))
        {
            return 0;
        }
        if (out.size() < N + Offset)
        {
            return 0;
        }
        std::memcpy(out.data() + N, block.data(), Offset);
        return N + Offset;
    }


} // namespace Preview::Http3
