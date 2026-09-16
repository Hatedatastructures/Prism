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
#include <cstddef>

#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Protocols/Http3/Qpack.hpp>

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
     * @param Output 输出缓冲区
     * @param[in,out] Offset 写入偏移，成功后推进实际写入字节数
     * @param Value 待编码值
     * @return 是否写入成功（缓冲不足或值溢出返回 false）
     * @note 与 HPACK/QPACK 整数编码不同：H3 帧头 varint 首字节高 2 位是长度码，
     *       裸写 ≥0x40 的单字节会被对端误读为多字节 varint
     */
    [[nodiscard]] inline auto WriteFrameVarint(
        std::span<std::byte> Output,
        std::size_t &Offset,
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
        if (Offset > Output.size() || Need > Output.size() - Offset)
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
            Output[Offset++] = static_cast<std::byte>(Byte);
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

        explicit AuthRequest(Preview::Memory::ResourcePointer MemoryResource)
            : Method(MemoryResource),
              Host(MemoryResource),
              Path(MemoryResource),
              Auth(MemoryResource)
        {
        }
    };

    /**
     * @brief HTTP/3 认证响应编码参数
     * @details Out 为调用方持有的输出缓冲，函数只借用其视图。
     */
    struct AuthResponseParameters
    {
        std::uint16_t Status;
        bool UdpEnabled;
        std::uint64_t Rx;
        std::span<std::byte> Out;
    };

    /**
     * @brief 解析认证请求 HEADERS 帧载荷（QPACK 块 → 头字段）
     * @param Data HEADERS 帧载荷（QPACK 编码头块）
     * @param Output 输出认证请求
     * @param MemoryResource 内存资源
     * @return 是否成功（含 :method POST / :path /auth 校验）
     */
    [[nodiscard]] auto ParseAuthRequest(
        std::span<const std::uint8_t> Data,
        AuthRequest &Output,
        Preview::Memory::ResourcePointer MemoryResource) -> bool;

    /**
     * @brief 编码认证响应 HEADERS 帧（含帧头 + QPACK 块）
     * @param Params 响应状态、UDP 开关、接收速率与输出缓冲区
     * @return 写入字节数，0 失败
     * @details 输出完整 HTTP/3 HEADERS 帧：
     *          [Frame Type varint=1][length varint][QPACK 块]
     */
    [[nodiscard]] auto EncodeAuthResponse(const AuthResponseParameters &Params) -> std::size_t;



    namespace
    {
        /**
         * @brief 查找头字段
         * @param Fields 头字段列表
         * @param Name 目标字段名
         * @return 匹配的字段值，未找到返回空视图
         */
        [[nodiscard]] auto FindHeader(
            const Preview::Memory::Vector<Qpack::HeaderField> &Fields,
            const std::string_view Name) -> std::string_view
        {
            for (const auto &Field : Fields)
            {
                if (Field.Name == Name)
                {
                    return std::string_view(Field.value.data(), Field.value.size());
                }
            }
            return {};
        }
    } // namespace

    /**
     * @brief 校验 HTTP/3 请求字段的伪首部约束
     * @param Fields QPACK 解码后的字段列表
     * @return 字段名、伪首部和必需字段均有效时返回 true
     */
    [[nodiscard]] inline auto ValidateAuthRequestFields(
        const Preview::Memory::Vector<Qpack::HeaderField> &Fields) -> bool
    {
        std::size_t MethodCount = 0;
        std::size_t PathCount = 0;
        std::size_t AuthorityCount = 0;
        std::size_t SchemeCount = 0;
        std::size_t AuthCount = 0;
        std::size_t RxCount = 0;
        bool SeenRegularField = false;
        for (const auto &Field : Fields)
        {
            if (Field.Name.empty())
            {
                return false;
            }
            for (const auto Character : Field.Name)
            {
                if (Character >= 'A' && Character <= 'Z')
                {
                    return false;
                }
            }
            if (Field.Name.front() != ':')
            {
                SeenRegularField = true;
                if (Field.Name == "hysteria-auth")
                {
                    ++AuthCount;
                }
                else if (Field.Name == "hysteria-cc-rx")
                {
                    ++RxCount;
                }
                continue;
            }
            if (SeenRegularField)
            {
                return false;
            }
            if (Field.Name == ":method")
            {
                ++MethodCount;
            }
            else if (Field.Name == ":path")
            {
                ++PathCount;
            }
            else if (Field.Name == ":authority")
            {
                ++AuthorityCount;
            }
            else if (Field.Name == ":scheme")
            {
                ++SchemeCount;
            }
            else
            {
                return false;
            }
        }
        return MethodCount == 1 && PathCount == 1 && AuthorityCount <= 1 &&
               SchemeCount <= 1 && AuthCount == 1 && RxCount <= 1;
    }

    inline auto ParseAuthRequest(
        std::span<const std::uint8_t> Data,
        AuthRequest &Output,
        const Preview::Memory::ResourcePointer MemoryResource) -> bool
    {
        Output.Method.clear();
        Output.Host.clear();
        Output.Path.clear();
        Output.Auth.clear();
        Output.Rx = 0;
        auto Fields = Qpack::DecodeHeaderBlock(Data, MemoryResource);
        if (!ValidateAuthRequestFields(Fields))
        {
            return false;
        }

        Output.Method.assign(FindHeader(Fields, ":method"));
        Output.Host.assign(FindHeader(Fields, ":authority"));
        Output.Path.assign(FindHeader(Fields, ":path"));
        Output.Auth.assign(FindHeader(Fields, "hysteria-auth"));

        const auto RxStr = FindHeader(Fields, "hysteria-cc-rx");
        if (!RxStr.empty())
        {
            const auto ParseResult = std::from_chars(
                RxStr.data(), RxStr.data() + RxStr.size(), Output.Rx);
            if (ParseResult.ec != std::errc{} ||
                ParseResult.ptr != RxStr.data() + RxStr.size())
            {
                return false;
            }
        }

        // 认证请求必须匹配 POST https://hysteria/auth
        return Output.Method == "POST" && Output.Path == "/auth" && !Output.Auth.empty();
    }

    namespace
    {
        struct ResponseEncoder
        {
            explicit ResponseEncoder(std::span<std::uint8_t> OutputValue)
                : Output(OutputValue)
            {
            }

            [[nodiscard]] auto AppendLiteral(
                std::string_view Name,
                std::string_view Value) -> bool
            {
                if (Offset > Output.size())
                {
                    return false;
                }
                const auto Remaining = Output.size() - Offset;
                const auto OutputWindow = Output.subspan(Offset);
                const auto EncodedLength = Qpack::EncodeLiteral(
                    Name,
                    Value,
                    OutputWindow);
                if (EncodedLength == 0 || EncodedLength > Remaining)
                {
                    return false;
                }
                Offset += EncodedLength;
                return true;
            }

            std::span<std::uint8_t> Output;
            std::size_t Offset{0};
        };
    } // namespace

    inline auto EncodeAuthResponse(const AuthResponseParameters &Params) -> std::size_t
    {
        // QPACK 块：前缀 + :status + Hysteria-UDP + Hysteria-CC-RX + Hysteria-Padding
        std::array<std::uint8_t, 512> Block{};
        const auto BlockSpan = std::span<std::uint8_t>(Block);
        ResponseEncoder Encoder{BlockSpan};
        Encoder.Offset = Qpack::EncodePrefix(Block);
        if (Encoder.Offset == 0)
        {
            return 0;
        }

        // :status 字段（静态表无 233 条目，用字面量）
        char StatusBuffer[5];
        const auto StatusResult = std::to_chars(
            StatusBuffer,
            StatusBuffer + sizeof(StatusBuffer),
            Params.Status);
        if (StatusResult.ec != std::errc{})
        {
            return 0;
        }
        const auto StatusValue = std::string_view(
            StatusBuffer,
            static_cast<std::size_t>(StatusResult.ptr - StatusBuffer));
        if (!Encoder.AppendLiteral(":status", StatusValue))
        {
            return 0;
        }

        // Hysteria-UDP: true
        const char *UdpValue = "false";
        if (Params.UdpEnabled)
        {
            UdpValue = "true";
        }
        if (!Encoder.AppendLiteral("hysteria-udp", UdpValue))
        {
            return 0;
        }

        // Hysteria-CC-RX: <Rx>
        char RxBuffer[24];
        const auto RxResult = std::to_chars(RxBuffer, RxBuffer + sizeof(RxBuffer), Params.Rx);
        if (RxResult.ec != std::errc{})
        {
            return 0;
        }
        const auto RxValue = std::string_view(
            RxBuffer,
            static_cast<std::size_t>(RxResult.ptr - RxBuffer));
        if (!Encoder.AppendLiteral("hysteria-cc-rx", RxValue))
        {
            return 0;
        }

        // Hysteria-Padding: 0（客户端解析用，填 0 表示无 padding）
        if (!Encoder.AppendLiteral("hysteria-padding", "0"))
        {
            return 0;
        }

        // HTTP/3 帧头：Type=HEADERS(1) + length varint（RFC 9000 §16 格式）
        std::size_t FrameOffset = 0;
        if (!WriteFrameVarint(Params.Out, FrameOffset, FrameHeaders) ||
            !WriteFrameVarint(Params.Out, FrameOffset, Encoder.Offset))
        {
            return 0;
        }
        if (FrameOffset > Params.Out.size() ||
            Encoder.Offset > Params.Out.size() - FrameOffset)
        {
            return 0;
        }
        std::memcpy(Params.Out.data() + FrameOffset, Block.data(), Encoder.Offset);
        return FrameOffset + Encoder.Offset;
    }


} // namespace Preview::Http3
