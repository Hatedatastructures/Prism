/**
 * @file Probe.hpp
 * @brief 首包探测（预读 + 协议类型检测）
 * @details 从传输层预读最多 24 字节，检测协议类型。
 *          预读数据经 Preview 包装回注（不丢失）。
 */

#pragma once

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <preview/Runtime/Recognition/Protocol.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Transport/Preview.hpp>

namespace Preview::Recognition
{

    namespace Net = boost::asio;

    /**
     * @struct ProbeResult
     * @brief 探测结果
     */
    struct ProbeResult
    {
        ProtocolType Type{ProtocolType::Unknown}; ///< 检测到的协议类型
        std::array<std::byte, 24> PreRead{};       ///< 预读数据
        std::size_t PreReadSize{0};               ///< 预读字节数
        bool success{false};                        ///< 检测成功（类型非 unknown）
    };

    /// 最大预读字节数
    inline constexpr std::size_t MaxProbeSize = 24;

    /**
     * @brief 判断当前字节是否仍可能是已知协议的前缀
     * @param Data 当前已预读字节
     * @return true = 继续等待更多字节可能得到确定分类
     * @details 未知首包不能无条件等待到 24 字节，否则协议专用
     *          AcceptProtocol 场景会因普通应用数据而永久阻塞。
     */
    [[nodiscard]] inline auto CouldBeProtocolPrefix(
        std::span<const std::uint8_t> Data) noexcept -> bool
    {
        if (Data.empty())
        {
            return false;
        }

        const auto StartsWith = [Data](std::span<const std::uint8_t> Prefix)
        {
            return Data.size() <= Prefix.size() &&
                   std::equal(Data.begin(), Data.end(), Prefix.begin());
        };

        // TLS 在出现不匹配字节后即可确定不是候选协议；Trojan 没有稳定首包魔数，
        // 必须由配置候选凭据校验，不能在 legacy probe 中等待 CRLF 序列。
        constexpr std::array<std::uint8_t, 2> TlsPrefix{0x16, 0x03};
        if (StartsWith(TlsPrefix))
        {
            return true;
        }
        if (Data[0] == 0x16)
        {
            return false;
        }

        // SOCKS5 需要第二字节 NMETHODS 才能确认；非法方法数量立即停止等待。
        if (Data[0] == 0x05)
        {
            return Data.size() < 2;
        }

        // 结构化 VLESS 以版本 0 开始，需要固定头和受限附加字段才能校验。
        if (Data[0] == 0x00)
        {
            if (Data.size() < 18)
            {
                return true;
            }
            const auto AddonLength = static_cast<std::size_t>(Data[17]);
            const auto Need = 18 + AddonLength + 4;
            return Need <= MaxProbeSize && Data.size() < Need;
        }

        // HTTP 方法名是首包分片后仍可继续判定的文本前缀。
        constexpr std::string_view Methods[] = {
            "GET ", "POST ", "CONNECT ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "TRACE ", "PATCH "};
        for (const auto Method : Methods)
        {
            if (Data.size() <= Method.size() &&
                std::equal(Data.begin(), Data.end(), Method.begin()))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief 预读并检测协议类型
     * @param transport 底层传输
     * @param MaxSize 最大预读字节数（≤ 24）
     * @return 探测结果
     * @details 预读数据保留在结果中，调用方可用 WrapWithPreview 回注。
     */
    [[nodiscard]] inline auto Probe(Transmission &transport, std::size_t MaxSize = MaxProbeSize)
        -> Net::awaitable<ProbeResult>
    {
        ProbeResult Result;
        const auto Peek = (std::min)(MaxSize, MaxProbeSize);

        std::array<std::uint8_t, MaxProbeSize> Bytes{};
        while (Result.PreReadSize < Peek)
        {
            std::error_code ec;
            const auto N = co_await transport.async_read_some(
                std::span<std::byte>(Result.PreRead.data() + Result.PreReadSize,
                                     Peek - Result.PreReadSize),
                ec);
            if (N > Peek - Result.PreReadSize)
            {
                co_return Result;
            }
            for (std::size_t I = 0; I < N; ++I)
            {
                Bytes[Result.PreReadSize + I] = std::to_integer<std::uint8_t>(
                    Result.PreRead[Result.PreReadSize + I]);
            }
            Result.PreReadSize += N;
            Result.Type = Detect(std::span<const std::uint8_t>(Bytes.data(), Result.PreReadSize));
            if (ec || N == 0)
            {
                co_return Result;
            }
            if (Result.Type != ProtocolType::Unknown)
            {
                Result.success = true;
                break;
            }
            if (!CouldBeProtocolPrefix(
                    std::span<const std::uint8_t>(Bytes.data(), Result.PreReadSize)))
            {
                break;
            }
        }
        co_return Result;
    }

    /**
     * @brief 预读数据回注（Preview 包装）
     * @param transport 已消费预读的传输
     * @param preread 预读数据
     * @return 包装后的传输（回放预读）
     */
    [[nodiscard]] inline auto WrapPreread(SharedTransmission transport, std::span<const std::byte> preread)
        -> SharedTransmission
    {
        if (preread.empty())
        {
            return transport;
        }
        return Preview::Transport::WrapWithPreview(std::move(transport), preread);
    }

} // namespace Preview::Recognition
