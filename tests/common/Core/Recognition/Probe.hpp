/**
 * @file Probe.hpp
 * @brief 首包探测（预读 + 协议类型检测）
 * @details 从传输层预读最多 24 字节，检测协议类型。
 *          预读数据经 Preview 包装回注（不丢失）。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <common/Core/Recognition/Protocol.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Core/Transport/Preview.hpp>

namespace Preview::Recognition
{

    namespace net = boost::asio;

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
     * @brief 预读并检测协议类型
     * @param transport 底层传输
     * @param MaxSize 最大预读字节数（≤ 24）
     * @return 探测结果
     * @details 预读数据保留在结果中，调用方可用 WrapWithPreview 回注。
     */
    [[nodiscard]] inline auto Probe(Transmission &transport, std::size_t MaxSize = MaxProbeSize)
        -> net::awaitable<ProbeResult>
    {
        ProbeResult Result;
        const auto Peek = (std::min)(MaxSize, MaxProbeSize);
        auto span = std::span(Result.PreRead.data(), Peek);

        std::error_code ec;
        const auto N = co_await transport.async_read_some(span, ec);
        if (ec || N == 0)
        {
            co_return Result;
        }
        Result.PreReadSize = N;

        std::array<std::uint8_t, MaxProbeSize> Bytes{};
        for (std::size_t I = 0; I < N; ++I)
        {
            Bytes[I] = std::to_integer<std::uint8_t>(Result.PreRead[I]);
        }
        Result.Type = Detect(std::span<const std::uint8_t>(Bytes.data(), N));
        Result.success = Result.Type != ProtocolType::Unknown;
        co_return Result;
    }

    /**
     * @brief 预读数据回注（Preview 包装）
     * @param transport 已消费预读的传输
     * @param preread 预读数据
     * @return 包装后的传输（回放预读）
     */
    [[nodiscard]] inline auto WrapPreread(SharedTransmission transport,std::span<const std::byte> preread) 
        -> SharedTransmission
    {
        if (preread.empty())
        {
            return transport;
        }
        return Preview::Transport::WrapWithPreview(std::move(transport), preread);
    }

} // namespace Preview::Recognition
