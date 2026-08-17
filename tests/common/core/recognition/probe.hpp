/**
 * @file probe.hpp
 * @brief 首包探测（预读 + 协议类型检测）
 * @details 从传输层预读最多 24 字节，检测协议类型。
 *          预读数据经 preview 包装回注（不丢失）。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <common/core/recognition/protocol.hpp>
#include <common/core/transmission.hpp>
#include <common/core/transport/preview.hpp>

namespace preview::recognition
{

    namespace net = boost::asio;

    /**
     * @struct probe_result
     * @brief 探测结果
     */
    struct probe_result
    {
        protocol_type type{protocol_type::unknown}; ///< 检测到的协议类型
        std::array<std::byte, 24> pre_read{};       ///< 预读数据
        std::size_t pre_read_size{0};               ///< 预读字节数
        bool success{false};                        ///< 检测成功（类型非 unknown）
    };

    /// 最大预读字节数
    inline constexpr std::size_t max_probe_size = 24;

    /**
     * @brief 预读并检测协议类型
     * @param transport 底层传输
     * @param max_size 最大预读字节数（≤ 24）
     * @return 探测结果
     * @details 预读数据保留在结果中，调用方可用 wrap_with_preview 回注。
     */
    [[nodiscard]] inline auto probe(transmission &transport, std::size_t max_size = max_probe_size)
        -> net::awaitable<probe_result>
    {
        probe_result result;
        const auto peek = (std::min)(max_size, max_probe_size);
        auto span = std::span(result.pre_read.data(), peek);

        std::error_code ec;
        const auto n = co_await transport.async_read_some(span, ec);
        if (ec || n == 0)
        {
            co_return result;
        }
        result.pre_read_size = n;

        std::array<std::uint8_t, max_probe_size> bytes{};
        for (std::size_t i = 0; i < n; ++i)
        {
            bytes[i] = std::to_integer<std::uint8_t>(result.pre_read[i]);
        }
        result.type = detect(std::span<const std::uint8_t>(bytes.data(), n));
        result.success = result.type != protocol_type::unknown;
        co_return result;
    }

    /**
     * @brief 预读数据回注（preview 包装）
     * @param transport 已消费预读的传输
     * @param preread 预读数据
     * @return 包装后的传输（回放预读）
     */
    [[nodiscard]] inline auto wrap_preread(shared_transmission transport,std::span<const std::byte> preread) 
        -> shared_transmission
    {
        if (preread.empty())
        {
            return transport;
        }
        return preview::transport::wrap_with_preview(std::move(transport), preread);
    }

} // namespace preview::recognition
