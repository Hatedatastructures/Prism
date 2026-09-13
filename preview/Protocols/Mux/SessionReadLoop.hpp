/**
 * @file SessionReadLoop.hpp
 * @brief 多路复用会话的精确读取细节
 * @details 只负责将底层 Transmission 的部分读拼接为一个完整帧片段，
 *          不解析帧字段，也不持有会话状态。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Mux::Detail
{

    /**
     * @brief 读取完整缓冲区
     * @param Raw 底层传输
     * @param Buffer 目标缓冲区
     * @return 完整读入返回 true；EOF、底层错误或 over-report 返回 false
     */
    [[nodiscard]] inline auto ReadExact(
        SharedTransmission Raw,
        std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
    {
        if (!Raw)
        {
            co_return false;
        }

        std::size_t Done = 0;
        while (Done < Buffer.size())
        {
            std::error_code ErrorCode;
            const auto N = co_await Raw->async_read_some(
                Preview::AsBytes(Buffer.subspan(Done)), ErrorCode);
            if (ErrorCode || N == 0 || N > Buffer.size() - Done)
            {
                co_return false;
            }
            Done += N;
        }
        co_return true;
    }

} // namespace Preview::Mux::Detail
