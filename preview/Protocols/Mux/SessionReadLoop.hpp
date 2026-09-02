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

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Mux::Detail
{

    /**
     * @brief 读取完整缓冲区
     * @param Raw 底层传输
     * @param Buffer 目标缓冲区
     * @return true = 完整读入；false = EOF 或底层错误
     */
    [[nodiscard]] inline auto ReadExact(const SharedTransmission &Raw, std::span<std::uint8_t> Buffer)
        -> net::awaitable<bool>
    {
        std::size_t Done = 0;
        while (Done < Buffer.size())
        {
            std::error_code Ec;
            const auto N = co_await Raw->async_read_some(
                Preview::AsBytes(Buffer.subspan(Done)), Ec);
            if (Ec || N == 0)
            {
                co_return false;
            }
            Done += N;
        }
        co_return true;
    }

} // namespace Preview::Mux::Detail
