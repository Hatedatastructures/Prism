/**
 * @file SessionWriteLoop.hpp
 * @brief 多路复用会话的底层写入细节
 * @details 将会话帧的 uint8_t 视图适配到 Preview Transmission 的
 *          byte 视图，保留会话层统一的协议错误映射。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Mux::Detail
{

    /**
     * @brief 写入一个帧缓冲
     * @param Raw 底层传输
     * @param Buffer 待写入帧
     * @return 协议错误码
     */
    [[nodiscard]] inline auto WriteFrame(
        SharedTransmission Raw,
        std::span<const std::uint8_t> Buffer) -> Net::awaitable<ProtocolEc>
    {
        if (!Raw)
        {
            co_return make_error_code(Error::BrokenPipe);
        }

        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            const auto Remaining = Buffer.size() - Offset;
            std::error_code ErrorCode;
            const auto Written = co_await Raw->async_write_some(
                Preview::AsBytes(Buffer.subspan(Offset)), ErrorCode);
            if (ErrorCode)
            {
                if (ErrorCode == make_error_code(Error::BrokenPipe))
                {
                    co_return ErrorCode;
                }
                co_return make_error_code(Error::IoError);
            }

            if (Written == 0 || Written > Remaining)
            {
                co_return make_error_code(Error::BrokenPipe);
            }
            Offset += Written;
        }
        co_return boost::system::error_code{};
    }

} // namespace Preview::Mux::Detail
