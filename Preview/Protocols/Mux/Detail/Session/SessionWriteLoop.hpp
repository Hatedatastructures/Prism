/**
 * @file SessionWriteLoop.hpp
 * @brief 多路复用会话的底层写入细节
 * @details 将会话帧的 uint8_t 视图适配到 Preview Transmission 的
 *          byte 视图，保留会话层统一的协议错误映射。每次部分写沿唯一
 *          typed 前门 Raw->WriteSome 启动，已完成字节先消费再判定终态。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Mux::Detail
{

    /**
     * @brief 写入一个帧缓冲
     * @param Raw 底层传输（借用；调用方保活到协程返回）
     * @param Buffer 待写入帧（借用至协程返回）
     * @return 协议错误码；成功为空
     * @details 单次部分写消费 IoResult 的 Bytes 与 Failure；零字节或 over-report
     *          按 BrokenPipe 报告，不复制缓冲区。
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
            const auto Part = co_await Raw->WriteSome(Preview::AsBytes(Buffer.subspan(Offset)));
            const std::error_code ErrorCode = Preview::Fault::ToNative(Part.Failure);
            if (ErrorCode)
            {
                if (ErrorCode == make_error_code(Error::BrokenPipe))
                {
                    co_return ErrorCode;
                }
                co_return make_error_code(Error::IoError);
            }

            if (Part.Bytes == 0 || Part.Bytes > Remaining)
            {
                co_return make_error_code(Error::BrokenPipe);
            }
            Offset += Part.Bytes;
        }
        co_return boost::system::error_code{};
    }

} // namespace Preview::Mux::Detail
