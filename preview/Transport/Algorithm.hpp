/**
 * @file Algorithm.hpp
 * @brief 组合操作（Composed Operations，借鉴 Boost.Beast/Asio 精髓）
 * @details 提供基于 Stream concept 的高层组合算法：
 *          - AsyncReadExact()：读满指定字节（内部循环补读）
 *          - AsyncWriteExact()：写满指定字节（内部循环补写）
 *          组合算法不关心底层协议细节，直接使用 Stream 原语，
 *          与 Beast 的 http::AsyncRead / websocket::AsyncWrite 同构。
 * @note 全部协程实现，内部不分配堆内存。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Stream.hpp>

namespace Preview
{

    /**
     * @brief 读满 buf.size() 字节（内部循环补读）
     * @tparam S Stream concept 满足类型
     * @param StreamObject 目标流
     * @param Buffer 输出缓冲
     * @return 错误码；EOF（对端提前关闭）= unexpected_eof
     * @note 超时由流的 SetTimeout 控制（如有）
     */
    template <Stream S>
    auto AsyncReadExact(S &StreamObject, std::span<std::uint8_t> Buffer) -> Net::awaitable<ProtocolEc>
    {
        std::size_t Done = 0;
        while (Done < Buffer.size())
        {
            std::error_code Ec;
            const auto Remaining = Buffer.size() - Done;
            const auto N = co_await StreamObject.async_read_some(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data() + Done), Remaining), Ec);
            if (Ec)
            {
                co_return make_error_code(Error::IoError);
            }
            if (N == 0)
            {
                co_return make_error_code(Error::UnexpectedEof);
            }
            if (N > Remaining)
            {
                co_return make_error_code(Error::BrokenPipe);
            }
            Done += N;
        }
        co_return make_error_code(Error::None);
    }

    /**
     * @brief 写满 buf.size() 字节
     * @tparam S Stream concept 满足类型
     * @param StreamObject 目标流
     * @param Buffer 输入缓冲
     * @return 错误码（WriteAll 语义：全部写入或失败）
     */
    template <Stream S>
    auto AsyncWriteExact(S &StreamObject, std::span<const std::uint8_t> Buffer)
        -> Net::awaitable<ProtocolEc>
    {
        std::size_t Done = 0;
        while (Done < Buffer.size())
        {
            std::error_code Ec;
            const auto Remaining = Buffer.size() - Done;
            const auto N = co_await StreamObject.async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Buffer.data() + Done), Remaining),
                Ec);
            if (Ec)
            {
                co_return make_error_code(Error::IoError);
            }
            if (N == 0 || N > Remaining)
            {
                co_return make_error_code(Error::BrokenPipe);
            }
            Done += N;
        }
        co_return make_error_code(Error::None);
    }

    /**
     * @brief 带超时读满指定字节
     * @param StreamObject 目标流
     * @param Buffer 输出缓冲
     * @param Timeout 读超时（0 = 不设置）
     * @return 错误码；超时 = timeout
     */
    template <Stream S>
    auto AsyncReadExact(S &StreamObject, std::span<std::uint8_t> Buffer,
                        std::chrono::milliseconds Timeout) -> Net::awaitable<ProtocolEc>
    {
        if constexpr (requires(S &StreamValue, std::chrono::milliseconds Duration) {
                          StreamValue.SetTimeout(Duration);
                      })
        {
            if (Timeout.count() > 0)
            {
                StreamObject.SetTimeout(Timeout);
            }
        }
        co_return co_await AsyncReadExact(StreamObject, Buffer);
    }

} // namespace Preview
