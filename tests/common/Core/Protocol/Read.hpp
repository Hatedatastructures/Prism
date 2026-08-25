/**
 * @file Read.hpp
 * @brief 共享 I/O 读取工具函数
 * @details 提供跨协议的通用读取辅助函数，包括 ReadMin 和
 * ReadRemaining。这些函数封装了从传输层批量读取数据的协程逻辑，
 * 被 Trojan 和 VLESS relay 共同使用，消除重复代码。
 * 所有函数返回 net::awaitable，遵循项目纯协程设计。
 */

#pragma once

#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Transmission.hpp>

#include <boost/asio.hpp>

#include <cstddef>
#include <span>
#include <system_error>
#include <utility>

namespace Preview::Protocol::Common
{

    namespace net = boost::asio;

    /**
     * @brief 批量读取至少指定数量的字节
     * @param transport 传输层引用
     * @param Buffer 输出缓冲区
     * @param min_size 最小读取字节数
     * @return 协程对象，完成后返回错误码和实际读取字节数
     * @details 循环调用 AsyncReadSome 直到读取至少 min_size 字节。
     * 遇到错误或 EOF 时提前返回，返回已读取的字节数和对应的错误码。
     */
    [[nodiscard]] inline auto ReadMin(Transport::Transmission &transport, std::span<std::byte> Buffer,
                                       const std::size_t min_size)
        -> net::awaitable<std::pair<Fault::Code, std::size_t>>
    {
        std::size_t Total = 0;
        while (Total < min_size)
        {
            std::error_code ec;
            const auto n = co_await transport.AsyncReadSome(Buffer.subspan(Total), ec);
            if (ec)
            {
                co_return std::pair{Fault::ToCode(ec), Total};
            }
            if (n == 0)
            {
                co_return std::pair{Fault::Code::eof, Total};
            }
            Total += n;
        }
        co_return std::pair{Fault::Code::success, Total};
    }

    /**
     * @struct RemainingOpts
     * @brief ReadRemaining 参数聚合
     * @details 将 ReadRemaining 的 4 个参数收敛到单结构体，
     * 符合 Rule 1（函数参数不超过 3 个）。
     */
    struct RemainingOpts
    {
        Transport::Transmission &transport; ///< 传输层引用
        std::span<std::byte> Buffer;        ///< 输出缓冲区
        std::size_t current;                ///< 当前已读字节数
        std::size_t Target;                 ///< 目标字节数
    };

    /**
     * @brief 精确补读剩余字节
     * @param opts 读取选项（transport + Buffer + current + Target）
     * @return 协程对象，完成后返回错误码和最终读取字节数
     * @details 从 current 位置继续读取，直到达到 Target 字节。
     * 遇到错误或 EOF 时提前返回，返回已读取的字节数和对应的错误码。
     */
    [[nodiscard]] inline auto ReadRemaining(RemainingOpts opts)
        -> net::awaitable<std::pair<Fault::Code, std::size_t>>
    {
        while (opts.current < opts.Target)
        {
            std::error_code ec;
            const auto n = co_await opts.transport.AsyncReadSome(opts.Buffer.subspan(opts.current), ec);
            if (ec)
            {
                co_return std::pair{Fault::ToCode(ec), opts.current};
            }
            if (n == 0)
            {
                co_return std::pair{Fault::Code::eof, opts.current};
            }
            opts.current += n;
        }
        co_return std::pair{Fault::Code::success, opts.current};
    }
} // namespace Preview::Protocol::Common
