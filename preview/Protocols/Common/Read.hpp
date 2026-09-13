/**
 * @file Read.hpp
 * @brief 共享 I/O 读取工具函数
 * @details 提供跨协议的通用读取辅助函数，包括 ReadMin 和
 * ReadRemaining。这些函数封装了从传输层批量读取数据的协程逻辑，
 * 被 Trojan 和 VLESS relay 共同使用，消除重复代码。
     * 所有函数返回 Net::awaitable，遵循项目纯协程设计。
 */

#pragma once

#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Transport/Transmission.hpp>

#include <boost/asio.hpp>

#include <cstddef>
#include <span>
#include <system_error>
#include <utility>

namespace Preview::Protocol::Common
{

    namespace Net = boost::asio;

    /**
     * @brief 批量读取至少指定数量的字节
     * @param Transport 传输层引用
     * @param Buffer 输出缓冲区
     * @param MinSize 最小读取字节数
     * @return 协程对象，完成后返回错误码和实际读取字节数
     * @details 循环调用 async_read_some 直到读取至少 MinSize 字节。
     * 遇到错误或 EOF 时提前返回，返回已读取的字节数和对应的错误码。
     */
    [[nodiscard]] inline auto ReadMin(
        Preview::Transmission &Transport,
        std::span<std::byte> Buffer,
        const std::size_t MinSize) -> Net::awaitable<std::pair<Fault::Code, std::size_t>>
    {
        if (MinSize > Buffer.size())
        {
            co_return std::pair{Fault::Code::IoError, std::size_t{0}};
        }
        std::size_t Total = 0;
        while (Total < MinSize)
        {
            std::error_code ErrorCode;
            const auto Count = co_await Transport.async_read_some(Buffer.subspan(Total), ErrorCode);
            if (Count > Buffer.size() - Total)
            {
                co_return std::pair{Fault::Code::IoError, Total};
            }
            Total += Count;
            // Asio 允许一次读取同时返回有效字节和 EOF/错误；先保留已消费的字节，
            // 否则调用方会丢掉帧尾并从错误位置继续解析。
            if (ErrorCode)
            {
                co_return std::pair{Fault::ToCode(ErrorCode), Total};
            }
            if (Count == 0)
            {
                co_return std::pair{Fault::Code::Eof, Total};
            }
        }
        co_return std::pair{Fault::Code::Success, Total};
    }

    /**
     * @struct RemainingOpts
     * @brief ReadRemaining 参数聚合
     * @details 将 ReadRemaining 的 4 个参数收敛到单结构体，
     * 符合 Rule 1（函数参数不超过 3 个）。
     */
    struct RemainingOpts
    {
        Preview::Transmission &transport; ///< 传输层引用
        std::span<std::byte> Buffer;        ///< 输出缓冲区
        std::size_t current;                ///< 当前已读字节数
        std::size_t Target;                 ///< 目标字节数
    };

    /**
     * @brief 精确补读剩余字节
     * @param Options 读取选项（transport + Buffer + current + Target）
     * @return 协程对象，完成后返回错误码和最终读取字节数
     * @details 从 current 位置继续读取，直到达到 Target 字节。
     * 遇到错误或 EOF 时提前返回，返回已读取的字节数和对应的错误码。
     */
    [[nodiscard]] inline auto ReadRemaining(RemainingOpts Options)
        -> Net::awaitable<std::pair<Fault::Code, std::size_t>>
    {
        if (Options.current > Options.Buffer.size() || Options.Target > Options.Buffer.size())
        {
            co_return std::pair{Fault::Code::IoError, Options.current};
        }
        while (Options.current < Options.Target)
        {
            std::error_code ErrorCode;
            const auto Count = co_await Options.transport.async_read_some(
                Options.Buffer.subspan(Options.current),
                ErrorCode);
            if (Options.current > Options.Buffer.size() || Count > Options.Buffer.size() - Options.current)
            {
                co_return std::pair{Fault::Code::IoError, Options.current};
            }
            Options.current += Count;
            if (ErrorCode)
            {
                co_return std::pair{Fault::ToCode(ErrorCode), Options.current};
            }
            if (Count == 0)
            {
                co_return std::pair{Fault::Code::Eof, Options.current};
            }
        }
        co_return std::pair{Fault::Code::Success, Options.current};
    }
} // namespace Preview::Protocol::Common
