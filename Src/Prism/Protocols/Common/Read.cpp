/**
 * @file Read.cpp
 * @brief Common 精确读取协程实现。
 */

#include <Prism/Protocols/Common/Read.hpp>

namespace Prism::Protocol::Common
{

    auto ReadMin(
        Prism::Transmission &Transport,
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
            const auto Part = co_await Transport.ReadSome(Buffer.subspan(Total));
            if (Part.Bytes > Buffer.size() - Total)
            {
                co_return std::pair{Fault::Code::IoError, Total};
            }
            Total += Part.Bytes;
            // Asio 允许一次读取同时返回有效字节和 EOF/错误；先保留已消费的字节，
            // 否则调用方会丢掉帧尾并从错误位置继续解析。
            if (Part.Failure.Failed())
            {
                co_return std::pair{Part.Failure.Code, Total};
            }
            if (Part.Bytes == 0)
            {
                co_return std::pair{Fault::Code::Eof, Total};
            }
        }
        co_return std::pair{Fault::Code::Success, Total};
    }

    auto ReadRemaining(RemainingOpts Options)
        -> Net::awaitable<std::pair<Fault::Code, std::size_t>>
    {
        if (Options.current > Options.Buffer.size() || Options.Target > Options.Buffer.size())
        {
            co_return std::pair{Fault::Code::IoError, Options.current};
        }
        while (Options.current < Options.Target)
        {
            const auto Part = co_await Options.transport.ReadSome(Options.Buffer.subspan(Options.current));
            if (Options.current > Options.Buffer.size() || Part.Bytes > Options.Buffer.size() - Options.current)
            {
                co_return std::pair{Fault::Code::IoError, Options.current};
            }
            Options.current += Part.Bytes;
            if (Part.Failure.Failed())
            {
                co_return std::pair{Part.Failure.Code, Options.current};
            }
            if (Part.Bytes == 0)
            {
                co_return std::pair{Fault::Code::Eof, Options.current};
            }
        }
        co_return std::pair{Fault::Code::Success, Options.current};
    }

} // namespace Prism::Protocol::Common
