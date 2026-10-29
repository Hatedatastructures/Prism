/**
 * @file SessionWriteLoop.cpp
 * @brief Mux 会话 writer 的非模板帧缓冲写入实现。
 */
#include <Prism/Protocols/Mux/Session/WriteLoop.hpp>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <cstddef>
#include <system_error>

namespace Prism::Mux::Detail
{
    [[nodiscard]] auto WriteFrame(
        SharedTransmission Raw,
        std::span<const std::uint8_t> Buffer) -> Net::awaitable<FrameWriteResult>
    {
        if (!Raw)
        {
            const auto ErrorCode = make_error_code(Error::BrokenPipe);
            co_return FrameWriteResult{
                ErrorCode, Prism::Fault::Failure{Prism::Fault::Code::IoError}};
        }

        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            const auto Remaining = Buffer.size() - Offset;
            const auto Part = co_await Raw->WriteSome(
                Prism::AsBytes(Buffer.subspan(Offset)));
            const std::error_code ErrorCode = Prism::Fault::ToNative(Part.Failure);
            if (ErrorCode)
            {
                if (ErrorCode == make_error_code(Error::BrokenPipe))
                {
                    co_return FrameWriteResult{make_error_code(Error::BrokenPipe), Part.Failure};
                }
                co_return FrameWriteResult{make_error_code(Error::IoError), Part.Failure};
            }
            if (Part.Bytes == 0 || Part.Bytes > Remaining)
            {
                const auto WriteError = make_error_code(Error::BrokenPipe);
                co_return FrameWriteResult{
                    WriteError, Prism::Fault::Failure{Prism::Fault::Code::IoError}};
            }
            Offset += Part.Bytes;
        }
        co_return FrameWriteResult{};
    }

} // namespace Prism::Mux::Detail
