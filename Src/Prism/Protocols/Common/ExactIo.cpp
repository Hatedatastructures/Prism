/** @file ExactIo.cpp @brief 协议握手使用的精确传输读写组合实现。 */
#include <Prism/Protocols/Common/ExactIo.hpp>

#include <Prism/Foundation/ByteSpan.hpp>

namespace Prism::Protocol::Common
{

    auto ReadExactIo(
        const Prism::SharedTransmission &Transport,
        const std::span<std::uint8_t> Buffer) -> Net::awaitable<Prism::IoResult>
    {
        Prism::IoResult Result;
        if (!Transport)
        {
            Result.Failure = {Prism::Fault::Code::IoError};
            co_return Result;
        }
        while (Result.Bytes < Buffer.size())
        {
            const auto Remaining = Buffer.size() - Result.Bytes;
            const auto Part = co_await Transport->ReadSome(Prism::AsBytes(Buffer.subspan(Result.Bytes)));
            if (Part.Bytes > Remaining)
            {
                Result.Failure = {Prism::Fault::Code::IoError, Part.Failure.Native};
                co_return Result;
            }
            Result.Bytes += Part.Bytes;
            Result.Failure = Part.Failure;
            if (Result.Failure.Failed())
            {
                co_return Result;
            }
            if (Part.Bytes == 0)
            {
                Result.Failure = {Prism::Fault::Code::WouldBlock};
                co_return Result;
            }
        }
        co_return Result;
    }

    auto WriteAllIo(
        const Prism::SharedTransmission &Transport,
        const std::span<const std::uint8_t> Buffer) -> Net::awaitable<Prism::IoResult>
    {
        Prism::IoResult Result;
        if (!Transport)
        {
            Result.Failure = {Prism::Fault::Code::IoError};
            co_return Result;
        }
        while (Result.Bytes < Buffer.size())
        {
            const auto Remaining = Buffer.size() - Result.Bytes;
            const auto Part = co_await Transport->WriteSome(Prism::AsBytes(Buffer.subspan(Result.Bytes)));
            if (Part.Bytes > Remaining)
            {
                Result.Failure = {Prism::Fault::Code::IoError, Part.Failure.Native};
                co_return Result;
            }
            Result.Bytes += Part.Bytes;
            Result.Failure = Part.Failure;
            if (Result.Failure.Failed())
            {
                co_return Result;
            }
            if (Part.Bytes == 0)
            {
                Result.Failure = {Prism::Fault::Code::WouldBlock};
                co_return Result;
            }
        }
        co_return Result;
    }

} // namespace Prism::Protocol::Common
