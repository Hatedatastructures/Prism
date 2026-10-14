/**
 * @file ExactIo.hpp
 * @brief 协议握手使用的精确传输读写组合。
 * @details 对每个真实 ReadSome/WriteSome 结果累计字节，并原样保留首次底层失败。
 */
#pragma once

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>
#include <system_error>

namespace Preview::Protocol::Common
{
    namespace Net = boost::asio;

    /** @brief 在协议正式边界把私有 Error 一次转换为保留分类的 Failure。 */
    [[nodiscard]] inline auto FailureFromProtocolError(const Preview::Error Value) noexcept
        -> Preview::Fault::Failure
    {
        return {Preview::Fault::ToCode(Preview::make_error_code(Value))};
    }

    /** @brief 把真实精确 I/O 失败提升到协议结果，原样保留 category/value。 */
    [[nodiscard]] inline auto FailureFromIo(const Preview::IoResult &Result) noexcept
        -> Preview::Fault::Failure
    {
        return Result.Failure;
    }

    /** @brief 读取完整缓冲；失败携带累计字节与首次 Native cause。 */
    [[nodiscard]] inline auto ReadExactIo(
        const Preview::SharedTransmission &Transport,
        const std::span<std::uint8_t> Buffer) -> Net::awaitable<Preview::IoResult>
    {
        Preview::IoResult Result;
        if (!Transport)
        {
            Result.Failure = {Preview::Fault::Code::IoError};
            co_return Result;
        }
        while (Result.Bytes < Buffer.size())
        {
            const auto Remaining = Buffer.size() - Result.Bytes;
            const auto Part = co_await Transport->ReadSome(Preview::AsBytes(Buffer.subspan(Result.Bytes)));
            if (Part.Bytes > Remaining)
            {
                Result.Bytes = Part.Bytes > std::numeric_limits<std::size_t>::max() - Result.Bytes
                    ? Result.Bytes
                    : Result.Bytes + Part.Bytes;
                Result.Failure = {Preview::Fault::Code::IoError, Part.Failure.Native};
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
                Result.Failure = {Preview::Fault::Code::WouldBlock};
                co_return Result;
            }
        }
        co_return Result;
    }

    /** @brief 写完整缓冲；失败携带已交给传输层的字节与首次 Native cause。 */
    [[nodiscard]] inline auto WriteAllIo(
        const Preview::SharedTransmission &Transport,
        const std::span<const std::uint8_t> Buffer) -> Net::awaitable<Preview::IoResult>
    {
        Preview::IoResult Result;
        if (!Transport)
        {
            Result.Failure = {Preview::Fault::Code::IoError};
            co_return Result;
        }
        while (Result.Bytes < Buffer.size())
        {
            const auto Remaining = Buffer.size() - Result.Bytes;
            const auto Part = co_await Transport->WriteSome(Preview::AsBytes(Buffer.subspan(Result.Bytes)));
            if (Part.Bytes > Remaining)
            {
                Result.Bytes = Part.Bytes > std::numeric_limits<std::size_t>::max() - Result.Bytes
                    ? Result.Bytes
                    : Result.Bytes + Part.Bytes;
                Result.Failure = {Preview::Fault::Code::IoError, Part.Failure.Native};
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
                Result.Failure = {Preview::Fault::Code::WouldBlock};
                co_return Result;
            }
        }
        co_return Result;
    }
} // namespace Preview::Protocol::Common
