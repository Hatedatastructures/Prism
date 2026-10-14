/**
 * @file Io.hpp
 * @brief ShadowTLS 传输精确读写组合操作。
 * @details 只组合 Transmission typed I/O，不拥有连接状态或最终关闭权。
 */
#pragma once

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Protocols/Common/ExactIo.hpp>
#include <Preview/Protocols/Shadowtls/Types.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace Preview::Shadowtls::Detail::Io
{
    namespace Net = boost::asio;

    /** @brief 精确读取；失败携带底层类别、Native 与累计 wire 字节数。 */
    [[nodiscard]] inline auto ReadExact(
        const SharedTransmission &Transport,
        std::span<std::uint8_t> Buffer) -> Net::awaitable<Result<std::size_t>>
    {
        auto Read = co_await Preview::Protocol::Common::ReadExactIo(
            Transport, Buffer);
        if (Read.Failure.Failed())
        {
            if (Read.Failure.Code == Preview::Fault::Code::WouldBlock)
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::Eof, {}, Read.Bytes});
            }
            co_return std::unexpected(FailureFromFault(Read.Failure, Read.Bytes));
        }
        co_return Read.Bytes;
    }

    /** @brief 写完全部 wire 数据；失败携带已经由底层接受的字节数。 */
    [[nodiscard]] inline auto SendBytes(
        const SharedTransmission &Transport,
        std::span<const std::uint8_t> Data) -> Net::awaitable<Result<std::size_t>>
    {
        auto Written = co_await Preview::Protocol::Common::WriteAllIo(
            Transport, Data);
        if (Written.Failure.Failed())
        {
            if (Written.Failure.Code == Preview::Fault::Code::WouldBlock)
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::IoError, {}, Written.Bytes});
            }
            co_return std::unexpected(FailureFromFault(Written.Failure, Written.Bytes));
        }
        co_return Written.Bytes;
    }
}
