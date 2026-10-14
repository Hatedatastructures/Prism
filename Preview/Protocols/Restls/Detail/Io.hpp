/**
 * @file WireIo.hpp
 * @brief Restls 记录面 typed wire I/O：精确读、整段写与记录帧读取。
 */
#pragma once

#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Protocols/Common/ExactIo.hpp>
#include <Preview/Protocols/Restls/Types.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Restls::Detail
{
    namespace Net = boost::asio;

    /** @brief 原生错误 → Restls 分类；Native 仍由 WireFailure 原样保存。 */
    [[nodiscard]] inline auto MapWireError(const std::error_code &ErrorCode) noexcept
        -> Preview::Error
    {
        if (!ErrorCode) return Preview::Error::None;
        const auto Code = Preview::Fault::ToCode(ErrorCode);
        if (Code == Preview::Fault::Code::Eof)
            return Preview::Error::UnexpectedEof;
        if (Code == Preview::Fault::Code::Canceled ||
            ErrorCode == std::make_error_code(std::errc::operation_canceled))
            return Preview::Error::Canceled;
        if (Code == Preview::Fault::Code::Timeout ||
            ErrorCode == std::make_error_code(std::errc::timed_out))
            return Preview::Error::Timeout;
        return Preview::Error::IoError;
    }

    /** @brief 将唯一 I/O Failure 映射到 Restls 分类，并保留原生 category/value。 */
    [[nodiscard]] inline auto WireFailure(
        const Preview::Fault::Failure &Value,
        const std::size_t Bytes = 0) noexcept
        -> Failure
    {
        const auto Native = Preview::Fault::ToNative(Value);
        return {MapWireError(Native), Native, Bytes};
    }

    /** @brief 将零进度或越界 wire 行为归类为 I/O 失败。 */
    [[nodiscard]] inline auto InvalidProgress(const std::size_t Bytes = 0) noexcept -> Failure
    {
        return {Preview::Error::IoError, std::make_error_code(std::errc::io_error), Bytes};
    }

    /**
     * @brief 精确读取指定字节数；底层失败完整保留原生 cause。
     * @param Transport 读取 owner 的共享引用；协程期间保持有效。
     * @param Buffer 借用至返回的写入缓冲区。
     * @return 成功无值；失败返回 Restls 分类与真实原生 cause。
     */
    [[nodiscard]] inline auto ReadExactWire(
        const SharedTransmission &Transport,
        std::span<std::uint8_t> Buffer) -> Net::awaitable<Result<void>>
    {
        const auto Read = co_await Preview::Protocol::Common::ReadExactIo(Transport, Buffer);
        if (Read.Failure.Failed())
        {
            if (Read.Failure.Code == Preview::Fault::Code::WouldBlock)
            {
                co_return std::unexpected(
                    Failure{Preview::Error::UnexpectedEof, {}, Read.Bytes});
            }
            co_return std::unexpected(WireFailure(Read.Failure, Read.Bytes));
        }
        co_return Result<void>{};
    }

    /**
     * @brief 循环短写直至全部字节发出；不使用 out-error 或 bool 双结果。
     * @param Transport 写入 owner 的共享引用；协程期间保持有效。
     * @param Buffer 借用至返回的读取缓冲区。
     * @return 成功无值；失败返回分类和原生 cause。
     */
    [[nodiscard]] inline auto SendAllWire(
        const SharedTransmission &Transport,
        std::span<const std::uint8_t> Buffer) -> Net::awaitable<Result<void>>
    {
        const auto Written = co_await Preview::Protocol::Common::WriteAllIo(Transport, Buffer);
        if (Written.Failure.Failed())
        {
            if (Written.Failure.Code == Preview::Fault::Code::WouldBlock)
            {
                co_return std::unexpected(InvalidProgress(Written.Bytes));
            }
            co_return std::unexpected(WireFailure(Written.Failure, Written.Bytes));
        }
        co_return Result<void>{};
    }

    /** @brief 读取一条记录帧；TLS close_notify、长度错误与传输 cause 均有唯一结果。 */
    [[nodiscard]] inline auto ReadRecordWire(const SharedTransmission &Transport)
        -> Net::awaitable<Result<std::vector<std::uint8_t>>>
    {
        std::array<std::uint8_t, TlsHdrlen> Header{};
        const auto HeaderResult = co_await ReadExactWire(Transport, Header);
        if (!HeaderResult) co_return std::unexpected(HeaderResult.error());
        if (Header[0] == 0x15)
            co_return std::unexpected(
                Failure{Preview::Error::UnexpectedEof, {}, Header.size()});

        const auto PayloadLength = (static_cast<std::size_t>(Header[3]) << 8U) | Header[4];
        const auto HasApplicationAuthenticationHeader =
            Header[0] == TlsApplicationData && PayloadLength < AuthHdrlen;
        if (HasApplicationAuthenticationHeader || PayloadLength > MaxRecordPayload)
            co_return std::unexpected(Failure{Preview::Error::BadLength, {}, Header.size()});

        std::vector<std::uint8_t> Wire(TlsHdrlen + PayloadLength);
        std::copy(Header.begin(), Header.end(), Wire.begin());
        const auto PayloadResult = co_await ReadExactWire(
            Transport, std::span<std::uint8_t>(Wire).subspan(TlsHdrlen));
        if (!PayloadResult)
        {
            auto Failure = PayloadResult.error();
            Failure.Bytes += Header.size();
            co_return std::unexpected(Failure);
        }
        co_return Wire;
    }
}
