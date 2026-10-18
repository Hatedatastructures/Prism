/**
 * @file CarrierRecord.hpp
 * @brief Reality carrier 的 TLS record 读写。
 * @details 负责在 Transmission 上完整读取/写入 TLS record，统一处理
 *          短读、短写、干净 EOF 和底层 I/O 错误。
 */
#pragma once

#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Reality::Detail
{

    using Bytes = std::vector<std::uint8_t>;
    namespace Net = boost::asio;

    /**
     * @brief 读取指定长度的数据。
     * @param Transport 底层传输，所有权由调用方保留
     * @param Buffer 目标缓冲区
     * @return 保留部分字节和原生 cause 的传输结果。
     */
    [[nodiscard]] inline auto ReadExact(Prism::SharedTransmission &Transport,
                                        std::span<std::byte> Buffer)
        -> Net::awaitable<Prism::IoResult>
    {
        co_return co_await Prism::Protocol::Common::ReadExactIo(
            Transport,
            std::span<std::uint8_t>(reinterpret_cast<std::uint8_t *>(Buffer.data()), Buffer.size()));
    }

    /**
     * @brief 写入完整的数据缓冲区。
     * @param Transport 底层传输，所有权由调用方保留
     * @param Buffer 待写入的字节
     * @return 保留部分字节和原生 cause 的传输结果。
     */
    [[nodiscard]] inline auto WriteAll(Prism::SharedTransmission &Transport,
                                       std::span<const std::byte> Buffer)
        -> Net::awaitable<Prism::IoResult>
    {
        co_return co_await Prism::Protocol::Common::WriteAllIo(
            Transport,
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Buffer.data()), Buffer.size()));
    }

    /**
     * @brief 读取一个完整的 TLS record。
     * @param Transport 底层传输，所有权由调用方保留
     * @param CleanEof 可选的 record 边界 EOF 输出
     * @return 包含五字节头的完整 record；失败保留真实 Native cause。
     */
    [[nodiscard]] inline auto ReadRecord(Prism::SharedTransmission &Transport,
                                         bool *CleanEof = nullptr)
        -> Net::awaitable<std::expected<Bytes, Prism::Fault::Failure>>
    {
        if (CleanEof != nullptr)
        {
            *CleanEof = false;
        }
        std::array<std::byte, 5> Header{};
        const auto HeaderRead = co_await ReadExact(Transport, Header);
        if (HeaderRead.Failure.Failed())
        {
            if (CleanEof != nullptr && HeaderRead.Bytes == 0 &&
                (HeaderRead.Failure.Code == Prism::Fault::Code::Eof ||
                 HeaderRead.Failure.Code == Prism::Fault::Code::WouldBlock))
            {
                *CleanEof = true;
            }
            co_return std::unexpected(HeaderRead.Failure);
        }
        const auto *BytesHeader = reinterpret_cast<const std::uint8_t *>(Header.data());
        const auto Length = static_cast<std::size_t>(BytesHeader[3]) << 8 | BytesHeader[4];
        Bytes Record(5 + Length);
        std::copy(BytesHeader, BytesHeader + 5, Record.begin());
        const auto PayloadRead = co_await ReadExact(
            Transport,
            std::span<std::byte>(reinterpret_cast<std::byte *>(Record.data() + 5), Length));
        if (PayloadRead.Failure.Failed())
        {
            co_return std::unexpected(PayloadRead.Failure);
        }
        co_return Record;
    }

} // namespace Prism::Reality::Detail
