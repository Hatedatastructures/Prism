/**
 * @file TlsRecordReader.hpp
 * @brief TLS record 边界读取 owner。
 * @details 从 Prism::Transmission 补齐一条 TLS record，分别返回记录完整性状态、已观察字节
 *          与原始 typed terminal；ClientHello 扩展语义由 Tls.hpp 解析器拥有。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Recognition
{

    namespace Net = boost::asio;

    inline constexpr std::size_t TlsRecordHeaderSize = 5;
    inline constexpr std::size_t MaxTlsRecordPayload = 16 * 1024;
    inline constexpr std::size_t MaxTlsClientHelloBytes = 64 * 1024;
    inline constexpr std::size_t MaxTlsSessionIdBytes = 32;

    /**
     * @brief 一次 TLS record 读取的完整性、已观察字节与传输终态。
     * @details Record 保存从预读与本次 I/O 观察到的全部 record 字节，未完成时可能是截断前缀；
     *          Status 描述 record 的协议/完整性状态。完整 record 即使同次读取收到 terminal，
     *          Status 仍为 None，terminal 单独保存在 Terminal；未完成时 EOF 映射为 UnexpectedEof，
     *          其他传输失败映射为 IoError。原 Fault::Failure 的 Code 与 Native 均原样保留。
     */
    struct TlsRecordReadResult final
    {
        Error Status{Error::None};
        std::vector<std::uint8_t> Record;
        Prism::Fault::Failure Terminal{};
    };

    [[nodiscard]] auto ReadTlsRecord(
        Prism::Transmission &Transport,
        std::span<const std::byte> Preread = {})
        -> Net::awaitable<TlsRecordReadResult>;

} // namespace Prism::Recognition
