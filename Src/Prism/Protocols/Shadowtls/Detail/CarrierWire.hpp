/**
 * @file CarrierWire.hpp
 * @brief ShadowTLS ClientHello 构造与精确传输 I/O。
 * @details 仅包含无状态 wire 操作，不拥有连接或最终关闭权。
 */
#pragma once

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Protocols/Shadowtls/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

namespace Prism::Shadowtls::Detail::Io
{
    namespace Net = boost::asio;

    [[nodiscard]] inline auto ReadExact(
        const SharedTransmission &Transport,
        std::span<std::uint8_t> Buffer,
        std::optional<Failure> &PendingTerminal) -> Net::awaitable<Result<std::size_t>>
    {
        if (Buffer.empty())
        {
            co_return std::size_t{0};
        }
        if (PendingTerminal)
        {
            co_return std::unexpected(*PendingTerminal);
        }
        auto Read = co_await Prism::Protocol::Common::ReadExactIo(Transport, Buffer);
        if (Read.Failure.Failed())
        {
            Failure Terminal;
            if (Read.Failure.Code == Prism::Fault::Code::WouldBlock)
            {
                Terminal = {Prism::Fault::Code::Eof, {}, Read.Bytes};
            }
            else
            {
                Terminal = FailureFromFault(Read.Failure, Read.Bytes);
            }
            PendingTerminal = Terminal;
            if (Read.Bytes == Buffer.size())
            {
                co_return Read.Bytes;
            }
            co_return std::unexpected(std::move(Terminal));
        }
        co_return Read.Bytes;
    }

    /** @brief 读取完整 TLS record，并在同读终态前交付已完成记录。 */
    [[nodiscard]] inline auto ReadRecord(
        const SharedTransmission &Transport,
        std::optional<Failure> &PendingTerminal) -> Net::awaitable<Result<std::vector<std::uint8_t>>>
    {
        std::array<std::uint8_t, TlsHdrsize> Header{};
        auto HeaderRead = co_await ReadExact(Transport, Header, PendingTerminal);
        if (!HeaderRead) co_return std::unexpected(HeaderRead.error());
        const auto Length = (static_cast<std::size_t>(Header[3]) << 8) | Header[4];
        if (Length != 0U && PendingTerminal)
        {
            co_return std::unexpected(*PendingTerminal);
        }
        if (Length > MaxTlsPlaintext)
        {
            co_return std::unexpected(FailureFromError(Error::BadLength, TlsHdrsize));
        }

        std::vector<std::uint8_t> Record(TlsHdrsize + Length);
        std::copy(Header.begin(), Header.end(), Record.begin());
        auto PayloadRead = co_await ReadExact(
            Transport, std::span<std::uint8_t>(Record).subspan(TlsHdrsize), PendingTerminal);
        if (!PayloadRead)
        {
            auto Cause = PayloadRead.error();
            Cause.Bytes += TlsHdrsize;
            PendingTerminal = Cause;
            co_return std::unexpected(std::move(Cause));
        }
        if (PendingTerminal) PendingTerminal->Bytes += TlsHdrsize;
        co_return Record;
    }

    [[nodiscard]] inline auto SendBytes(
        const SharedTransmission &Transport,
        std::span<const std::uint8_t> Data) -> Net::awaitable<Result<std::size_t>>
    {
        auto Written = co_await Prism::Protocol::Common::WriteAllIo(Transport, Data);
        if (Written.Failure.Failed())
        {
            if (Written.Failure.Code == Prism::Fault::Code::WouldBlock)
            {
                co_return std::unexpected(Failure{
                    Prism::Fault::Code::IoError, {}, Written.Bytes});
            }
            co_return std::unexpected(FailureFromFault(Written.Failure, Written.Bytes));
        }
        co_return Written.Bytes;
    }
}

namespace Prism::Shadowtls::Detail::Wire
{
    [[nodiscard]] inline auto BuildClientHello(
        std::span<const std::uint8_t> ClientRandom) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Hello(TlsHdrsize + SessionIdStart + TlsSessionIdSz + 16, 0);
        Hello[0] = 0x16;
        Hello[TlsHdrsize] = HsTypeClienthello;
        Hello[TlsHdrsize + SessionIdStart - 1] = TlsSessionIdSz;
        if (ClientRandom.size() >= TlsRndSize)
        {
            std::memcpy(
                Hello.data() + TlsHdrsize + 1 + 3 + 2, ClientRandom.data(), TlsRndSize);
        }
        return Hello;
    }
}
