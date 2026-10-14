/**
 * @file TlsRecordReader.hpp
 * @brief TLS record 边界读取 owner。
 * @details 只负责从 Preview::Transmission 补齐一条 TLS record 并映射 EOF、
 *          I/O 和长度错误；ClientHello 扩展语义由 Tls.hpp 解析器拥有。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Recognition
{

    namespace Net = boost::asio;

    inline constexpr std::size_t TlsRecordHeaderSize = 5;
    inline constexpr std::size_t MaxTlsRecordPayload = 16 * 1024;
    inline constexpr std::size_t MaxTlsClientHelloBytes = 64 * 1024;
    inline constexpr std::size_t MaxTlsSessionIdBytes = 32;

    [[nodiscard]] inline auto ReadTlsRecord(
        Preview::Transmission &Transport,
        std::span<const std::byte> Preread = {})
        -> Net::awaitable<std::pair<Error, std::vector<std::uint8_t>>>
    {
        if (Preread.size() > TlsRecordHeaderSize + MaxTlsRecordPayload)
        {
            co_return std::pair{Error::BadLength, std::vector<std::uint8_t>{}};
        }

        std::vector<std::uint8_t> Record;
        Record.reserve(TlsRecordHeaderSize + MaxTlsRecordPayload);
        if (!Preread.empty())
        {
            const auto *Bytes = reinterpret_cast<const std::uint8_t *>(Preread.data());
            Record.insert(Record.end(), Bytes, Bytes + Preread.size());
        }

        while (Record.size() < TlsRecordHeaderSize)
        {
            std::array<std::byte, TlsRecordHeaderSize> Chunk{};
            const auto Need = TlsRecordHeaderSize - Record.size();
            const auto Part = co_await Transport.ReadSome(
                std::span<std::byte>(Chunk).first(Need));
            const auto Read = Part.Bytes;
            if (Part.Failure.Failed())
            {
                Error Status = Error::IoError;
                if (Read == 0 && Part.Failure.Code == Preview::Fault::Code::Eof)
                {
                    Status = Error::UnexpectedEof;
                }
                co_return std::pair{Status, std::vector<std::uint8_t>{}};
            }
            if (Read == 0 || Read > Need)
            {
                co_return std::pair{Error::UnexpectedEof, std::vector<std::uint8_t>{}};
            }
            const auto *Bytes = reinterpret_cast<const std::uint8_t *>(Chunk.data());
            Record.insert(Record.end(), Bytes, Bytes + Read);
        }

        if (Record[0] != 0x16 || Record[1] != 0x03)
        {
            co_return std::pair{Error::BadMessage, std::vector<std::uint8_t>{}};
        }
        const auto PayloadLength = static_cast<std::size_t>(Record[3]) << 8 | Record[4];
        if (PayloadLength > MaxTlsRecordPayload)
        {
            co_return std::pair{Error::BadLength, std::vector<std::uint8_t>{}};
        }
        const auto Total = TlsRecordHeaderSize + PayloadLength;
        if (Record.size() > Total)
        {
            co_return std::pair{Error::BadLength, std::vector<std::uint8_t>{}};
        }
        const auto AlreadyRead = Record.size();
        Record.resize(Total);
        auto Offset = AlreadyRead;
        while (Offset < Total)
        {
            const auto Part = co_await Transport.ReadSome(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Record.data() + Offset),
                                     Total - Offset));
            const auto Read = Part.Bytes;
            if (Part.Failure.Failed())
            {
                Error Status = Error::IoError;
                if (Read == 0 && Part.Failure.Code == Preview::Fault::Code::Eof)
                {
                    Status = Error::UnexpectedEof;
                }
                co_return std::pair{Status, std::vector<std::uint8_t>{}};
            }
            if (Read == 0 || Read > Total - Offset)
            {
                co_return std::pair{Error::UnexpectedEof, std::vector<std::uint8_t>{}};
            }
            Offset += Read;
        }
        co_return std::pair{Error::None, std::move(Record)};
    }

} // namespace Preview::Recognition

