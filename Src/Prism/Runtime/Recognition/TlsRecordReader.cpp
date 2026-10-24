/** @file TlsRecordReader.cpp @brief TLS 记录边界增量读取实现。 */
#include <Prism/Runtime/Recognition/TlsRecordReader.hpp>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace Prism::Recognition
{
    namespace
    {
        [[nodiscard]] auto IsEof(const Prism::Fault::Failure& Terminal) noexcept -> bool
        {
            return Terminal.Code == Prism::Fault::Code::Eof ||
                (Terminal.Native && Prism::Fault::ToCode(Terminal.Native) == Prism::Fault::Code::Eof);
        }

        [[nodiscard]] auto IncompleteStatus(const Prism::Fault::Failure& Terminal) noexcept -> Error
        {
            return IsEof(Terminal) ? Error::UnexpectedEof : Error::IoError;
        }
    }

    auto ReadTlsRecord(Prism::Transmission &Transport, std::span<const std::byte> Preread)
        -> Net::awaitable<TlsRecordReadResult>
    {
        TlsRecordReadResult Result;
        if (Preread.size() > TlsRecordHeaderSize + MaxTlsRecordPayload)
        {
            Result.Status = Error::BadLength;
            co_return Result;
        }

        Result.Record.reserve(TlsRecordHeaderSize + MaxTlsRecordPayload);
        if (!Preread.empty())
        {
            const auto *Bytes = reinterpret_cast<const std::uint8_t *>(Preread.data());
            Result.Record.insert(Result.Record.end(), Bytes, Bytes + Preread.size());
        }

        while (Result.Record.size() < TlsRecordHeaderSize)
        {
            std::array<std::byte, TlsRecordHeaderSize> Chunk{};
            const auto Need = TlsRecordHeaderSize - Result.Record.size();
            const auto Part = co_await Transport.ReadSome(
                std::span<std::byte>(Chunk).first(Need));
            const auto Read = Part.Bytes;
            if (Read > Need)
            {
                Result.Status = IncompleteStatus(Part.Failure);
                Result.Terminal = Part.Failure;
                co_return Result;
            }
            if (Read != 0)
            {
                const auto *Bytes = reinterpret_cast<const std::uint8_t *>(Chunk.data());
                Result.Record.insert(Result.Record.end(), Bytes, Bytes + Read);
            }
            if (Part.Failure.Failed())
            {
                Result.Terminal = Part.Failure;
                break;
            }
            if (Read == 0)
            {
                Result.Status = Error::UnexpectedEof;
                co_return Result;
            }
        }

        if (Result.Record.size() < TlsRecordHeaderSize)
        {
            Result.Status = IncompleteStatus(Result.Terminal);
            co_return Result;
        }
        if (Result.Record[0] != 0x16 || Result.Record[1] != 0x03)
        {
            Result.Status = Error::BadMessage;
            co_return Result;
        }
        const auto PayloadLength = static_cast<std::size_t>(Result.Record[3]) << 8 | Result.Record[4];
        if (PayloadLength > MaxTlsRecordPayload)
        {
            Result.Status = Error::BadLength;
            co_return Result;
        }
        const auto Total = TlsRecordHeaderSize + PayloadLength;
        if (Result.Record.size() > Total)
        {
            Result.Status = Error::BadLength;
            co_return Result;
        }
        if (Result.Record.size() == Total)
        {
            co_return Result;
        }
        if (Result.Terminal.Failed())
        {
            Result.Status = IncompleteStatus(Result.Terminal);
            co_return Result;
        }

        while (Result.Record.size() < Total)
        {
            const auto OriginalSize = Result.Record.size();
            const auto Need = Total - OriginalSize;
            Result.Record.resize(Total);
            const auto Part = co_await Transport.ReadSome(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Result.Record.data() + OriginalSize), Need));
            const auto Read = Part.Bytes;
            if (Read > Need)
            {
                Result.Record.resize(OriginalSize);
                Result.Terminal = Part.Failure;
                Result.Status = IncompleteStatus(Part.Failure);
                co_return Result;
            }
            Result.Record.resize(OriginalSize + Read);
            if (Part.Failure.Failed())
            {
                Result.Terminal = Part.Failure;
                if (Result.Record.size() != Total)
                {
                    Result.Status = IncompleteStatus(Result.Terminal);
                }
                co_return Result;
            }
            if (Read == 0)
            {
                Result.Status = Error::UnexpectedEof;
                co_return Result;
            }
        }
        co_return Result;
    }
}
