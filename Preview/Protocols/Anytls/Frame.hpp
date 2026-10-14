/** @file Frame.hpp @brief AnyTLS 独立 SETTINGS/SYN/PSH/FIN wire 与精确读取。 */
#pragma once
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <array>
#include <expected>
#include <system_error>
#include <vector>

namespace Preview::Anytls
{
    namespace Net = boost::asio;
    enum class Command : std::uint8_t
    {
        Waste = 0, Syn = 1, Push = 2, Fin = 3, Settings = 4, Alert = 5,
        UpdatePadding = 6, SynAck = 7, HeartRequest = 8, HeartResponse = 9, ServerSettings = 10
    };
    /** @brief 一条完整拥有的协议帧；producer/writer 不借用调用者 payload。 */
    struct Frame final
    {
        Command Kind{Command::Waste};
        std::uint32_t StreamId{0};
        std::vector<std::byte> Payload;
    };
    inline auto ReadExact(Preview::SharedTransmission Stream, std::span<std::byte> Bytes)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        std::size_t Offset = 0;
        while (Offset < Bytes.size())
        {
            if (!Stream)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            const auto Part = co_await Stream->ReadSome(Bytes.subspan(Offset));
            const auto Count = Part.Bytes;
            if (Count > Bytes.size() - Offset)
            {
                co_return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::InvalidArgument, Part.Failure.Native});
            }
            Offset += Count;
            if (Part.Failure.Failed())
            {
                if (Part.Failure.Code == Preview::Fault::Code::Eof && Offset != 0U)
                {
                    co_return std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::ProtocolError, Part.Failure.Native});
                }
                co_return std::unexpected(Part.Failure);
            }
            if (Count == 0U)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Offset == 0U
                        ? Preview::Fault::Code::Eof
                        : Preview::Fault::Code::ProtocolError});
            }
        }
        co_return std::expected<void, Preview::Fault::Failure>{};
    }
    inline auto ReadFrame(Preview::SharedTransmission Stream) -> Net::awaitable<std::expected<Frame, Error>>
    {
        std::array<std::byte, 7> Header{};
        const auto HeaderRead = co_await ReadExact(Stream, Header);
        if (!HeaderRead)
        {
            if (HeaderRead.error().Code == Preview::Fault::Code::Eof)
                co_return std::unexpected(Error::UnexpectedEof);
            throw std::system_error(Preview::Fault::ToNative(HeaderRead.error()));
        }
        Frame Result;
        Result.Kind = static_cast<Command>(std::to_integer<std::uint8_t>(Header[0]));
        if (Result.Kind > Command::ServerSettings) co_return std::unexpected(Error::BadMessage);
        for (std::size_t Index = 1; Index != 5; ++Index)
            Result.StreamId = (Result.StreamId << 8) | std::to_integer<std::uint8_t>(Header[Index]);
        const auto Size = (std::to_integer<std::size_t>(Header[5]) << 8) |
                           std::to_integer<std::size_t>(Header[6]);
        Result.Payload.resize(Size);
        const auto PayloadRead = co_await ReadExact(Stream, Result.Payload);
        if (!PayloadRead)
        {
            if (PayloadRead.error().Code == Preview::Fault::Code::Eof)
                co_return std::unexpected(Error::UnexpectedEof);
            throw std::system_error(Preview::Fault::ToNative(PayloadRead.error()));
        }
        co_return Result;
    }
    inline auto Encode(Frame Value) -> std::vector<std::byte>
    {
        if (Value.Payload.size() > 65535) return {};
        std::vector<std::byte> Wire{std::byte{static_cast<std::uint8_t>(Value.Kind)},
            std::byte{static_cast<std::uint8_t>(Value.StreamId >> 24)},
            std::byte{static_cast<std::uint8_t>(Value.StreamId >> 16)},
            std::byte{static_cast<std::uint8_t>(Value.StreamId >> 8)},
            std::byte{static_cast<std::uint8_t>(Value.StreamId)},
            std::byte{static_cast<std::uint8_t>(Value.Payload.size() >> 8)},
            std::byte{static_cast<std::uint8_t>(Value.Payload.size())}};
        Wire.insert(Wire.end(), Value.Payload.begin(), Value.Payload.end());
        return Wire;
    }
}
