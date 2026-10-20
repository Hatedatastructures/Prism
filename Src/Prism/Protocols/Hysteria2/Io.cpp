/**
 * @file Io.cpp
 * @brief Hysteria2 连接的精确读写实现。
 */
#include <Prism/Protocols/Hysteria2/Io.hpp>

#include <Prism/Foundation/ByteSpan.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <system_error>

namespace Prism::Hysteria2::Detail
{
    auto ReadFailureToError(const Prism::Fault::Failure &Failure) noexcept -> Prism::Error
    {
        switch (Failure.Code)
        {
        case Prism::Fault::Code::Eof: return Prism::Error::UnexpectedEof;
        case Prism::Fault::Code::Canceled: return Prism::Error::Canceled;
        case Prism::Fault::Code::Timeout: return Prism::Error::Timeout;
        default: return Prism::Error::IoError;
        }
    }

    auto ReadFailureToError(
        const std::optional<Prism::Fault::Failure> &Failure,
        const Prism::Error Fallback) noexcept -> Prism::Error
    {
        return Failure ? ReadFailureToError(*Failure) : Fallback;
    }

    auto ReadExact(
        const Prism::SharedTransmission &Transport,
        std::span<std::uint8_t> Destination,
        std::optional<Prism::Fault::Failure> &PendingTerminal)
        -> Net::awaitable<bool>
    {
        if (!Transport)
        {
            co_return true;
        }
        std::size_t Done = 0;
        while (Done < Destination.size())
        {
            if (PendingTerminal)
            {
                co_return true;
            }
            const auto Part = co_await Transport->ReadSome(
                AsBytes(Destination.subspan(Done)));
            const auto Count = Part.Bytes;
            if (Count > Destination.size() - Done)
            {
                co_return true;
            }
            Done += Count;
            if (Part.Failure.Failed())
            {
                PendingTerminal = Part.Failure;
                co_return Done != Destination.size();
            }
            if (Count == 0U)
            {
                co_return true;
            }
        }
        co_return false;
    }

    auto SendBytes(
        const Prism::SharedTransmission &Transport,
        std::span<const std::uint8_t> Data) -> Net::awaitable<bool>
    {
        if (!Transport)
        {
            co_return true;
        }
        std::size_t Done = 0;
        while (Done < Data.size())
        {
            const auto Part = co_await Transport->WriteSome(
                AsBytes(Data.subspan(Done)));
            const auto ErrorCode = Prism::Fault::ToNative(Part.Failure);
            const auto Count = Part.Bytes;
            if (ErrorCode || Count == 0U || Count > Data.size() - Done)
            {
                co_return true;
            }
            Done += Count;
        }
        co_return false;
    }

    auto ReadAddressBody(
        const Prism::SharedTransmission &Transport,
        Prism::Hysteria2::Address &AddressValue,
        std::optional<Prism::Fault::Failure> &PendingTerminal)
        -> Net::awaitable<Prism::Error>
    {
        const auto AddressError = co_await Prism::Protocol::Common::ReadAddressBody(
            AddressValue,
            [Transport, &PendingTerminal](std::span<std::uint8_t> Buffer)
                -> Net::awaitable<bool>
            {
                return ReadExact(Transport, Buffer, PendingTerminal);
            });
        if (AddressError == Prism::Error::IoError && PendingTerminal)
        {
            co_return ReadFailureToError(*PendingTerminal);
        }
        co_return AddressError;
    }

    auto ReadFrame(
        const Prism::SharedTransmission &Transport,
        Prism::Hysteria2::Message &MessageValue,
        std::optional<Prism::Fault::Failure> &PendingTerminal)
        -> Net::awaitable<Prism::Error>
    {
        std::array<std::uint8_t, 1> Kind{};
        if (co_await ReadExact(Transport, std::span<std::uint8_t>(Kind), PendingTerminal))
        {
            co_return ReadFailureToError(PendingTerminal, Prism::Error::UnexpectedEof);
        }
        MessageValue.Type = static_cast<Prism::Hysteria2::Message::Kind>(Kind[0]);
        if (MessageValue.Type != Prism::Hysteria2::Message::Kind::Tcp &&
            MessageValue.Type != Prism::Hysteria2::Message::Kind::Udp)
        {
            co_return Prism::Error::BadMessage;
        }
        if (MessageValue.Type == Prism::Hysteria2::Message::Kind::Udp)
        {
            std::array<std::uint8_t, 8> Ids{};
            if (co_await ReadExact(Transport, std::span<std::uint8_t>(Ids), PendingTerminal))
            {
                co_return ReadFailureToError(PendingTerminal, Prism::Error::UnexpectedEof);
            }

            MessageValue.SessionId =
                static_cast<std::uint32_t>(Ids[0]) | static_cast<std::uint32_t>(Ids[1]) << 8 |
                static_cast<std::uint32_t>(Ids[2]) << 16 | static_cast<std::uint32_t>(Ids[3]) << 24;
            MessageValue.PacketId =
                static_cast<std::uint32_t>(Ids[4]) | static_cast<std::uint32_t>(Ids[5]) << 8 |
                static_cast<std::uint32_t>(Ids[6]) << 16 | static_cast<std::uint32_t>(Ids[7]) << 24;
        }
        std::array<std::uint8_t, 1> Atyp{};
        if (co_await ReadExact(Transport, std::span<std::uint8_t>(Atyp), PendingTerminal))
        {
            co_return ReadFailureToError(PendingTerminal, Prism::Error::UnexpectedEof);
        }
        MessageValue.dst.Type = static_cast<Prism::Hysteria2::AddressType>(Atyp[0]);
        const auto AddressError = co_await ReadAddressBody(
            Transport, MessageValue.dst, PendingTerminal);
        if (AddressError != Prism::Error::None)
        {
            co_return AddressError;
        }
        std::array<std::uint8_t, 2> Port{};
        if (co_await ReadExact(Transport, std::span<std::uint8_t>(Port), PendingTerminal))
        {
            co_return ReadFailureToError(PendingTerminal, Prism::Error::UnexpectedEof);
        }
        MessageValue.dst.Port = static_cast<std::uint16_t>(Port[0]) << 8 | Port[1];
        if (MessageValue.Type != Prism::Hysteria2::Message::Kind::Udp)
        {
            co_return Prism::Error::None;
        }
        if (PendingTerminal)
        {
            co_return ReadFailureToError(*PendingTerminal);
        }
        std::array<std::uint8_t, 512> Chunk{};
        const auto Part = co_await Transport->ReadSome(AsBytes(std::span<std::uint8_t>(Chunk)));
        const auto ErrorCode = Prism::Fault::ToNative(Part.Failure);
        const auto Count = Part.Bytes;
        if (Count > Chunk.size())
        {
            co_return ErrorCode ? Prism::Error::IoError : Prism::Error::BadLength;
        }
        MessageValue.payload.assign(
            Chunk.begin(),
            Chunk.begin() + static_cast<std::ptrdiff_t>(Count));
        if (Part.Failure.Failed())
        {
            PendingTerminal = Part.Failure;
            co_return Count == 0U ? ReadFailureToError(Part.Failure) : Prism::Error::None;
        }
        co_return Prism::Error::None;
    }
}
