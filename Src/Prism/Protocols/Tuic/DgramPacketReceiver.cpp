/**
 * @file DgramPacketReceiver.cpp
 * @brief TUIC 数据报 packet 接收实现。
 */
#include <Prism/Protocols/Tuic/DgramPacketReceiver.hpp>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Protocols/Common/Address.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace Prism::Tuic::Detail
{
    DgramPacketReceiver::DgramPacketReceiver(SharedTransmission Upstream)
        : Upstream_(std::move(Upstream))
    {
    }

    auto DgramPacketReceiver::Receive() -> Net::awaitable<ReceiveResult>
    {
        if (!Upstream_)
        {
            co_return ReceiveResult{std::unexpected(Error::NotOpen), {}};
        }
        if (Upstream_->TransportType() == Prism::Transmission::Type::Udp)
            co_return co_await ReceiveDatagram();
        co_return co_await ReceiveStreamFrame();
    }

    auto DgramPacketReceiver::ReceiveDatagram() -> Net::awaitable<ReceiveResult>
    {
        std::array<std::uint8_t, 65536> Datagram{};
        const auto Part = co_await Upstream_->ReadSome(
            Prism::AsBytes(std::span<std::uint8_t>(Datagram)));
        auto Terminal = Part.Failure.Failed()
            ? std::optional<Prism::Fault::Failure>{Part.Failure}
            : std::optional<Prism::Fault::Failure>{};
        if (Part.Bytes > Datagram.size())
        {
            co_return ReceiveResult{
                std::unexpected(Error::BadLength),
                Terminal ? Terminal : std::optional<Prism::Fault::Failure>{
                    Prism::Fault::Failure{Prism::Fault::Code::IoError}}};
        }
        if (Part.Bytes == 0U)
        {
            const auto ReadError = Terminal
                ? ReadFailureToError(*Terminal)
                : Error::UnexpectedEof;
            co_return ReceiveResult{std::unexpected(ReadError), {}};
        }

        Message Parsed{};
        const auto Received = Part.Bytes;
        std::size_t Consumed = 0;
        const auto ParseError = Parse(
            std::span<const std::uint8_t>(Datagram.data(), Received), Parsed, Consumed);
        if (ParseError != Error::None || Parsed.Cmd != CmdPacket || Consumed != Received)
        {
            co_return ReceiveResult{
                std::unexpected(
                    ParseError == Error::None ? Error::BadMessage : ParseError),
                std::move(Terminal)};
        }
        co_return ReceiveResult{Packet{std::move(Parsed)}, std::move(Terminal)};
    }

    auto DgramPacketReceiver::ReceiveStreamFrame() -> Net::awaitable<ReceiveResult>
    {
        std::array<std::uint8_t, 10> Head{};
        auto ReadResult = co_await ReadExact(std::span<std::uint8_t>(Head));
        if (ReadResult.Bytes != Head.size() || ReadResult.Failure.Failed())
        {
            co_return ReceiveResult{
                std::unexpected(ReadFailureToError(ReadResult)), PendingTerminal_};
        }
        if (Head[0] != ProtocolVersion || Head[1] != CmdPacket)
        {
            co_return ReceiveResult{
                std::unexpected(Error::BadMessage), PendingTerminal_};
        }

        Message Parsed{};
        Parsed.Cmd = Head[1];
        Parsed.AssocId = static_cast<std::uint16_t>(Head[2]) << 8U | Head[3];
        Parsed.PktId = static_cast<std::uint16_t>(Head[4]) << 8U | Head[5];
        Parsed.FragTotal = Head[6];
        Parsed.FragId = Head[7];
        Parsed.Size = static_cast<std::uint16_t>(Head[8]) << 8U | Head[9];
        if (Parsed.FragTotal == 0U || Parsed.FragId >= Parsed.FragTotal)
        {
            co_return ReceiveResult{
                std::unexpected(Error::BadMessage), PendingTerminal_};
        }

        std::optional<Prism::Fault::Failure> Terminal;
        const auto AddressError = co_await ReadAddress(Parsed, Terminal);
        if (AddressError != Error::None)
        {
            if (!Terminal)
            {
                Terminal = PendingTerminal_;
            }
            co_return ReceiveResult{
                std::unexpected(AddressError), std::move(Terminal)};
        }
        std::vector<std::uint8_t> Chunk(Parsed.Size);
        if (!Chunk.empty())
        {
            ReadResult = co_await ReadExact(std::span<std::uint8_t>(Chunk));
            if (ReadResult.Bytes != Chunk.size())
            {
                co_return ReceiveResult{
                    std::unexpected(ReadFailureToError(ReadResult)), PendingTerminal_};
            }
            if (ReadResult.Failure.Failed())
            {
                Terminal = ReadResult.Failure;
            }
            Parsed.payload.assign(
                reinterpret_cast<const char *>(Chunk.data()), Chunk.size());
        }
        if (!Terminal)
        {
            Terminal = PendingTerminal_;
        }
        co_return ReceiveResult{Packet{std::move(Parsed)}, std::move(Terminal)};
    }

    auto DgramPacketReceiver::ReadAddress(
        Message &Parsed,
        std::optional<Prism::Fault::Failure> &Terminal) -> Net::awaitable<Error>
    {
        std::array<std::uint8_t, 1> Atyp{};
        auto ReadResult = co_await ReadExact(std::span<std::uint8_t>(Atyp));
        if (PendingTerminal_)
        {
            Terminal = PendingTerminal_;
        }
        if (ReadResult.Bytes != Atyp.size())
        {
            co_return ReadFailureToError(ReadResult);
        }
        if (ReadResult.Failure.Failed())
        {
            co_return ReadFailureToError(ReadResult);
        }
        Parsed.dst.Type = static_cast<AddressType>(Atyp[0]);
        if (Parsed.dst.Type == AddressType::None)
        {
            if (Parsed.FragId == 0U) co_return Error::BadMessage;
            if (PendingTerminal_ && Parsed.Size != 0U)
            {
                co_return ReadFailureToError(*PendingTerminal_);
            }
            co_return Error::None;
        }
        if (Parsed.FragId != 0U) co_return Error::BadMessage;
        if (Parsed.dst.Type != AddressType::Ipv4 &&
            Parsed.dst.Type != AddressType::Ipv6 &&
            Parsed.dst.Type != AddressType::Domain)
        {
            co_return Error::BadMessage;
        }
        if (PendingTerminal_)
        {
            co_return ReadFailureToError(*PendingTerminal_);
        }

        std::optional<Prism::Fault::Failure> AddressFailure;
        const auto AddressError = co_await ReadAddressBody(
            Parsed.dst, AddressFailure);
        if (AddressFailure)
        {
            Terminal = AddressFailure;
            co_return ReadFailureToError(*AddressFailure);
        }
        if (AddressError != Error::None) co_return AddressError;
        std::array<std::uint8_t, 2> Port{};
        ReadResult = co_await ReadExact(std::span<std::uint8_t>(Port));
        if (PendingTerminal_)
        {
            Terminal = PendingTerminal_;
        }
        if (ReadResult.Bytes != Port.size())
        {
            co_return ReadFailureToError(ReadResult);
        }
        if (ReadResult.Failure.Failed())
        {
            co_return ReadFailureToError(ReadResult);
        }
        if (PendingTerminal_ && Parsed.Size != 0U)
        {
            co_return ReadFailureToError(*PendingTerminal_);
        }
        Parsed.dst.Port = static_cast<std::uint16_t>(Port[0]) << 8U | Port[1];
        co_return Error::None;
    }

    auto DgramPacketReceiver::ReadExact(std::span<std::uint8_t> Dst)
        -> Net::awaitable<Prism::IoResult>
    {
        Prism::IoResult Result{};
        if (PendingTerminal_)
        {
            co_return Prism::IoResult{0U, *PendingTerminal_};
        }
        if (!Upstream_)
        {
            Result.Failure = {Prism::Fault::Code::IoError};
            co_return Result;
        }
        while (Result.Bytes < Dst.size())
        {
            const auto Remaining = Dst.size() - Result.Bytes;
            const auto Part = co_await Upstream_->ReadSome(
                Prism::AsBytes(Dst.subspan(Result.Bytes)));
            if (Part.Bytes > Remaining)
            {
                Result.Failure =
                    Prism::Fault::Failure{Prism::Fault::Code::IoError,
                        Part.Failure.Native};
                PendingTerminal_ = Result.Failure;
                co_return Result;
            }
            Result.Bytes += Part.Bytes;
            Result.Failure = Part.Failure;
            if (Result.Failure.Failed())
            {
                PendingTerminal_ = Result.Failure;
                if (Result.Bytes == Dst.size())
                {
                    Result.Failure = {};
                }
                co_return Result;
            }
            if (Part.Bytes == 0U)
            {
                Result.Failure = {Prism::Fault::Code::WouldBlock};
                co_return Result;
            }
        }
        co_return Result;
    }

    auto DgramPacketReceiver::ReadAddressBody(
        Address &AddressValue,
        std::optional<Prism::Fault::Failure> &ReadFailure) -> Net::awaitable<Error>
    {
        return Prism::Protocol::Common::ReadAddressBody(
            AddressValue,
            [this, &ReadFailure](std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
            {
                const auto Result = co_await ReadExact(Buffer);
                if (Result.Failure.Failed())
                {
                    ReadFailure = Result.Failure;
                }
                co_return Result.Failure.Failed() ||
                    Result.Bytes != Buffer.size();
            });
    }

    auto DgramPacketReceiver::ReadFailureToError(
        const Prism::IoResult &ReadResult) noexcept -> Error
    {
        if (!ReadResult.Failure.Failed())
        {
            return Error::UnexpectedEof;
        }
        switch (ReadResult.Failure.Code)
        {
        case Prism::Fault::Code::Eof: return Error::UnexpectedEof;
        case Prism::Fault::Code::Canceled: return Error::Canceled;
        case Prism::Fault::Code::Timeout: return Error::Timeout;
        default: return Error::IoError;
        }
    }

    auto DgramPacketReceiver::ReadFailureToError(
        const Prism::Fault::Failure &Failure) noexcept -> Error
    {
        switch (Failure.Code)
        {
        case Prism::Fault::Code::Eof: return Error::UnexpectedEof;
        case Prism::Fault::Code::Canceled: return Error::Canceled;
        case Prism::Fault::Code::Timeout: return Error::Timeout;
        default: return Error::IoError;
        }
    }
}
