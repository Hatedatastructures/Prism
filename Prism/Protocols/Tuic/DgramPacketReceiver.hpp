/**
 * @file DgramPacketReceiver.hpp
 * @brief 读取并解析 TUIC UDP 关联的单个 packet 帧。
 * @details 同一接收 owner 支持底层 datagram 边界与 stream 帧边界；分片重组仍由 Dgram 持有。
 */
#pragma once

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Tuic/Codec.hpp>
#include <Prism/Protocols/Tuic/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Prism::Tuic::Detail
{
    namespace Net = boost::asio;

    /**
     * @class DgramPacketReceiver
     * @brief 将一个底层 datagram 或 stream frame 解析为 TUIC packet。
     * @details 只持有接收所需的底层传输引用；分片状态、输出和最终关闭由 Dgram owner 管理。
     */
    class DgramPacketReceiver final
    {
    public:
        using Packet = std::expected<Message, Error>;

        explicit DgramPacketReceiver(SharedTransmission Upstream)
            : Upstream_(std::move(Upstream))
        {
        }

        /** @brief 按底层传输边界读取并解析一个 packet。 */
        [[nodiscard]] auto Receive() -> Net::awaitable<Packet>
        {
            if (!Upstream_) co_return std::unexpected(Error::NotOpen);
            if (Upstream_->TransportType() == Prism::Transmission::Type::Udp)
                co_return co_await ReceiveDatagram();
            co_return co_await ReceiveStreamFrame();
        }

    private:
        [[nodiscard]] auto ReceiveDatagram() -> Net::awaitable<Packet>
        {
            std::array<std::uint8_t, 65536> Datagram{};
            const auto Part = co_await Upstream_->ReadSome(
                Prism::AsBytes(std::span<std::uint8_t>(Datagram)));
            if (Part.Failure.Failed()) co_return std::unexpected(Error::IoError);
            if (Part.Bytes == 0U) co_return std::unexpected(Error::UnexpectedEof);
            if (Part.Bytes > Datagram.size()) co_return std::unexpected(Error::BadLength);

            Message Parsed{};
            const auto Received = Part.Bytes;
            std::size_t Consumed = 0;
            const auto ParseError = Parse(
                std::span<const std::uint8_t>(Datagram.data(), Received), Parsed, Consumed);
            if (ParseError != Error::None || Parsed.Cmd != CmdPacket || Consumed != Received)
            {
                co_return std::unexpected(
                    ParseError == Error::None ? Error::BadMessage : ParseError);
            }
            co_return Packet{std::move(Parsed)};
        }

        [[nodiscard]] auto ReceiveStreamFrame() -> Net::awaitable<Packet>
        {
            std::array<std::uint8_t, 10> Head{};
            if (co_await ReadExact(std::span<std::uint8_t>(Head)))
                co_return std::unexpected(Error::UnexpectedEof);
            if (Head[0] != ProtocolVersion || Head[1] != CmdPacket)
                co_return std::unexpected(Error::BadMessage);

            Message Parsed{};
            Parsed.Cmd = Head[1];
            Parsed.AssocId = static_cast<std::uint16_t>(Head[2]) << 8U | Head[3];
            Parsed.PktId = static_cast<std::uint16_t>(Head[4]) << 8U | Head[5];
            Parsed.FragTotal = Head[6];
            Parsed.FragId = Head[7];
            Parsed.Size = static_cast<std::uint16_t>(Head[8]) << 8U | Head[9];
            if (Parsed.FragTotal == 0U || Parsed.FragId >= Parsed.FragTotal)
                co_return std::unexpected(Error::BadMessage);

            const auto AddressError = co_await ReadAddress(Parsed);
            if (AddressError != Error::None) co_return std::unexpected(AddressError);
            std::vector<std::uint8_t> Chunk(Parsed.Size);
            if (co_await ReadExact(std::span<std::uint8_t>(Chunk)))
                co_return std::unexpected(Error::UnexpectedEof);
            if (!Chunk.empty())
            {
                Parsed.payload.assign(
                    reinterpret_cast<const char *>(Chunk.data()), Chunk.size());
            }
            co_return Packet{std::move(Parsed)};
        }

        [[nodiscard]] auto ReadAddress(Message &Parsed) -> Net::awaitable<Error>
        {
            // ATYP 位于 10 字节帧头之后。
            std::array<std::uint8_t, 1> Atyp{};
            if (co_await ReadExact(std::span<std::uint8_t>(Atyp)))
                co_return Error::UnexpectedEof;
            Parsed.dst.Type = static_cast<AddressType>(Atyp[0]);
            if (Parsed.dst.Type == AddressType::None)
            {
                if (Parsed.FragId == 0U) co_return Error::BadMessage;
                co_return Error::None;
            }
            if (Parsed.FragId != 0U) co_return Error::BadMessage;

            const auto AddressError = co_await ReadAddressBody(Parsed.dst);
            if (AddressError != Error::None) co_return AddressError;
            std::array<std::uint8_t, 2> Port{};
            if (co_await ReadExact(std::span<std::uint8_t>(Port)))
                co_return Error::UnexpectedEof;
            Parsed.dst.Port = static_cast<std::uint16_t>(Port[0]) << 8U | Port[1];
            co_return Error::None;
        }

        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Dst) -> Net::awaitable<bool>
        {
            if (!Upstream_) co_return true;
            std::size_t Done = 0;
            while (Done < Dst.size())
            {
                const auto Part = co_await Upstream_->ReadSome(
                    Prism::AsBytes(Dst.subspan(Done)));
                if (Part.Failure.Failed() || Part.Bytes == 0U ||
                    Part.Bytes > Dst.size() - Done)
                {
                    co_return true;
                }
                Done += Part.Bytes;
            }
            co_return false;
        }

        [[nodiscard]] auto ReadAddressBody(Address &AddressValue) -> Net::awaitable<Error>
        {
            return Prism::Protocol::Common::ReadAddressBody(
                AddressValue,
                [this](std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
                { return ReadExact(Buffer); });
        }

        SharedTransmission Upstream_;
    };
} // namespace Prism::Tuic::Detail
