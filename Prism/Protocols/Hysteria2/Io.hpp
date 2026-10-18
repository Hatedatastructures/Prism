/**
 * @file Io.hpp
 * @brief Hysteria2 连接的精确读写辅助。
 * @details 该 owner 只负责 Transmission 的完整字节读写和地址体消费；
 *          Conn 保留握手、帧状态、账户租约与关闭职责。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Hysteria2/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <array>
#include <vector>

namespace Prism::Hysteria2::Detail
{

    namespace Net = boost::asio;

    [[nodiscard]] inline auto ReadExact(const Prism::SharedTransmission &Transport,
                                        std::span<std::uint8_t> Destination)
        -> Net::awaitable<bool>
    {
        if (!Transport)
        {
            co_return true;
        }
        std::size_t Done = 0;
        while (Done < Destination.size())
        {
            const auto Part = co_await Transport->ReadSome(
                AsBytes(Destination.subspan(Done)));
            const auto ErrorCode = Prism::Fault::ToNative(Part.Failure);
            const auto Count = Part.Bytes;
            if (ErrorCode || Count == 0U || Count > Destination.size() - Done)
            {
                co_return true;
            }
            Done += Count;
        }
        co_return false;
    }

    [[nodiscard]] inline auto SendBytes(const Prism::SharedTransmission &Transport,
                                        std::span<const std::uint8_t> Data)
        -> Net::awaitable<bool>
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

    [[nodiscard]] inline auto ReadAddressBody(
        const Prism::SharedTransmission &Transport,
        Prism::Hysteria2::Address &AddressValue) -> Net::awaitable<Prism::Error>
    {
        return Prism::Protocol::Common::ReadAddressBody(
            AddressValue,
            [Transport](std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
            {
                return ReadExact(Transport, Buffer);
            });
    }

    /**
     * @brief 读取一个完整 Hysteria2 帧。
     * @param Transport 借用底层传输；所有权由调用方保留，借用期限到本次 completion。
     * @param MessageValue 输出帧；只在完整读取后写入。
     * @return 协议错误；EOF、短读与解析失败分别保留原类别。
     * @note 帧无长度字段：精确分段读取头部（Kind/Id/地址），剩余一次读为载荷。
     *       本函数不执行关闭、取消或半关闭。
     */
    [[nodiscard]] inline auto ReadFrame(const Prism::SharedTransmission &Transport,
                                        Prism::Hysteria2::Message &MessageValue)
        -> Net::awaitable<Prism::Error>
    {
        std::array<std::uint8_t, 1> Kind{};
        if (co_await ReadExact(Transport, std::span<std::uint8_t>(Kind)))
        {
            co_return Prism::Error::UnexpectedEof;
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
            if (co_await ReadExact(Transport, std::span<std::uint8_t>(Ids)))
            {
                co_return Prism::Error::UnexpectedEof;
            }

            MessageValue.SessionId =
                static_cast<std::uint32_t>(Ids[0]) | static_cast<std::uint32_t>(Ids[1]) << 8 |
                static_cast<std::uint32_t>(Ids[2]) << 16 | static_cast<std::uint32_t>(Ids[3]) << 24;
            MessageValue.PacketId =
                static_cast<std::uint32_t>(Ids[4]) | static_cast<std::uint32_t>(Ids[5]) << 8 |
                static_cast<std::uint32_t>(Ids[6]) << 16 | static_cast<std::uint32_t>(Ids[7]) << 24;
        }
        // 地址体：ATYP(1) + ADDR + PORT(2)
        std::array<std::uint8_t, 1> Atyp{};
        if (co_await ReadExact(Transport, std::span<std::uint8_t>(Atyp)))
        {
            co_return Prism::Error::UnexpectedEof;
        }
        MessageValue.dst.Type = static_cast<Prism::Hysteria2::AddressType>(Atyp[0]);
        const auto AddressError = co_await ReadAddressBody(Transport, MessageValue.dst);
        if (AddressError != Prism::Error::None)
        {
            co_return AddressError;
        }
        std::array<std::uint8_t, 2> Port{};
        if (co_await ReadExact(Transport, std::span<std::uint8_t>(Port)))
        {
            co_return Prism::Error::UnexpectedEof;
        }
        MessageValue.dst.Port = static_cast<std::uint16_t>(Port[0]) << 8 | Port[1];
        if (MessageValue.Type != Prism::Hysteria2::Message::Kind::Udp)
        {
            co_return Prism::Error::None;
        }
        // 载荷：剩余一次读（帧边界由调用方约定）
        std::array<std::uint8_t, 512> Chunk{};
        const auto Part = co_await Transport->ReadSome(AsBytes(std::span<std::uint8_t>(Chunk)));
        const auto ErrorCode = Prism::Fault::ToNative(Part.Failure);
        const auto Count = Part.Bytes;
        if (ErrorCode)
        {
            co_return Prism::Error::IoError;
        }
        if (Count > Chunk.size())
        {
            co_return Prism::Error::BadLength;
        }
        MessageValue.payload.assign(
            Chunk.begin(),
            Chunk.begin() + static_cast<std::ptrdiff_t>(Count));
        co_return Prism::Error::None;
    }

} // namespace Prism::Hysteria2::Detail
