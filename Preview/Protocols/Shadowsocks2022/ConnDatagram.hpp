/**
 * @file ConnDatagram.hpp
 * @brief Shadowsocks 2022 流连接上的 UDP 数据报 record owner。
 * @details 负责数据报模式的明文头预读、partial I/O、AEAD 解析和
 *          stream/datagram 互斥所需的会话状态访问。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Shadowsocks2022/Codec.hpp>
#include <Preview/Protocols/Shadowsocks2022/ConnRecord.hpp>

namespace Preview::Shadowsocks2022::detail
{

    namespace Net = boost::asio;
    namespace ss = Preview::Shadowsocks2022;

    /**
     * @brief SS2022 流连接上的 UDP 数据报 owner。
     * @tparam Memory 会话内存策略
     * @details 数据报路径不使用 chunk Nonce；它只通过 Record owner 的
     *          Raw I/O 访问底层传输，并复用会话的 PSK/数据报缓冲。
     */
    template <Preview::Memory::Restrict Memory>
    class ConnDatagram final
    {
    public:
        using Session = ConnSession<Memory>;
        using Record = ConnRecord<Memory>;

        ConnDatagram(Session &SessionValue, Record &RecordValue)
            : Session_(SessionValue), Record_(RecordValue)
        {
        }

        [[nodiscard]] auto AsyncSendDatagram(
            const ss::Address &Target,
            std::span<const std::uint8_t> Payload) -> Net::awaitable<Error>
        {
            if (!Session_.Handshaken_)
            {
                co_return Error::NotOpen;
            }
            const auto Packet = ss::BuildUdpPacket(
                ss::UdpBuildInput{Session_.SessionKey_, ++Session_.UdpPktId_, &Target, Payload});
            if (Packet.empty())
            {
                co_return Error::BadLength;
            }
            if (co_await Record_.SendBytes(Packet))
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        [[nodiscard]] auto AsyncReceiveDatagram(
            ss::Address &Target,
            std::vector<std::uint8_t> &Payload) -> Net::awaitable<Error>
        {
            if (!Session_.Handshaken_)
            {
                co_return Error::NotOpen;
            }

            std::array<std::uint8_t, ss::SeparateHdrLen> Separate{};
            if (co_await UdpReadExact(Separate))
            {
                co_return Error::UnexpectedEof;
            }
            std::array<std::uint8_t, 1 + ss::UdpTsLen> Header{};
            if (co_await UdpReadExact(Header))
            {
                co_return Error::UnexpectedEof;
            }
            if (Header[0] != ss::UdpType)
            {
                co_return Error::BadMessage;
            }

            std::array<std::uint8_t, 1> AddressTypeByte{};
            if (co_await UdpReadExact(AddressTypeByte))
            {
                co_return Error::UnexpectedEof;
            }
            const auto AddressTypeValue = static_cast<ss::AddressType>(AddressTypeByte[0]);
            std::size_t AddressLength = 0;
            std::uint8_t DomainLength = 0;
            if (AddressTypeValue == ss::AddressType::Ipv4)
            {
                AddressLength = 4;
            }
            else if (AddressTypeValue == ss::AddressType::Ipv6)
            {
                AddressLength = 16;
            }
            else if (AddressTypeValue == ss::AddressType::Domain)
            {
                std::array<std::uint8_t, 1> DomainLengthByte{};
                if (co_await UdpReadExact(DomainLengthByte))
                {
                    co_return Error::UnexpectedEof;
                }
                DomainLength = DomainLengthByte[0];
                AddressLength = DomainLength;
            }
            else
            {
                co_return Error::BadMessage;
            }

            std::vector<std::uint8_t> AddressBody(AddressLength);
            if (co_await UdpReadExact(AddressBody))
            {
                co_return Error::UnexpectedEof;
            }
            std::array<std::uint8_t, 2> Port{};
            if (co_await UdpReadExact(Port))
            {
                co_return Error::UnexpectedEof;
            }

            Session_.UdpRx_.clear();
            if (Session_.UdpUsed_ > 0)
            {
                Session_.UdpRx_.assign(
                    Session_.UdpBuf_.begin(),
                    Session_.UdpBuf_.begin() + static_cast<std::ptrdiff_t>(Session_.UdpUsed_));
                Session_.UdpBuf_.clear();
                Session_.UdpUsed_ = 0;
            }
            else
            {
                std::array<std::uint8_t, 512> Chunk{};
                const auto Part = co_await Session_.NextLayer_->ReadSome(
                    Preview::AsBytes(std::span<std::uint8_t>(Chunk)));
                const auto ErrorCode = Preview::Fault::ToNative(Part.Failure);
                const auto Count = Part.Bytes;
                if (ErrorCode || Count == 0 || Count > Chunk.size())
                {
                    co_return Error::UnexpectedEof;
                }
                Session_.UdpRx_.assign(
                    Chunk.begin(),
                    Chunk.begin() + static_cast<std::ptrdiff_t>(Count));
            }
            const auto CipherLength = Session_.UdpRx_.size();

            std::vector<std::uint8_t> Packet;
            Packet.reserve(ss::SeparateHdrLen + Header.size() + 1 + AddressBody.size() + 2 + CipherLength);
            Packet.insert(Packet.end(), Separate.begin(), Separate.end());
            Packet.insert(Packet.end(), Header.begin(), Header.end());
            Packet.insert(Packet.end(), AddressTypeByte.begin(), AddressTypeByte.end());
            if (DomainLength > 0)
            {
                Packet.push_back(DomainLength);
            }
            Packet.insert(Packet.end(), AddressBody.begin(), AddressBody.end());
            Packet.insert(Packet.end(), Port.begin(), Port.end());
            Packet.insert(Packet.end(), Session_.UdpRx_.begin(), Session_.UdpRx_.end());
            co_return ss::ParseUdpPacket(
                ss::UdpParseInput{Session_.SessionKey_, Packet, &Target, &Payload});
        }

    private:
        [[nodiscard]] auto UdpReadExact(std::span<std::uint8_t> Buffer)
            -> Net::awaitable<bool>
        {
            if (!Session_.NextLayer_)
            {
                co_return true;
            }
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                if (Session_.UdpUsed_ > 0)
                {
                    const auto Count = (std::min)(Buffer.size() - Done, Session_.UdpUsed_);
                    std::memcpy(Buffer.data() + Done, Session_.UdpBuf_.data(), Count);
                    if (Count < Session_.UdpUsed_)
                    {
                        std::memmove(Session_.UdpBuf_.data(),
                                     Session_.UdpBuf_.data() + Count,
                                     Session_.UdpUsed_ - Count);
                        Session_.UdpUsed_ -= Count;
                    }
                    else
                    {
                        Session_.UdpBuf_.clear();
                        Session_.UdpUsed_ = 0;
                    }
                    Done += Count;
                    continue;
                }

                std::array<std::uint8_t, 512> Chunk{};
                const auto Part = co_await Session_.NextLayer_->ReadSome(
                    Preview::AsBytes(std::span<std::uint8_t>(Chunk)));
                const auto ErrorCode = Preview::Fault::ToNative(Part.Failure);
                const auto Count = Part.Bytes;
                if (ErrorCode || Count == 0 || Count > Chunk.size())
                {
                    co_return true;
                }
                Session_.UdpBuf_.insert(
                    Session_.UdpBuf_.end(),
                    Chunk.begin(),
                    Chunk.begin() + static_cast<std::ptrdiff_t>(Count));
                Session_.UdpUsed_ += Count;
            }
            co_return false;
        }

        Session &Session_;
        Record &Record_;
    };

} // namespace Preview::Shadowsocks2022::detail
