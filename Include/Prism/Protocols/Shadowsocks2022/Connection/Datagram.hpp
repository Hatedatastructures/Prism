/**
 * @file Datagram.hpp
 * @brief Shadowsocks 2022 流连接上的 UDP 数据报 record owner。
 * @details TCP stream 以 4 字节大端长度帧承载完整 SIP022 packet；长度不含
 *          前缀。该外层帧只属于 Conn 的流式数据报 API，不是 SIP022 UDP
 *          wire 格式；独立 Dgram 继续直接使用保留数据报边界的标准 UDP。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Shadowsocks2022/ChunkCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestState.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestWire.hpp>
#include <Prism/Protocols/Shadowsocks2022/ResponseCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/Connection/Record.hpp>

namespace Prism::Shadowsocks2022::detail
{

    namespace Net = boost::asio;
    namespace ss = Prism::Shadowsocks2022;

    /**
     * @brief SS2022 流连接上的 UDP 数据报 owner。
     * @tparam Memory 会话内存策略
     * @details 数据报路径不使用 chunk Nonce；长度帧通过 Record owner 的
     *          Raw I/O 访问底层传输，内层由 SIP022 AEAD parser 验证。精确读取
     *          当前帧并保留同次读取中的后续帧字节及终态。
     */
    template <Prism::Memory::Restrict Memory>
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
            if (Packet.size() > ss::MaxUdpPacketSize)
            {
                co_return Error::BadLength;
            }
            const auto PacketLength = static_cast<std::uint32_t>(Packet.size());
            std::vector<std::uint8_t> Frame;
            Frame.reserve(StreamDatagramLengthPrefixSize + Packet.size());
            Frame.push_back(static_cast<std::uint8_t>(PacketLength >> 24U));
            Frame.push_back(static_cast<std::uint8_t>(PacketLength >> 16U));
            Frame.push_back(static_cast<std::uint8_t>(PacketLength >> 8U));
            Frame.push_back(static_cast<std::uint8_t>(PacketLength));
            Frame.insert(Frame.end(), Packet.begin(), Packet.end());
            const auto SendFailure = co_await Record_.SendBytes(Frame);
            if (SendFailure.Failed())
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
            std::array<std::uint8_t, StreamDatagramLengthPrefixSize> Prefix{};
            if (co_await UdpReadExact(Prefix))
            {
                co_return ReadFailureError();
            }
            const auto PacketLength = DecodePacketLength(Prefix);
            if (PacketLength < ss::MinUdpPacketSize || PacketLength > ss::MaxUdpPacketSize)
            {
                co_return Error::BadLength;
            }
            Session_.UdpRx_.resize(PacketLength);
            if (co_await UdpReadExact(Session_.UdpRx_))
            {
                Session_.UdpRx_.clear();
                co_return ReadFailureError();
            }

            ss::Address ParsedTarget;
            std::vector<std::uint8_t> ParsedPayload;
            const auto ParseError = ss::ParseUdpPacket(ss::UdpParseInput{
                Session_.SessionKey_, Session_.UdpRx_, &ParsedTarget, &ParsedPayload});
            if ((ParseError == Error::BadLength || ParseError == Error::BadAuth) &&
                PendingReadFailure_)
            {
                co_return ReadFailureError();
            }
            if (ParseError != Error::None)
            {
                co_return ParseError;
            }
            Target = std::move(ParsedTarget);
            Payload = std::move(ParsedPayload);
            co_return Error::None;
        }

    private:
        inline static constexpr std::size_t StreamDatagramLengthPrefixSize = 4U;

        [[nodiscard]] static auto DecodePacketLength(
            const std::array<std::uint8_t, StreamDatagramLengthPrefixSize> &Prefix) noexcept
            -> std::uint32_t
        {
            return static_cast<std::uint32_t>(Prefix[0]) << 24U |
                static_cast<std::uint32_t>(Prefix[1]) << 16U |
                static_cast<std::uint32_t>(Prefix[2]) << 8U |
                static_cast<std::uint32_t>(Prefix[3]);
        }

        [[nodiscard]] auto ReadFailureError() const noexcept -> Error
        {
            if (!PendingReadFailure_)
            {
                return Error::UnexpectedEof;
            }
            switch (PendingReadFailure_->Code)
            {
            case Prism::Fault::Code::Eof: return Error::UnexpectedEof;
            case Prism::Fault::Code::Canceled: return Error::Canceled;
            case Prism::Fault::Code::Timeout: return Error::Timeout;
            default: return Error::IoError;
            }
        }

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

                if (PendingReadFailure_)
                {
                    co_return true;
                }
                std::array<std::uint8_t, 512> Chunk{};
                const auto Part = co_await Session_.NextLayer_->ReadSome(
                    Prism::AsBytes(std::span<std::uint8_t>(Chunk)));
                const auto Count = Part.Bytes;
                if (Count > Chunk.size())
                {
                    co_return true;
                }
                if (Count != 0U)
                {
                    Session_.UdpBuf_.insert(
                        Session_.UdpBuf_.end(),
                        Chunk.begin(),
                        Chunk.begin() + static_cast<std::ptrdiff_t>(Count));
                    Session_.UdpUsed_ += Count;
                }
                if (Part.Failure.Failed())
                {
                    PendingReadFailure_ = Part.Failure;
                    continue;
                }
                if (Count == 0U)
                {
                    co_return true;
                }
            }
            co_return false;
        }

        Session &Session_;
        Record &Record_;
        std::optional<Prism::Fault::Failure> PendingReadFailure_{};
    };

} // namespace Prism::Shadowsocks2022::detail
