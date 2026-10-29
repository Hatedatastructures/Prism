/**
 * @file Datagram.hpp
 * @brief TUIC packet 命令和 UDP-only 数据面 owner。
 * @details 负责 packet frame 构造、解析、包序号推进和目标地址/载荷输出。
 *          它只在连接级 Connect 握手完成后工作，不参与独立 Dgram 的
 *          UDP socket 生命周期。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Tuic/Codec.hpp>
#include <Prism/Protocols/Tuic/Connection/Io.hpp>

namespace Prism::Tuic::detail
{

    namespace Net = boost::asio;

    /**
     * @class ConnDatagram
     * @brief TUIC 连接级 packet/UDP 数据面 owner。
     * @tparam Memory 会话内存策略
     */
    template <Prism::Memory::Restrict Memory>
    class ConnDatagram final
    {
    public:
        ConnDatagram(ConnSession<Memory> &Session, ConnIo<Memory> &Io) noexcept
            : Session_(Session), Io_(Io)
        {
        }

        ConnDatagram(const ConnDatagram &) = delete;
        auto operator=(const ConnDatagram &) -> ConnDatagram & = delete;

        /** @brief 发送一个 TUIC packet frame。 */
        [[nodiscard]] auto AsyncSendDatagram(
            const Address &Target,
            std::span<const std::uint8_t> Payload) -> Net::awaitable<Error>
        {
            co_await Io_.DispatchToExecutor();
            if (!Session_.IsHandshaken() || !Session_.Underlying())
            {
                co_return Error::NotOpen;
            }
            if (Payload.size() > 0xFFFF)
            {
                co_return Error::BadLength;
            }
            Message MessageValue;
            MessageValue.Cmd = CmdPacket;
            MessageValue.AssocId = Session_.AssocId();
            MessageValue.PktId = Session_.PacketId();
            MessageValue.dst = Target;
            MessageValue.payload.assign(
                reinterpret_cast<const char *>(Payload.data()), Payload.size());
            const auto Wire = Build(MessageValue);
            if (Wire.empty())
            {
                co_return Error::BadAddress;
            }
            Session_.AdvancePacketId();
            if (co_await ConnIo<Memory>::SendBytes(
                    Session_.Underlying(), std::span<const std::uint8_t>(Wire)))
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        /** @brief 接收并解析一个 TUIC packet frame。 */
        [[nodiscard]] auto AsyncReceiveDatagram(
            Address &Target,
            std::vector<std::uint8_t> &Payload) -> Net::awaitable<Error>
        {
            co_await Io_.DispatchToExecutor();
            if (!Session_.IsHandshaken() || !Session_.Underlying())
            {
                co_return Error::NotOpen;
            }
            Message MessageValue;
            const auto FrameError = co_await Io_.ReadFrame(MessageValue);
            if (FrameError != Error::None)
            {
                co_return FrameError;
            }
            if (MessageValue.Cmd != CmdPacket)
            {
                co_return Error::BadMessage;
            }
            Target = MessageValue.dst;
            Payload.assign(MessageValue.payload.begin(), MessageValue.payload.end());
            co_return Error::None;
        }

    private:
        ConnSession<Memory> &Session_;
        ConnIo<Memory> &Io_;
    };

} // namespace Prism::Tuic::detail
