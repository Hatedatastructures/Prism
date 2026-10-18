/**
 * @file ConnIo.hpp
 * @brief TUIC 连接的 executor、精确读写和 wire frame IO owner。
 * @details 保留 partial I/O、短写循环、按帧精确读取以及地址体解析。
 *          该 owner 不持有传输或协议租约，所有连接资源均由 ConnSession
 *          持有；认证、stream 和 datagram owner 通过本对象复用相同的 IO。
 */
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Tuic/Codec.hpp>
#include <Prism/Protocols/Tuic/ConnSession.hpp>

namespace Prism::Tuic::detail
{

    namespace Net = boost::asio;

    /**
     * @class ConnIo
     * @brief TUIC 连接的底层 IO 和 wire frame owner。
     * @tparam Memory 会话内存策略
     * @note 实例非线程安全；调用方负责在同一 executor 上串行访问。
     */
    template <Prism::Memory::Restrict Memory>
    class ConnIo final
    {
    public:
        explicit ConnIo(ConnSession<Memory> &Session) noexcept : Session_(Session)
        {
        }

        ConnIo(const ConnIo &) = delete;
        auto operator=(const ConnIo &) -> ConnIo & = delete;

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Session_.Executor();
        }

        [[nodiscard]] auto HasUpstream() const noexcept -> bool
        {
            return Session_.Underlying() != nullptr;
        }

        [[nodiscard]] auto Underlying() noexcept -> SharedTransmission
        {
            return Session_.Underlying();
        }

        [[nodiscard]] auto Underlying() const noexcept -> SharedTransmission
        {
            return Session_.Underlying();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission *
        {
            return Session_.NextLayer();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission *
        {
            return Session_.NextLayer();
        }

        [[nodiscard]] auto Release() -> SharedTransmission
        {
            return Session_.Release();
        }

        /** @brief 封止并交付底层关闭；实际退出由 Activity()->Drain() 另行等待。 */
        [[nodiscard]] auto Close() -> Prism::Transmission::ControlResult
        {
            return Session_.Close();
        }

        /** @brief 可重复取消底层 I/O；成功不表示连接已关闭。 */
        [[nodiscard]] auto Cancel() -> Prism::Transmission::ControlResult
        {
            return Session_.Cancel();
        }

        /** @brief 将后续协程工作切换到连接底层 executor。 */
        [[nodiscard]] auto DispatchToExecutor() -> Net::awaitable<void>
        {
            const auto Upstream = Session_.Underlying();
            if (Upstream)
            {
                co_await Net::dispatch(Upstream->Executor(), Net::use_awaitable);
            }
        }

        /** @brief 执行一次底层 partial read；结果沿用正式 IoResult。 */
        [[nodiscard]] auto ReadSome(std::span<std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
        {
            const auto Upstream = Session_.Underlying();
            if (!Upstream)
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }
            co_return co_await Upstream->ReadSome(Buffer);
        }

        /** @brief 执行一次底层 partial write；结果沿用正式 IoResult。 */
        [[nodiscard]] auto WriteSome(std::span<const std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
        {
            const auto Upstream = Session_.Underlying();
            if (!Upstream)
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }
            co_return co_await Upstream->WriteSome(Buffer);
        }

        /** @brief 真实写半关闭转交底层传输；读取方向保持可用。 */
        auto WriteShutdown(Prism::Transport::Detail::IoCompletion Handler) -> void
        {
            const auto Upstream = Session_.Underlying();
            if (!Upstream)
            {
                Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {Prism::Fault::Code::IoError}});
                return;
            }
            Upstream->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 精确读取指定字节数。
         * @return true 表示底层错误、EOF 或返回了越界字节数。
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Data)
            -> Net::awaitable<bool>
        {
            const auto Upstream = Session_.Underlying();
            co_return co_await ReadExactFrom(Upstream, Data);
        }

        /**
         * @brief 循环短写直至完整 wire 发出。
         * @return true 表示底层错误、EOF 或返回了越界字节数。
         */
        [[nodiscard]] static auto SendBytes(
            const SharedTransmission &Upstream,
            std::span<const std::uint8_t> Data) -> Net::awaitable<bool>
        {
            if (!Upstream)
            {
                co_return true;
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                const auto Part = co_await Upstream->WriteSome(AsBytes(Data.subspan(Done)));
                if (Part.Failure.Failed() || Part.Bytes == 0 || Part.Bytes > Data.size() - Done)
                {
                    co_return true;
                }
                Done += Part.Bytes;
            }
            co_return false;
        }

        /** @brief 从指定传输精确读取认证帧或其他独立输入。 */
        [[nodiscard]] static auto ReadExactFrom(
            const SharedTransmission &Upstream,
            std::span<std::uint8_t> Data) -> Net::awaitable<bool>
        {
            if (!Upstream)
            {
                co_return true;
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                const auto Part = co_await Upstream->ReadSome(AsBytes(Data.subspan(Done)));
                if (Part.Failure.Failed() || Part.Bytes == 0 || Part.Bytes > Data.size() - Done)
                {
                    co_return true;
                }
                Done += Part.Bytes;
            }
            co_return false;
        }

        /**
         * @brief 读取一条 TUIC Connect/Packet wire frame。
         * @details 地址体按协议族精确读取；packet continuation 必须携带 None
         *          地址类型，首片必须携带完整目标地址。
         */
        [[nodiscard]] auto ReadFrame(Message &MessageValue) -> Net::awaitable<Error>
        {
            std::array<std::uint8_t, 2> Head{};
            if (co_await ReadExact(std::span<std::uint8_t>(Head)))
            {
                co_return Error::UnexpectedEof;
            }
            if (Head[0] != ProtocolVersion)
            {
                co_return Error::BadMagic;
            }
            MessageValue.Cmd = Head[1];
            if (MessageValue.Cmd == CmdPacket)
            {
                std::array<std::uint8_t, 8> PacketHeader{};
                if (co_await ReadExact(std::span<std::uint8_t>(PacketHeader)))
                {
                    co_return Error::UnexpectedEof;
                }
                MessageValue.AssocId =
                    static_cast<std::uint16_t>(PacketHeader[0]) << 8 | PacketHeader[1];
                MessageValue.PktId =
                    static_cast<std::uint16_t>(PacketHeader[2]) << 8 | PacketHeader[3];
                MessageValue.FragTotal = PacketHeader[4];
                MessageValue.FragId = PacketHeader[5];
                MessageValue.Size =
                    static_cast<std::uint16_t>(PacketHeader[6]) << 8 | PacketHeader[7];
                if (MessageValue.FragTotal == 0 || MessageValue.FragId >= MessageValue.FragTotal)
                {
                    co_return Error::BadMessage;
                }
            }
            if (MessageValue.Cmd == CmdConnect || MessageValue.Cmd == CmdPacket)
            {
                std::array<std::uint8_t, 1> Atyp{};
                if (co_await ReadExact(std::span<std::uint8_t>(Atyp)))
                {
                    co_return Error::UnexpectedEof;
                }
                const auto IsPacketContinuation =
                    MessageValue.Cmd == CmdPacket && MessageValue.FragId != 0;
                if (IsPacketContinuation)
                {
                    if (Atyp[0] != static_cast<std::uint8_t>(AddressType::None))
                    {
                        co_return Error::BadMessage;
                    }
                    MessageValue.dst.Type = AddressType::None;
                    MessageValue.dst.Host.clear();
                    MessageValue.dst.Port = 0;
                }
                else
                {
                    MessageValue.dst.Type = static_cast<AddressType>(Atyp[0]);
                    const auto AddressError = co_await ReadAddressBody(MessageValue.dst);
                    if (AddressError != Error::None)
                    {
                        co_return AddressError;
                    }
                    std::array<std::uint8_t, 2> Port{};
                    if (co_await ReadExact(std::span<std::uint8_t>(Port)))
                    {
                        co_return Error::UnexpectedEof;
                    }
                    MessageValue.dst.Port =
                        static_cast<std::uint16_t>(Port[0]) << 8 | Port[1];
                }
            }
            if (MessageValue.Cmd == CmdPacket)
            {
                if (MessageValue.FragId == 0)
                {
                    if (MessageValue.dst.Type == AddressType::None)
                    {
                        co_return Error::BadMessage;
                    }
                }
                else if (MessageValue.dst.Type != AddressType::None)
                {
                    co_return Error::BadMessage;
                }
                std::vector<std::uint8_t> Payload(MessageValue.Size);
                if (co_await ReadExact(std::span<std::uint8_t>(Payload)))
                {
                    co_return Error::UnexpectedEof;
                }
                MessageValue.payload.assign(Payload.begin(), Payload.end());
            }
            co_return Error::None;
        }

        /** @brief 读取地址体，复用协议公共地址解析实现。 */
        [[nodiscard]] auto ReadAddressBody(Address &AddressValue)
            -> Net::awaitable<Error>
        {
            return Prism::Protocol::Common::ReadAddressBody(
                AddressValue,
                [this](std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
                {
                    return ReadExact(Buffer);
                });
        }

    private:
        ConnSession<Memory> &Session_;
    };

} // namespace Prism::Tuic::detail
