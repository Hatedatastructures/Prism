/**
 * @file Stream.hpp
 * @brief TUIC Connect 握手和握手后可靠流 owner。
 * @details 负责客户端 Connect frame、服务端 Connect frame 解析以及
 *          Transmission 的 partial read/write 透传。底层传输所有权和
 *          认证/握手标志由 ConnSession 持有。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Tuic/Codec.hpp>
#include <Prism/Protocols/Tuic/Connection/Io.hpp>
#include <cstdint>

namespace Prism::Tuic::detail
{

    namespace Net = boost::asio;

    /**
     * @class ConnStream
     * @brief TUIC 可靠流握手和数据透传 owner。
     * @tparam Memory 会话内存策略
     */
    template <Prism::Memory::Restrict Memory>
    class ConnStream final
    {
    public:
        ConnStream(ConnSession<Memory> &Session, ConnIo<Memory> &Io) noexcept
            : Session_(Session), Io_(Io)
        {
        }

        ConnStream(const ConnStream &) = delete;
        auto operator=(const ConnStream &) -> ConnStream & = delete;

        /** @brief 客户端发送 Connect frame。 */
        [[nodiscard]] auto WriteHandshake(const Address &Target)
            -> Net::awaitable<Error>
        {
            co_await Io_.DispatchToExecutor();
            if (!Session_.IsAuthenticated())
            {
                co_return Error::BadAuth;
            }
            const auto Upstream = Session_.Underlying();
            if (!Upstream)
            {
                co_return Error::NotOpen;
            }
            Message MessageValue;
            MessageValue.Cmd = CmdConnect;
            MessageValue.dst = Target;
            const auto Wire = Build(MessageValue);
            if (Wire.empty())
            {
                co_return Error::BadAddress;
            }
            if (co_await ConnIo<Memory>::SendBytes(
                    Upstream, std::span<const std::uint8_t>(Wire)))
            {
                co_return Error::IoError;
            }
            Session_.SetTarget(Target);
            Session_.SetHandshaken(true);
            co_return Error::None;
        }

        /** @brief 服务端读取并校验 Connect frame。 */
        [[nodiscard]] auto ReadHandshake()
            -> Net::awaitable<std::pair<Error, Message>>
        {
            co_await Io_.DispatchToExecutor();
            if (!Session_.IsAuthenticated())
            {
                co_return std::pair{Error::BadAuth, Message{}};
            }
            if (!Session_.Underlying())
            {
                co_return std::pair{Error::NotOpen, Message{}};
            }
            Message MessageValue;
            const auto FrameError = co_await Io_.ReadFrame(MessageValue);
            if (FrameError != Error::None)
            {
                co_return std::pair{FrameError, Message{}};
            }
            if (MessageValue.Cmd != CmdConnect)
            {
                co_return std::pair{Error::BadMessage, Message{}};
            }
            Session_.SetTarget(MessageValue.dst);
            Session_.SetParsed(MessageValue);
            Session_.SetHandshaken(true);
            co_return std::pair{Error::None, std::move(MessageValue)};
        }

        [[nodiscard]] auto Parsed() const noexcept -> const Message &
        {
            return Session_.Parsed();
        }

        /** @brief 握手后的 partial read；未握手返回确定的失败码，结果沿用正式 IoResult。 */
        [[nodiscard]] auto ReadSome(std::span<std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
        {
            co_await Io_.DispatchToExecutor();
            if (!Session_.Underlying() || !Session_.IsHandshaken())
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }
            co_return co_await Io_.ReadSome(Buffer);
        }

        /** @brief 握手后的 partial write；未握手返回确定的失败码，结果沿用正式 IoResult。 */
        [[nodiscard]] auto WriteSome(std::span<const std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
        {
            co_await Io_.DispatchToExecutor();
            if (!Session_.Underlying() || !Session_.IsHandshaken())
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }
            co_return co_await Io_.WriteSome(Buffer);
        }

    private:
        ConnSession<Memory> &Session_;
        ConnIo<Memory> &Io_;
    };

} // namespace Prism::Tuic::detail
