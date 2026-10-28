/**
 * @file Io.hpp
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
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Tuic/Codec.hpp>
#include <Prism/Protocols/Tuic/Connection/Session.hpp>
#include <Prism/Transport/Transmission.hpp>

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
            if (ReadFailure_)
            {
                co_return Prism::IoResult{0U, *ReadFailure_};
            }
            if (PendingTerminal_)
            {
                const auto Failure = *PendingTerminal_;
                PendingTerminal_.reset();
                RecordReadFailure(Failure);
                co_return Prism::IoResult{0, Failure};
            }
            const auto Upstream = Session_.Underlying();
            if (!Upstream)
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }
            const auto Result = co_await Upstream->ReadSome(Buffer);
            if (Result.Failure.Failed())
            {
                RecordReadFailure(Result.Failure);
            }
            co_return Result;
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
        auto WriteShutdown(Prism::Transmission::Completion Handler) -> void
        {
            const auto Upstream = Session_.Underlying();
            if (!Upstream)
            {
                Prism::Transmission::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {Prism::Fault::Code::IoError}});
                return;
            }
            Upstream->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 精确读取指定字节数。
         * @return Bytes 为累计已读数；Failure 保留同次完成的 terminal。
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Data)
            -> Net::awaitable<Prism::IoResult>
        {
            if (ReadFailure_)
            {
                co_return Prism::IoResult{0U, *ReadFailure_};
            }
            if (PendingTerminal_)
            {
                const auto Failure = *PendingTerminal_;
                PendingTerminal_.reset();
                RecordReadFailure(Failure);
                co_return Prism::IoResult{0, Failure};
            }
            const auto Upstream = Session_.Underlying();
            if (!Upstream)
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }
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

        /** @brief 从指定传输精确读取，并保留累计字节与底层 terminal。 */
        [[nodiscard]] static auto ReadExactFrom(
            const SharedTransmission &Upstream,
            std::span<std::uint8_t> Data) -> Net::awaitable<Prism::IoResult>
        {
            Prism::IoResult Result{};
            if (!Upstream)
            {
                Result.Failure = {Prism::Fault::Code::IoError};
                co_return Result;
            }
            while (Result.Bytes < Data.size())
            {
                const auto Remaining = Data.size() - Result.Bytes;
                const auto Part = co_await Upstream->ReadSome(
                    AsBytes(Data.subspan(Result.Bytes)));
                if (Part.Bytes > Remaining)
                {
                    Result.Failure = {
                        Prism::Fault::Code::InvalidArgument, Part.Failure.Native};
                    co_return Result;
                }
                Result.Bytes += Part.Bytes;
                Result.Failure = Part.Failure;
                if (Result.Failure.Failed())
                {
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

        /**
         * @brief 读取一条 TUIC Connect/Packet wire frame。
         * @details 地址体按协议族精确读取；packet continuation 必须携带 None
         *          地址类型，首片必须携带完整目标地址。
         */
        [[nodiscard]] auto ReadFrame(Message &MessageValue) -> Net::awaitable<Error>
        {
            std::array<std::uint8_t, 2> Head{};
            const auto HeadError = co_await ReadFrameField(
                std::span<std::uint8_t>(Head), false);
            if (HeadError != Error::None)
            {
                co_return HeadError;
            }
            if (Head[0] != ProtocolVersion)
            {
                co_return Error::BadMagic;
            }
            MessageValue.Cmd = Head[1];
            if (MessageValue.Cmd == CmdPacket)
            {
                std::array<std::uint8_t, 8> PacketHeader{};
                const auto HeaderError = co_await ReadFrameField(
                    std::span<std::uint8_t>(PacketHeader), false);
                if (HeaderError != Error::None)
                {
                    co_return HeaderError;
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
                const auto IsPacketContinuation =
                    MessageValue.Cmd == CmdPacket && MessageValue.FragId != 0;
                const auto AtypError = co_await ReadFrameField(
                    std::span<std::uint8_t>(Atyp),
                    IsPacketContinuation && MessageValue.Size == 0U);
                if (AtypError != Error::None)
                {
                    co_return AtypError;
                }
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
                    std::optional<Prism::Fault::Failure> AddressFailure;
                    const auto AddressError = co_await ReadAddressBody(
                        MessageValue.dst, AddressFailure);
                    if (AddressFailure)
                    {
                        co_return ReadFailureToError(*AddressFailure);
                    }
                    if (AddressError != Error::None)
                    {
                        co_return AddressError;
                    }
                    std::array<std::uint8_t, 2> Port{};
                    const auto PortError = co_await ReadFrameField(
                        std::span<std::uint8_t>(Port),
                        MessageValue.Cmd == CmdConnect || MessageValue.Size == 0U);
                    if (PortError != Error::None)
                    {
                        co_return PortError;
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
                if (!Payload.empty())
                {
                    const auto PayloadError = co_await ReadFrameField(
                        std::span<std::uint8_t>(Payload), true);
                    if (PayloadError != Error::None)
                    {
                        co_return PayloadError;
                    }
                }
                MessageValue.payload.assign(Payload.begin(), Payload.end());
            }
            co_return Error::None;
        }

        [[nodiscard]] auto ReadAddressBody(
            Address &AddressValue,
            std::optional<Prism::Fault::Failure> &ReadFailure)
            -> Net::awaitable<Error>
        {
            return Prism::Protocol::Common::ReadAddressBody(
                AddressValue,
                [this, &ReadFailure](std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
                {
                    const auto Result = co_await ReadExact(Buffer);
                    if (Result.Failure.Failed())
                    {
                        PreserveAddressReadFailure(ReadFailure, Result.Failure);
                    }
                    co_return Result.Failure.Failed() ||
                        Result.Bytes != Buffer.size();
                });
        }

    private:
        auto RecordReadFailure(const Prism::Fault::Failure &Failure) noexcept -> void
        {
            if (!ReadFailure_ && Failure.Failed())
            {
                ReadFailure_ = Failure;
            }
        }

        auto PreserveAddressReadFailure(
            std::optional<Prism::Fault::Failure> &AddressFailure,
            const Prism::Fault::Failure &ReadTerminal) noexcept -> void
        {
            RecordReadFailure(ReadTerminal);
            AddressFailure = ReadTerminal;
        }

        [[nodiscard]] auto ReadFrameField(
            std::span<std::uint8_t> Data,
            const bool IsFinalField) -> Net::awaitable<Error>
        {
            const auto Result = co_await ReadExact(Data);
            if (Result.Bytes != Data.size())
            {
                if (Result.Failure.Failed())
                {
                    RecordReadFailure(Result.Failure);
                    co_return ReadFailureToError(Result.Failure);
                }
                co_return Error::UnexpectedEof;
            }
            if (Result.Failure.Failed())
            {
                if (!IsFinalField)
                {
                    RecordReadFailure(Result.Failure);
                    co_return ReadFailureToError(Result.Failure);
                }
                PendingTerminal_ = Result.Failure;
            }
            co_return Error::None;
        }

        [[nodiscard]] static auto ReadFailureToError(
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

        ConnSession<Memory> &Session_;
        std::optional<Prism::Fault::Failure> PendingTerminal_{};
        std::optional<Prism::Fault::Failure> ReadFailure_{};
    };

} // namespace Prism::Tuic::detail
