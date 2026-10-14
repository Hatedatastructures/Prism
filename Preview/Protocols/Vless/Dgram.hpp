/**
 * @file Dgram.hpp
 * @brief VLESS 普通 UDP 长度帧连接。
 * @details 一个 VLESS UDP 握手绑定固定目标；数据报 wire 只含
 *          [uint16BE payload length][payload]，不携带逐包地址。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Contract/Io/PacketTransferResult.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Vless/Types.hpp>
#include <Preview/Protocols/Vless/UdpCodec.hpp>

namespace Preview::Vless
{
    namespace Net = boost::asio;

    /**
     * @brief VLESS UDP 包连接；其目标仅由建立此连接的握手确定。
     * @tparam Memory 调用方提供的会话内存资源策略。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Dgram : public Preview::Transmission
    {
    public:
        /** @brief 接管已完成普通 UDP 握手的唯一流连接。 */
        explicit Dgram(SharedTransmission Stream)
            : Preview::Transmission(Stream ? Stream->Executor() : Net::any_io_executor{}),
              NextLayer_(std::move(Stream))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return NextLayer_ ? NextLayer_->Executor() : Preview::Transmission::Executor();
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        /** @brief 编码并完整写出一条长度帧，保留失败原因与真实部分进度。 */
        [[nodiscard]] auto AsyncSendDatagram(
            const std::span<const std::uint8_t> Payload)
            -> Net::awaitable<Preview::Contract::Io::PacketTransferResult>
        {
            if (!NextLayer_)
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, 0, {Preview::Fault::Code::IoError}};
            }
            const auto Encoded = BuildUdpPkt(Payload, TxWire_);
            if (!Encoded)
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, Encoded.error().Transferred, Encoded.error().Cause};
            }

            std::size_t Written = 0;
            while (Written < TxWire_.size())
            {
                const auto Remaining = TxWire_.size() - Written;
                const auto Part = co_await NextLayer_->WriteSome(
                    AsBytes(std::span<const std::uint8_t>(TxWire_).subspan(Written)));
                if (Part.Bytes > Remaining)
                {
                    const auto Progress = Part.Bytes >
                        (std::numeric_limits<std::size_t>::max)() - Written
                        ? (std::numeric_limits<std::size_t>::max)()
                        : Written + Part.Bytes;
                    co_return Preview::Contract::Io::PacketTransferResult{
                        0, Progress,
                        {Preview::Fault::Code::InvalidArgument, Part.Failure.Native}};
                }
                Written += Part.Bytes;
                if (Part.Failure.Failed())
                {
                    co_return Preview::Contract::Io::PacketTransferResult{
                        0, Written, Part.Failure};
                }
                if (Part.Bytes == 0U)
                {
                    co_return Preview::Contract::Io::PacketTransferResult{
                        0, Written, {Preview::Fault::Code::WouldBlock}};
                }
            }
            co_return Preview::Contract::Io::PacketTransferResult{
                Payload.size(), Written, {}};
        }

        /** @brief 精确读取一条长度帧；EOF、截断、取消与 Native 保持可区分。 */
        [[nodiscard]] auto AsyncReceiveDatagram(
            std::vector<std::uint8_t> &Payload)
            -> Net::awaitable<Preview::Contract::Io::PacketTransferResult>
        {
            if (!NextLayer_)
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, 0, {Preview::Fault::Code::IoError}};
            }

            std::array<std::uint8_t, 2> Length{};
            const auto Header = co_await ReadExact(std::span<std::uint8_t>(Length));
            if (!Header)
            {
                auto Failure = Header.error();
                if (Failure.Cause.Code == Preview::Fault::Code::Eof &&
                    Failure.Transferred > 0U)
                {
                    Failure.Cause.Code = Preview::Fault::Code::BadMessage;
                }
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, Failure.Transferred, std::move(Failure.Cause)};
            }

            const auto Size = (static_cast<std::size_t>(Length[0]) << 8U) | Length[1];
            RxWire_.clear();
            RxWire_.reserve(Size + Length.size());
            RxWire_.insert(RxWire_.end(), Length.begin(), Length.end());
            RxWire_.resize(Size + Length.size());
            if (Size != 0U)
            {
                const auto Body = co_await ReadExact(
                    std::span<std::uint8_t>(RxWire_).subspan(Length.size()));
                if (!Body)
                {
                    auto Failure = Body.error();
                    if (Failure.Cause.Code == Preview::Fault::Code::Eof)
                        Failure.Cause.Code = Preview::Fault::Code::BadMessage;
                    co_return Preview::Contract::Io::PacketTransferResult{
                        0, Length.size() + Failure.Transferred,
                        std::move(Failure.Cause)};
                }
            }

            std::span<const std::uint8_t> View;
            const auto Parsed = ParseUdpPkt(
                std::span<const std::uint8_t>(RxWire_.data(), RxWire_.size()), View);
            if (!Parsed)
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, RxWire_.size(), Parsed.error().Cause};
            }
            Payload.assign(View.begin(), View.end());
            co_return Preview::Contract::Io::PacketTransferResult{
                Payload.size(), RxWire_.size(), {}};
        }

        /** @brief 透传原始流读取。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(
                    Executor(), std::move(Handler),
                    Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            NextLayer_->ReadSome(Buffer, std::move(Handler));
        }

        /** @brief 透传原始流写入。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(
                    Executor(), std::move(Handler),
                    Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteSome(Buffer, std::move(Handler));
        }

        /** @brief 透传真实写半关闭。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(
                    Executor(), std::move(Handler),
                    Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return NextLayer_ ? NextLayer_->Close() : ControlResult{};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return NextLayer_ ? NextLayer_->Cancel() : ControlResult{};
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return std::move(NextLayer_);
        }

        [[nodiscard]] auto Stream() const noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

    private:
        [[nodiscard]] auto ReadExact(const std::span<std::uint8_t> Buffer)
            -> Net::awaitable<UdpResult>
        {
            std::size_t Read = 0;
            while (Read < Buffer.size())
            {
                if (!NextLayer_)
                {
                    co_return std::unexpected(UdpFailure{
                        {Preview::Fault::Code::IoError}, Read});
                }
                const auto Part = co_await NextLayer_->ReadSome(
                    AsBytes(Buffer.subspan(Read)));
                const auto Remaining = Buffer.size() - Read;
                if (Part.Bytes > Remaining)
                {
                    co_return std::unexpected(UdpFailure{
                        {Preview::Fault::Code::InvalidArgument, Part.Failure.Native}, Read});
                }
                Read += Part.Bytes;
                if (Part.Failure.Failed())
                {
                    co_return std::unexpected(UdpFailure{Part.Failure, Read});
                }
                if (Part.Bytes == 0U)
                {
                    co_return std::unexpected(UdpFailure{
                        {Read == 0U ? Preview::Fault::Code::Eof
                                    : Preview::Fault::Code::BadMessage}, Read});
                }
            }
            co_return UdpResult{};
        }

        SharedTransmission NextLayer_;
        Memory Mem_;
        typename Memory::template Buffer<std::uint8_t> TxWire_{Mem_.Arena()};
        typename Memory::template Buffer<std::uint8_t> RxWire_{Mem_.Arena()};
    };

    using SharedDgram = std::shared_ptr<Dgram<>>;
} // namespace Preview::Vless
