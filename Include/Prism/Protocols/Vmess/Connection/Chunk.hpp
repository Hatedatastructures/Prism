/**
 * @file Chunk.hpp
 * @brief VMess 连接 chunk 数据面和 UDP 包边界 owner。
 * @details 负责 AEAD 状态、分块长度解析、明文缓冲以及流式/数据报
 *          partial I/O；握手头和底层精确读写分别由其他 owner 负责。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <system_error>
#include <vector>
#include <utility>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Contract/Io/PacketTransferResult.hpp>
#include <Prism/Protocols/Vmess/ChunkCodec.hpp>
#include <Prism/Protocols/Vmess/Connection/Io.hpp>
#include <Prism/Protocols/Vmess/Connection/Session.hpp>

namespace Prism::Vmess::detail
{

    namespace Net = boost::asio;

    /** @brief 握手完成后交给 chunk owner 的双向 AEAD 密钥材料。 */
    struct ChunkKeys final
    {
        std::array<std::uint8_t, 16> EncryptKey{};
        std::array<std::uint8_t, 16> EncryptNonce{};
        std::array<std::uint8_t, 16> DecryptKey{};
        std::array<std::uint8_t, 16> DecryptNonce{};
        std::uint8_t Options{static_cast<std::uint8_t>(Option::AuthenticatedLength)};
    };

    /**
     * @brief VMess chunk 编解码、缓冲和数据面 owner。
     * @tparam Memory 会话内存策略
     * @details 加密/解密方向分别推进自己的 Nonce；外部的短读、短写和
     *          close/cancel 通过 ConnIo 收口，避免握手 owner 复制数据面逻辑。
     */
    template <Prism::Memory::Restrict Memory>
    class ConnChunk final
    {
        using DatagramResult = Prism::Contract::Io::PacketTransferResult;

    public:
        using Session = ConnSession<Memory>;

        explicit ConnChunk(Session &SessionValue, ConnIo<Memory> &IoValue)
            : Session_(SessionValue), Io_(IoValue), RxWire_(Session_.Mem_.Arena()),
              PlainRx_(Session_.Mem_.Arena())
        {
        }

        auto Reset() -> void
        {
            Enc_.reset();
            Dec_.reset();
            ChunkOptions_ = static_cast<std::uint8_t>(Option::AuthenticatedLength);
            RxWire_.clear();
            PlainRx_.clear();
            PlainOff_ = 0;
            Eof_ = false;
            ReadFailure_.reset();
            DatagramFailure_.reset();
        }

        auto Configure(ChunkKeys Keys) -> void
        {
            Enc_.emplace(
                std::span<const std::uint8_t, 16>(Keys.EncryptKey),
                std::span<const std::uint8_t, 16>(Keys.EncryptNonce),
                Keys.Options);
            Dec_.emplace(
                std::span<const std::uint8_t, 16>(Keys.DecryptKey),
                std::span<const std::uint8_t, 16>(Keys.DecryptNonce),
                Keys.Options);
            ChunkOptions_ = Keys.Options;
        }

        [[nodiscard]] auto IsConfigured() const noexcept -> bool
        {
            return Enc_.has_value() && Dec_.has_value();
        }

        /** @brief 解密后的部分读；EOF 以正式 Code::Eof 交付，已完成字节不清零。 */
        [[nodiscard]] auto ReadSome(std::span<std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
        {
            if (!Session_.NextLayer_ || !Session_.Handshaken_ || !Dec_)
            {
                co_return Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))};
            }
            if (Eof_)
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::Eof}};
            }
            while (PlainOff_ >= PlainRx_.size())
            {
                if (ReadFailure_)
                {
                    co_return Prism::IoResult{0, *ReadFailure_};
                }
                const auto Failure = co_await ReadChunk();
                if (Failure.Failed())
                {
                    ReadFailure_ = Failure;
                    co_return Prism::IoResult{0, *ReadFailure_};
                }
                if (Eof_)
                {
                    co_return Prism::IoResult{0, {Prism::Fault::Code::Eof}};
                }
            }
            const auto Count = (std::min)(Buffer.size(), PlainRx_.size() - PlainOff_);
            std::memcpy(Buffer.data(), PlainRx_.data() + PlainOff_, Count);
            PlainOff_ += Count;
            co_return Prism::IoResult{Count, {}};
        }

        /** @brief 加密后的部分写；失败保留已真实交付字节。 */
        [[nodiscard]] auto WriteSome(std::span<const std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
        {
            if (!Session_.NextLayer_ || !Session_.Handshaken_ || !Enc_)
            {
                co_return Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))};
            }
            if (Buffer.empty())
            {
                co_return Prism::IoResult{0, {}};
            }

            std::size_t Done = 0;
            auto Output = Session_.Mem_.template MakeBuffer<std::uint8_t>(
                MaxChunkLen + ChunkEncryptor::Overhead);
            while (Done < Buffer.size())
            {
                const auto Count = (std::min)(MaxWriteChunkLen, Buffer.size() - Done);
                const auto Encoded = Enc_->Seal(
                    Prism::AsU8(Buffer.subspan(Done, Count)), Output);
                if (Encoded == 0)
                {
                    co_return Prism::IoResult{Done, Prism::Fault::FromNative(make_error_code(Error::BadLength))};
                }
                if (co_await Io_.SendBytes(
                        std::span<const std::uint8_t>(Output.data(), Encoded)))
                {
                    co_return Prism::IoResult{Done, Prism::Fault::FromNative(make_error_code(Error::IoError))};
                }
                Done += Count;
            }
            co_return Prism::IoResult{Buffer.size(), {}};
        }

        [[nodiscard]] auto AsyncSendDatagram(
            std::span<const std::uint8_t> Payload) -> Net::awaitable<DatagramResult>
        {
            if (!Session_.NextLayer_ || !Session_.Handshaken_ || !Enc_)
            {
                co_return DatagramResult{0, 0, FailureFor(Error::NotOpen)};
            }
            if (Payload.size() >
                (std::numeric_limits<std::size_t>::max)() - ChunkEncryptor::Overhead)
            {
                co_return DatagramResult{0, 0, FailureFor(Error::BadLength)};
            }
            std::vector<std::uint8_t> Output(Payload.size() + ChunkEncryptor::Overhead);
            const auto Encoded = Enc_->Seal(Payload, Output);
            if (Encoded == 0)
            {
                co_return DatagramResult{0, 0, FailureFor(Error::BadLength)};
            }
            const auto Sent = co_await Io_.SendDatagramBytes(
                std::span<const std::uint8_t>(Output.data(), Encoded));
            if (Sent.Failure.Failed())
                co_return DatagramResult{0, Sent.Bytes, Sent.Failure};
            co_return DatagramResult{Payload.size(), Sent.Bytes, {}};
        }

        [[nodiscard]] auto AsyncReceiveDatagram(
            std::vector<std::uint8_t> &Payload) -> Net::awaitable<DatagramResult>
        {
            if (DatagramFailure_)
            {
                co_return DatagramResult{0, 0, *DatagramFailure_};
            }
            if (!Session_.NextLayer_ || !Session_.Handshaken_ || !Dec_)
            {
                co_return DatagramResult{0, 0, FailureFor(Error::NotOpen)};
            }
            if (Eof_)
            {
                co_return DatagramResult{
                    0, 0, Prism::Fault::Failure{Prism::Fault::Code::Eof}};
            }
            const bool AuthenticatedLength =
                HasOption(ChunkOptions_, Option::AuthenticatedLength);
            const auto LengthHeaderSize = AuthenticatedLength ? std::size_t{18} : std::size_t{2};
            std::array<std::uint8_t, 18> Header{};
            bool FrameStarted = false;
            const auto HeaderRead = co_await Io_.ReadDatagramBytes(
                std::span<std::uint8_t>(Header).first(LengthHeaderSize), FrameStarted);
            if (HeaderRead.Failure.Failed() &&
                HeaderRead.Bytes != LengthHeaderSize)
            {
                auto Failure = HeaderRead.Failure;
                if (Failure.Code == Prism::Fault::Code::Eof)
                {
                    if (HeaderRead.Bytes == 0U) Eof_ = true;
                    else Failure.Code = Prism::Fault::Code::BadMessage;
                }
                if (!Eof_ && !IsTransientDatagramFailure(Failure))
                    DatagramFailure_ = Failure;
                co_return DatagramResult{0, HeaderRead.Bytes, std::move(Failure)};
            }
            if (HeaderRead.Bytes != LengthHeaderSize)
            {
                DatagramFailure_ = Prism::Fault::Failure{Prism::Fault::Code::BadMessage};
                co_return DatagramResult{
                    0, HeaderRead.Bytes,
                    *DatagramFailure_};
            }
            auto Length = Dec_->OpenLen(
                std::span<const std::uint8_t>(Header).first(LengthHeaderSize));
            if (!Length)
            {
                const auto Failure = FailureFor(Length.error());
                DatagramFailure_ = Failure;
                co_return DatagramResult{
                    0, HeaderRead.Bytes, Failure};
            }
            const bool EndMarker = AuthenticatedLength
                ? *Length == AuthenticatedLengthEofMarker
                : *Length == 0U;
            if (EndMarker)
            {
                if (const auto &Terminal = Io_.ReadTerminal())
                {
                    if (Terminal->Code == Prism::Fault::Code::Eof)
                    {
                        Eof_ = true;
                    }
                    else if (!IsTransientDatagramFailure(*Terminal))
                    {
                        DatagramFailure_ = *Terminal;
                    }
                    co_return DatagramResult{
                        0, HeaderRead.Bytes, *Terminal};
                }
                Eof_ = true;
                co_return DatagramResult{
                    0, HeaderRead.Bytes,
                    Prism::Fault::Failure{Prism::Fault::Code::Eof}};
            }
            auto EncodedLength = *Length;
            if (AuthenticatedLength) EncodedLength += 16;
            if (EncodedLength < 16)
            {
                DatagramFailure_ = FailureFor(Error::BadLength);
                co_return DatagramResult{
                    0, HeaderRead.Bytes, *DatagramFailure_};
            }
            const auto PlainLength = EncodedLength - 16;
            RxWire_.resize(EncodedLength);
            const auto BodyRead = co_await Io_.ReadDatagramBytes(RxWire_, FrameStarted);
            const auto WireBytes = HeaderRead.Bytes + BodyRead.Bytes;
            if (BodyRead.Failure.Failed() &&
                BodyRead.Bytes != EncodedLength)
            {
                auto Failure = BodyRead.Failure;
                if (Failure.Code == Prism::Fault::Code::Eof && FrameStarted)
                    Failure.Code = Prism::Fault::Code::BadMessage;
                if (!IsTransientDatagramFailure(Failure)) DatagramFailure_ = Failure;
                co_return DatagramResult{0, WireBytes, std::move(Failure)};
            }
            if (BodyRead.Bytes != EncodedLength)
            {
                DatagramFailure_ = Prism::Fault::Failure{Prism::Fault::Code::BadMessage};
                co_return DatagramResult{
                    0, WireBytes, *DatagramFailure_};
            }
            PlainRx_.resize(PlainLength);
            const auto DecodeError = Dec_->OpenPayload(
                std::span<const std::uint8_t>(RxWire_.data(), RxWire_.size()),
                std::span<std::uint8_t>(PlainRx_.data(), PlainRx_.size()));
            if (DecodeError != Error::None)
            {
                DatagramFailure_ = FailureFor(DecodeError);
                co_return DatagramResult{
                    0, WireBytes, *DatagramFailure_};
            }
            Payload.assign(PlainRx_.begin(), PlainRx_.end());
            PlainOff_ = 0;
            co_return DatagramResult{Payload.size(), WireBytes, {}};
        }

    private:
        /** @brief 为 16 字节 AEAD tag 留出空间，限制单个 stream 密文块至 16 KiB。 */
        static constexpr std::size_t MaxWriteChunkLen = MaxChunkLen - 16U;

        [[nodiscard]] static auto IsTransientDatagramFailure(
            const Prism::Fault::Failure &Failure) noexcept -> bool
        {
            using Code = Prism::Fault::Code;
            return Failure.Code == Code::WouldBlock || Failure.Code == Code::Timeout ||
                Failure.Code == Code::Canceled;
        }

        [[nodiscard]] static auto FailureFor(Error Value) noexcept
            -> Prism::Fault::Failure
        {
            return {Prism::Fault::ToCode(Prism::make_error_code(Value))};
        }

        [[nodiscard]] auto ReadChunk() -> Net::awaitable<Prism::Fault::Failure>
        {
            const bool AuthenticatedLength =
                HasOption(ChunkOptions_, Option::AuthenticatedLength);
            const auto LengthHeaderSize = AuthenticatedLength ? std::size_t{18} : std::size_t{2};

            std::array<std::uint8_t, 18> Header{};
            const auto HeaderRead = co_await Io_.ReadExactIo(
                std::span<std::uint8_t>(Header).first(LengthHeaderSize));
            if (HeaderRead.Failure.Failed() &&
                HeaderRead.Bytes != LengthHeaderSize)
            {
                if (HeaderRead.Failure.Code == Prism::Fault::Code::Eof &&
                    HeaderRead.Bytes == 0U && Session_.ServerSide_)
                {
                    Eof_ = true;
                    co_return Prism::Fault::Failure{};
                }
                if (HeaderRead.Failure.Code == Prism::Fault::Code::Eof)
                {
                    co_return FailureFor(Error::UnexpectedEof);
                }
                co_return HeaderRead.Failure;
            }
            if (HeaderRead.Bytes != LengthHeaderSize)
            {
                co_return FailureFor(Error::UnexpectedEof);
            }

            auto Length = Dec_->OpenLen(
                std::span<const std::uint8_t>(Header).first(LengthHeaderSize));
            if (!Length)
            {
                co_return FailureFor(Length.error());
            }
            const bool EndMarker = AuthenticatedLength
                ? *Length == AuthenticatedLengthEofMarker
                : *Length == 0U;
            if (EndMarker)
            {
                if (const auto &Terminal = Io_.ReadTerminal())
                {
                    if (Terminal->Code == Prism::Fault::Code::Eof &&
                        Session_.ServerSide_)
                    {
                        Eof_ = true;
                    }
                    co_return *Terminal;
                }
                Eof_ = true;
                co_return Prism::Fault::Failure{};
            }

            auto EncodedLength = *Length;
            if (AuthenticatedLength)
            {
                EncodedLength += 16;
            }
            if (EncodedLength < 16)
            {
                co_return FailureFor(Error::BadLength);
            }
            const auto PlainLength = EncodedLength - 16;
            RxWire_.resize(EncodedLength);
            const auto PayloadRead = co_await Io_.ReadExactIo(RxWire_);
            if (PayloadRead.Failure.Failed() &&
                PayloadRead.Bytes != RxWire_.size())
            {
                if (PayloadRead.Failure.Code == Prism::Fault::Code::Eof)
                {
                    co_return FailureFor(Error::UnexpectedEof);
                }
                co_return PayloadRead.Failure;
            }
            if (PayloadRead.Bytes != RxWire_.size())
            {
                co_return FailureFor(Error::UnexpectedEof);
            }
            PlainRx_.resize(PlainLength);
            const auto DecodeError = Dec_->OpenPayload(
                std::span<const std::uint8_t>(RxWire_.data(), RxWire_.size()),
                std::span<std::uint8_t>(PlainRx_.data(), PlainRx_.size()));
            if (DecodeError != Error::None)
            {
                co_return FailureFor(DecodeError);
            }
            PlainOff_ = 0;
            co_return Prism::Fault::Failure{};
        }

        Session &Session_;
        ConnIo<Memory> &Io_;
        std::optional<ChunkEncryptor> Enc_{};
        std::optional<ChunkDecryptor> Dec_{};
        std::uint8_t ChunkOptions_{static_cast<std::uint8_t>(Option::AuthenticatedLength)};
        typename Memory::template Buffer<std::uint8_t> RxWire_;
        typename Memory::template Buffer<std::uint8_t> PlainRx_;
        std::size_t PlainOff_{0};
        bool Eof_{false};
        std::optional<Prism::Fault::Failure> ReadFailure_{};
        std::optional<Prism::Fault::Failure> DatagramFailure_{}; ///< 首个不可恢复数据报帧失败。
    };

} // namespace Prism::Vmess::detail
