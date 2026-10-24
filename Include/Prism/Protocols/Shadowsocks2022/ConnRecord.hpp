/**
 * @file ConnRecord.hpp
 * @brief Shadowsocks 2022 流 record 编解码与 partial I/O owner。
 * @details 负责 chunk AEAD、Nonce 衔接、明文缓冲、精确读写和 EOF 状态。
 *          握手和 UDP owner 通过有限的 Raw I/O 接口复用底层连接。
 */
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <tuple>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Protocols/Shadowsocks2022/ChunkCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/ConnSession.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Shadowsocks2022::detail
{

    namespace Net = boost::asio;
    namespace ss = Prism::Shadowsocks2022;

    /**
     * @brief SS2022 流 record owner。
     * @tparam Memory 会话内存策略
     * @details 发送侧每个 chunk 消耗长度和载荷两个 Nonce，接收侧在完整
     *          读取后才推进状态；底层 short read/partial write 均在此收口。
     */
    template <Prism::Memory::Restrict Memory>
    class ConnRecord final
    {
    public:
        using Session = ConnSession<Memory>;
        using Completion = Prism::Transmission::Completion;

        explicit ConnRecord(Session &SessionValue) : Session_(SessionValue)
        {
        }

        auto ConfigureEncoder(ChunkCodec Codec) -> void
        {
            Encoder_.emplace(std::move(Codec));
        }

        auto ConfigureDecoder(ChunkCodec Codec) -> void
        {
            Decoder_.emplace(std::move(Codec));
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Session_.Executor();
        }

        /** @brief 部分读取：先补齐并解密一个 chunk，再交付缓冲中的明文。 */
        [[nodiscard]] auto ReadSome(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            Prism::Fault::Failure Failure;
            const auto Count = co_await ReadPartial(Buffer, Failure);
            co_return Prism::IoResult{Count, Failure};
        }

        /** @brief token 形式：经 co_composed 恰好交付一次结果，不复制 buffer。 */
        auto ReadSome(std::span<std::byte> Buffer, Completion Handler) -> void
        {
            Initiate<ReadWork>(std::move(Handler), Buffer);
        }

        /** @brief 按 chunk 加密并完整发送；一旦密文提交失败，本方向保留首因并拒绝续写，避免跳过 nonce。 */
        [[nodiscard]] auto WriteSome(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            Prism::Fault::Failure Failure;
            const auto Count = co_await WritePartial(Buffer, Failure);
            co_return Prism::IoResult{Count, Failure};
        }

        /** @brief token 形式：经 co_composed 恰好交付一次结果，不复制 buffer。 */
        auto WriteSome(std::span<const std::byte> Buffer, Completion Handler) -> void
        {
            Initiate<WriteWork>(std::move(Handler), Buffer);
        }

        /** @brief 真实写半关闭转交底层载体；反向读取仍然可用。 */
        auto WriteShutdown(Completion Handler) -> void
        {
            if (!Session_.NextLayer_)
            {
                Prism::Transmission::PostResult(
                    Executor(),
                    std::move(Handler),
                    Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            Session_.NextLayer_->WriteShutdown(std::move(Handler));
        }

        /** @brief 封止并交付底层关闭；实际退出由底层 Activity()->Drain() 另行等待。 */
        [[nodiscard]] auto Close() -> Prism::Transmission::ControlResult
        {
            return Session_.Close();
        }

        /** @brief 可重复取消底层挂起操作；成功只表示命令已接管。 */
        [[nodiscard]] auto Cancel() -> Prism::Transmission::ControlResult
        {
            return Session_.Cancel();
        }

        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            const auto Result = co_await ReceiveExactStatus(Buffer);
            if (!Result)
            {
                co_return Prism::IoResult{Result.error().Consumed, Result.error().Cause};
            }
            if (*Result != ExactReadStatus::Complete)
            {
                co_return Prism::IoResult{
                    0, Prism::Fault::Failure{Prism::Fault::Code::Eof}};
            }
            co_return Prism::IoResult{Buffer.size(), {}};
        }

        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const
            -> Net::awaitable<Prism::Fault::Failure>
        {
            if (!Session_.NextLayer_)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::IoError};
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                const auto Part = co_await Session_.NextLayer_->WriteSome(
                    Prism::AsBytes(Data.subspan(Done)));
                const auto Count = Part.Bytes;
                if (Count > Data.size() - Done)
                {
                    co_return Prism::Fault::Failure{
                        Prism::Fault::Code::InvalidArgument, Part.Failure.Native};
                }
                if (Part.Failure.Failed())
                    co_return Part.Failure;
                if (Count == 0)
                    co_return Prism::Fault::Failure{Prism::Fault::Code::IoError};
                Done += Count;
            }
            co_return Prism::Fault::Failure{};
        }

    private:
        /** @brief 原协程体：握手与解码器判定、chunk 解密，EOF 显式以 Eof 交付。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer,
                                       Prism::Fault::Failure &Failure)
            -> Net::awaitable<std::size_t>
        {
            if (!Session_.Handshaken_)
            {
                Failure = WireFailure(Error::NotOpen);
                co_return 0;
            }
            if (!Decoder_)
            {
                Failure = WireFailure(Error::NotOpen);
                co_return 0;
            }
            while (Session_.PlainOff_ >= Session_.PlainRx_.size())
            {
                if (ReadFailure_)
                {
                    Failure = *ReadFailure_;
                    co_return 0;
                }
                if (Session_.Eof_)
                {
                    Failure = Prism::Fault::Failure{Prism::Fault::Code::Eof};
                    co_return 0;
                }
                Failure = co_await ReadChunk();
                if (Failure.Failed())
                {
                    co_return 0;
                }
                if (Session_.Eof_)
                {
                    Failure = Prism::Fault::Failure{Prism::Fault::Code::Eof};
                    co_return 0;
                }
            }
            const auto Count = (std::min)(Buffer.size(),
                                          Session_.PlainRx_.size() - Session_.PlainOff_);
            std::memcpy(Buffer.data(), Session_.PlainRx_.data() + Session_.PlainOff_, Count);
            Session_.PlainOff_ += Count;
            Failure = {};
            co_return Count;
        }

        /** @brief 原协程体：按 chunk 加密并完整发送，保留长度判定与协议失败码。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer,
                                        Prism::Fault::Failure &Failure)
            -> Net::awaitable<std::size_t>
        {
            if (!Session_.Handshaken_)
            {
                Failure = WireFailure(Error::NotOpen);
                co_return 0;
            }
            if (Buffer.empty())
            {
                Failure = {};
                co_return 0;
            }
            if (!Encoder_)
            {
                Failure = WireFailure(Error::NotOpen);
                co_return 0;
            }
            if (WriteFailure_)
            {
                Failure = *WriteFailure_;
                co_return 0;
            }

            std::size_t Done = 0;
            auto Output = Session_.Mem_.template MakeBuffer<std::uint8_t>(
                ss::MaxChunkSize + 2 * ss::AeadTagLen + 2);
            while (Done < Buffer.size())
            {
                const auto Count = (std::min)(static_cast<std::size_t>(ss::MaxChunkSize),
                                              Buffer.size() - Done);
                const auto Encoded = Encoder_->Seal(Prism::AsU8(Buffer.subspan(Done, Count)), Output);
                if (Encoded == 0)
                {
                    Failure = WireFailure(Error::BadLength);
                    co_return 0;
                }
                const auto SendFailure = co_await SendBytes(
                    std::span<const std::uint8_t>(Output.data(), Encoded));
                if (SendFailure.Failed())
                {
                    WriteFailure_ = SendFailure;
                    Failure = SendFailure;
                    co_return 0;
                }
                Done += Count;
            }
            Failure = {};
            co_return Buffer.size();
        }

        struct ReadWork final
        {
            ConnRecord *Owner;
            template<class State>
            auto operator()(State Operation, std::span<std::byte> Buffer) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                co_return std::tuple{co_await Net::co_spawn(
                    Owner->Executor(), Owner->ReadSome(Buffer), Net::deferred)};
            }
        };
        struct WriteWork final
        {
            ConnRecord *Owner;
            template<class State>
            auto operator()(State Operation, std::span<const std::byte> Buffer) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                co_return std::tuple{co_await Net::co_spawn(
                    Owner->Executor(), Owner->WriteSome(Buffer), Net::deferred)};
            }
        };
        template<class Work, class... Input>
        auto Initiate(Completion Handler, Input... Values) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{this}, Executor()), Handler, Values...);
        }

        enum class ExactReadStatus : std::uint8_t
        {
            Complete,
            CleanEof,
        };
        struct ExactReadFailure final
        {
            Prism::Fault::Failure Cause;
            std::size_t Consumed{0};
        };

        [[nodiscard]] static auto WireFailure(const Error Value) noexcept
            -> Prism::Fault::Failure
        {
            return {Prism::Fault::Detail::MapProtocolCategoryValue(static_cast<int>(Value)), {}};
        }

        [[nodiscard]] static auto TruncatedFailure(
            Prism::Fault::Failure Cause) noexcept -> Prism::Fault::Failure
        {
            auto Failure = WireFailure(Error::UnexpectedEof);
            Failure.Native = Cause.Native;
            return Failure;
        }

        [[nodiscard]] auto ReadChunk() -> Net::awaitable<Prism::Fault::Failure>
        {
            std::array<std::uint8_t, ss::LenBlockSize> Header{};
            const auto HeaderResult = co_await ReceiveExactStatus(
                std::span<std::uint8_t>(Header));
            if (!HeaderResult)
            {
                auto Cause = HeaderResult.error().Cause;
                if (Cause.Code == Prism::Fault::Code::Eof &&
                    HeaderResult.error().Consumed != 0U)
                {
                    Cause = TruncatedFailure(Cause);
                }
                if (!ReadFailure_)
                {
                    ReadFailure_ = Cause;
                }
                else if (ReadFailure_->Code == Prism::Fault::Code::Eof &&
                         Cause.Code != Prism::Fault::Code::Eof)
                {
                    ReadFailure_ = Cause;
                }
                co_return *ReadFailure_;
            }
            if (*HeaderResult == ExactReadStatus::CleanEof)
            {
                Session_.Eof_ = true;
                co_return Prism::Fault::Failure{};
            }

            const auto Length = Decoder_->OpenLen(Header);
            if (!Length)
            {
                if (!ReadFailure_)
                {
                    ReadFailure_ = WireFailure(Error::BadAuth);
                }
                co_return *ReadFailure_;
            }
            if (*Length == 0)
            {
                Session_.Eof_ = true;
                co_return Prism::Fault::Failure{};
            }

            auto Encoded = Session_.Mem_.template MakeBuffer<std::uint8_t>(
                *Length + ss::AeadTagLen);
            const auto PayloadResult = co_await ReceiveExactStatus(Encoded);
            if (!PayloadResult)
            {
                auto Cause = PayloadResult.error().Cause;
                if (Cause.Code == Prism::Fault::Code::Eof)
                {
                    Cause = TruncatedFailure(Cause);
                }
                if (!ReadFailure_)
                {
                    ReadFailure_ = Cause;
                }
                else if (ReadFailure_->Code == Prism::Fault::Code::Eof &&
                         Cause.Code != Prism::Fault::Code::Eof)
                {
                    ReadFailure_ = Cause;
                }
                co_return *ReadFailure_;
            }
            if (*PayloadResult != ExactReadStatus::Complete)
            {
                ReadFailure_ = WireFailure(Error::UnexpectedEof);
                co_return *ReadFailure_;
            }
            Session_.PlainRx_.resize(*Length);
            if (Decoder_->OpenPayload(Encoded, Session_.PlainRx_) == 0)
            {
                if (!ReadFailure_)
                {
                    ReadFailure_ = WireFailure(Error::BadAuth);
                }
                co_return *ReadFailure_;
            }
            Session_.PlainOff_ = 0;
            co_return Prism::Fault::Failure{};
        }

        [[nodiscard]] auto ReceiveExactStatus(std::span<std::uint8_t> Buffer)
            -> Net::awaitable<std::expected<ExactReadStatus, ExactReadFailure>>
        {
            if (!Session_.NextLayer_)
            {
                co_return std::unexpected(ExactReadFailure{WireFailure(Error::NotOpen), 0});
            }
            if (ReadFailure_)
            {
                co_return std::unexpected(ExactReadFailure{*ReadFailure_, 0});
            }
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                const auto Part = co_await Session_.NextLayer_->ReadSome(
                    Prism::AsBytes(Buffer.subspan(Done)));
                const auto Count = Part.Bytes;
                if (Count > Buffer.size() - Done)
                {
                    co_return std::unexpected(ExactReadFailure{
                        Prism::Fault::Failure{
                            Prism::Fault::Code::InvalidArgument, Part.Failure.Native}, Done});
                }
                if (Count == 0)
                {
                    if (Done == 0 && (!Part.Failure.Failed() ||
                                      (Part.Failure.Code == Prism::Fault::Code::Eof &&
                                       !Part.Failure.Native)))
                    {
                        co_return ExactReadStatus::CleanEof;
                    }
                    if (Part.Failure.Failed())
                        co_return std::unexpected(ExactReadFailure{Part.Failure, Done});
                    co_return std::unexpected(ExactReadFailure{
                        WireFailure(Error::UnexpectedEof), Done});
                }
                Done += Count;
                if (Part.Failure.Failed())
                {
                    if (Done == Buffer.size())
                    {
                        ReadFailure_ = Part.Failure;
                        co_return ExactReadStatus::Complete;
                    }
                    co_return std::unexpected(ExactReadFailure{Part.Failure, Done});
                }
            }
            co_return ExactReadStatus::Complete;
        }

        Session &Session_;
        std::optional<ChunkCodec> Encoder_{};
        std::optional<ChunkCodec> Decoder_{};
        std::optional<Prism::Fault::Failure> ReadFailure_{};
        std::optional<Prism::Fault::Failure> WriteFailure_{};
    };

} // namespace Prism::Shadowsocks2022::detail
