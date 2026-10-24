/**
 * @file ConnTransport.hpp
 * @brief WebSocket 底层 partial I/O 与握手回注 owner。
 * @details ConnTransport 将底层 Transmission 的短读/短写组合成握手、
 *          帧头和载荷使用的完整读写操作，并保存握手响应后已读出的帧字节。
 * @note 实例非线程安全，应在同一协程或线程内使用。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Protocols/Ws/Detail/ConnSession.hpp>

namespace Prism::Ws::Detail
{

    namespace Net = boost::asio;

    /**
     * @class ConnTransport
     * @brief WebSocket 底层流传输 owner。
     * @tparam Memory 会话内存策略。
     */
    template <Prism::Memory::Restrict Memory>
    class ConnTransport final
    {
    public:
        explicit ConnTransport(ConnSession<Memory> &Session)
            : Session_(Session)
        {
        }

        ConnTransport(const ConnTransport &) = delete;
        auto operator=(const ConnTransport &) -> ConnTransport & = delete;

        auto Reset() -> void
        {
            PendingWire_.clear();
            PendingOffset_ = 0;
            PendingFailure_.reset();
        }

        auto PreserveTail(const std::string &Data, std::size_t Offset) -> void
        {
            PendingWire_.clear();
            PendingOffset_ = 0;
            if (Offset >= Data.size())
            {
                return;
            }
            const auto *Begin = reinterpret_cast<const std::byte *>(Data.data() + Offset);
            PendingWire_.assign(Begin, Begin + (Data.size() - Offset));
        }

        /**
         * @brief 完整发送一段字节，并累计实际写出量及同次完整失败。
         */
        [[nodiscard]] auto SendBytes(
            std::span<const std::uint8_t> Data) -> Net::awaitable<Prism::IoResult>
        {
            auto Upstream = Session_.Underlying();
            if (!Upstream)
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }

            Prism::IoResult Result;
            while (Result.Bytes < Data.size())
            {
                const auto Part = co_await Upstream->WriteSome(
                    AsBytes(Data.subspan(Result.Bytes)));
                if (Part.Bytes > Data.size() - Result.Bytes)
                {
                    Result.Failure = Part.Failure;
                    if (!Result.Failure.Failed())
                    {
                        Result.Failure = {
                            Prism::Fault::Code::InvalidArgument};
                    }
                    co_return Result;
                }
                Result.Bytes += Part.Bytes;
                Result.Failure = Part.Failure;
                if (Result.Failure.Failed())
                {
                    co_return Result;
                }
                if (Part.Bytes == 0)
                {
                    Result.Failure = {Prism::Fault::Code::WouldBlock};
                    co_return Result;
                }
            }
            co_return Result;
        }

        /** @brief 读取一段 Upgrade 字节并将同次终态留给后续字段或帧读取。 */
        [[nodiscard]] auto ReadHandshakeChunk(std::span<std::uint8_t> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            if (Buffer.empty())
            {
                co_return Prism::IoResult{};
            }
            if (PendingOffset_ < PendingWire_.size())
            {
                const auto Count = (std::min)(
                    Buffer.size(), PendingWire_.size() - PendingOffset_);
                std::memcpy(
                    Buffer.data(), PendingWire_.data() + PendingOffset_, Count);
                PendingOffset_ += Count;
                if (PendingOffset_ == PendingWire_.size())
                {
                    PendingWire_.clear();
                    PendingOffset_ = 0;
                }
                co_return Prism::IoResult{Count, {}};
            }
            if (PendingFailure_)
            {
                co_return Prism::IoResult{0, *PendingFailure_};
            }

            auto Upstream = Session_.Underlying();
            if (!Upstream)
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }
            auto Result = co_await Upstream->ReadSome(AsBytes(Buffer));
            if (Result.Bytes > Buffer.size())
            {
                PendingFailure_ = Prism::Fault::Failure{
                    Prism::Fault::Code::InvalidArgument, Result.Failure.Native};
                co_return Prism::IoResult{0, *PendingFailure_};
            }
            if (Result.Failure.Failed())
            {
                PendingFailure_ = Result.Failure;
                if (Result.Bytes != 0U)
                {
                    Result.Failure = {};
                }
            }
            co_return Result;
        }

        [[nodiscard]] auto PendingFailure() const noexcept
            -> const std::optional<Prism::Fault::Failure> &
        {
            return PendingFailure_;
        }

        /**
         * @brief 完整读取一段字节，优先消费握手回注数据。
         * @return true 表示读取成功。
         */
        [[nodiscard]] auto ReadExact(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<bool>
        {
            auto Upstream = Session_.Underlying();
            if (!Upstream)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return false;
            }

            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                if (PendingOffset_ < PendingWire_.size())
                {
                    const auto Count = (std::min)(
                        Buffer.size() - Done,
                        PendingWire_.size() - PendingOffset_);
                    std::memcpy(
                        Buffer.data() + Done,
                        PendingWire_.data() + PendingOffset_,
                        Count);
                    PendingOffset_ += Count;
                    Done += Count;
                    if (PendingOffset_ == PendingWire_.size())
                    {
                        PendingWire_.clear();
                        PendingOffset_ = 0;
                    }
                    continue;
                }
                if (PendingFailure_)
                {
                    ErrorCode = Prism::Fault::ToNative(*PendingFailure_);
                    co_return false;
                }

                const auto Part = co_await Upstream->ReadSome(Buffer.subspan(Done));
                const auto Count = Part.Bytes;
                if (Count > Buffer.size() - Done)
                {
                    ErrorCode = make_error_code(Error::BrokenPipe);
                    co_return false;
                }
                Done += Count;
                if (Part.Failure.Failed())
                {
                    PendingFailure_ = Part.Failure;
                    if (Done == Buffer.size())
                    {
                        ErrorCode.clear();
                        co_return true;
                    }
                    ErrorCode = Prism::Fault::ToNative(Part.Failure);
                    co_return false;
                }
                if (Count == 0)
                {
                    if (Done != 0)
                    {
                        ErrorCode = make_error_code(Error::UnexpectedEof);
                    }
                    co_return false;
                }
            }
            ErrorCode.clear();
            co_return true;
        }

    private:
        ConnSession<Memory> &Session_;
        std::vector<std::byte> PendingWire_;
        std::size_t PendingOffset_{0};
        std::optional<Prism::Fault::Failure> PendingFailure_;
    };

} // namespace Prism::Ws::Detail
