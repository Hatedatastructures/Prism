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
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Contract/Io/IoResult.hpp>
#include <Preview/Protocols/Ws/Detail/ConnSession.hpp>

namespace Preview::Ws::Detail
{

    namespace Net = boost::asio;

    /**
     * @class ConnTransport
     * @brief WebSocket 底层流传输 owner。
     * @tparam Memory 会话内存策略。
     */
    template <Preview::Memory::Restrict Memory>
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
            std::span<const std::uint8_t> Data) -> Net::awaitable<Preview::IoResult>
        {
            auto Upstream = Session_.Underlying();
            if (!Upstream)
            {
                co_return Preview::IoResult{0, {Preview::Fault::Code::IoError}};
            }

            Preview::IoResult Result;
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
                            Preview::Fault::Code::InvalidArgument};
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
                    Result.Failure = {Preview::Fault::Code::WouldBlock};
                    co_return Result;
                }
            }
            co_return Result;
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

                std::error_code ReadError;
                const auto Part = co_await Upstream->ReadSome(Buffer.subspan(Done));
                ReadError = Preview::Fault::ToNative(Part.Failure);
                const auto Count = Part.Bytes;
                if (ReadError)
                {
                    ErrorCode = ReadError;
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
                if (Count > Buffer.size() - Done)
                {
                    ErrorCode = make_error_code(Error::BrokenPipe);
                    co_return false;
                }
                Done += Count;
            }
            ErrorCode.clear();
            co_return true;
        }

    private:
        ConnSession<Memory> &Session_;
        std::vector<std::byte> PendingWire_;
        std::size_t PendingOffset_{0};
    };

} // namespace Preview::Ws::Detail
