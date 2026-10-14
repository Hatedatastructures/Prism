/**
 * @file ConnStream.hpp
 * @brief WebSocket 裸流读写与 partial I/O owner。
 * @details ConnStream 将完整 WebSocket 消息暴露为 Transmission 风格的
 *          partial read/write，并负责保存用户缓冲区无法一次消费的载荷。
 * @note 实例非线程安全，应在同一协程或线程内使用。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <span>
#include <system_error>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Ws/Detail/ConnClose.hpp>
#include <Preview/Protocols/Ws/Detail/ConnFrame.hpp>
#include <Preview/Protocols/Ws/Detail/ConnSession.hpp>

namespace Preview::Ws::Detail
{

    namespace Net = boost::asio;

    /**
     * @class ConnStream
     * @brief WebSocket 应用数据流 owner。
     * @tparam Memory 会话内存策略。
     */
    template <Preview::Memory::Restrict Memory>
    class ConnStream final
    {
    public:
        ConnStream(
            ConnSession<Memory> &Session,
            ConnFrame<Memory> &Frame,
            ConnClose<Memory> &Close)
            : Session_(Session),
              Frame_(Frame),
              Close_(Close)
        {
        }

        ConnStream(const ConnStream &) = delete;
        auto operator=(const ConnStream &) -> ConnStream & = delete;

        auto Reset() -> void
        {
            RxPayload_.clear();
            RxOffset_ = 0;
        }

        /** @brief 读取一部分已重组的 WebSocket 消息（内部实现，由 Conn 前门包装）。 */
        [[nodiscard]] auto ReadPartial(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
        {
            if (!Session_.HasBytes())
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            if (!Session_.IsHandshaken() || Session_.IsClosed() ||
                !Session_.HasUpstream())
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            ErrorCode.clear();
            if (Buffer.empty())
            {
                co_return 0;
            }

            while (true)
            {
                if (RxOffset_ < RxPayload_.size())
                {
                    const auto Count = (std::min)(
                        Buffer.size(), RxPayload_.size() - RxOffset_);
                    std::memcpy(
                        Buffer.data(),
                        RxPayload_.data() + RxOffset_,
                        Count);
                    RxOffset_ += Count;
                    if (RxOffset_ == RxPayload_.size())
                    {
                        RxPayload_.clear();
                        RxOffset_ = 0;
                    }
                    co_return Count;
                }

                RxPayload_.clear();
                RxOffset_ = 0;
                if (!co_await Frame_.ReadNextDataFrame(RxPayload_, ErrorCode))
                {
                    co_return 0;
                }
            }
        }

        /** @brief 将一段应用数据编码为 binary 帧并发送（内部协程实现）。 */
        [[nodiscard]] auto WritePartial(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
        {
            if (!Session_.HasBytes())
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            if (!Session_.IsHandshaken() || Session_.IsClosed() ||
                !Session_.HasUpstream())
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            ErrorCode.clear();
            if (Buffer.empty())
            {
                co_return 0;
            }
            if (Buffer.size() > ConnFrame<Memory>::MaxFramePayload)
            {
                ErrorCode = make_error_code(Error::BadLength);
                co_return 0;
            }
            if (co_await Frame_.SendFrame(
                    Opcode::Binary, Buffer, ErrorCode))
            {
                const auto CloseResult = Close_.Terminate(false);
                if (!CloseResult && !ErrorCode)
                {
                    ErrorCode = Preview::Fault::ToNative(CloseResult.error());
                }
                co_return 0;
            }
            co_return Buffer.size();
        }

    private:
        ConnSession<Memory> &Session_;
        ConnFrame<Memory> &Frame_;
        ConnClose<Memory> &Close_;
        std::vector<std::byte> RxPayload_;
        std::size_t RxOffset_{0};
    };

} // namespace Preview::Ws::Detail
