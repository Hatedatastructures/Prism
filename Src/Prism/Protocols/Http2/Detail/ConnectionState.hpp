/**
 * @file ConnectionState.hpp
 * @brief HTTP/2 连接级输入、输出和流控状态 owner。
 * @details 负责连接前导码、跨读缓冲、可从帧头判定的长度约束、待发送队列以及连接窗口；
 *          帧语义由 FrameProcessor 负责，流表和流级操作由 StreamController 负责。
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <boost/asio/any_io_executor.hpp>

#include <Prism/Protocols/Http2/Detail/Frame.hpp>

namespace Prism::Http2::Detail
{

    namespace Net = boost::asio;

    /**
     * @class ConnectionState
     * @brief 持有单条 HTTP/2 连接的传输级状态。
     * @details Feed 校验帧头可判定的载荷长度，再把完整帧交给调用方的 frame sink；
     *          stream ID、载荷字段和连接状态语义仍由 sink 负责。
     */
    class ConnectionState final
    {
    public:
        explicit ConnectionState(Net::any_io_executor Executor, bool IsServer)
            : Ex_(std::move(Executor)), IsServer_(IsServer)
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Ex_;
        }

        [[nodiscard]] auto IsServer() const noexcept -> bool
        {
            return IsServer_;
        }

        [[nodiscard]] auto ConnectionSendWindow() noexcept -> std::int64_t &
        {
            return ConnectionSendWindow_;
        }

        [[nodiscard]] auto ConnectionReceiveWindow() noexcept -> std::uint32_t &
        {
            return ConnectionReceiveWindow_;
        }

        [[nodiscard]] auto LocalMaxFrameSize() const noexcept -> std::uint32_t
        {
            return LocalMaxFrameSize_;
        }

        auto QueueFrame(const FrameParameters &Parameters) -> void;

        /**
         * @brief 解析输入缓冲并把完整帧交给 frame sink。
         * @tparam FrameSink 提供 ValidateHeaderSequence 和 Dispatch 的 owner
         */
        template <typename FrameSink>
        [[nodiscard]] auto Feed(
            std::span<const std::byte> Data,
            std::error_code &ErrorCode,
            FrameSink &Sink) -> bool
        {
            RxBuffer_.insert(RxBuffer_.end(), Data.begin(), Data.end());
            if (IsServer_ && !PrefaceChecked_)
            {
                constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
                const auto Count = (std::min)(RxBuffer_.size(), Preface.size());
                for (std::size_t Index = 0; Index < Count; ++Index)
                {
                    if (std::to_integer<char>(RxBuffer_[Index]) != Preface[Index])
                    {
                        ErrorCode = make_error_code(Error::ProtocolError);
                        return false;
                    }
                }
                if (!PrefaceChecked_)
                {
                    if (RxBuffer_.size() < Preface.size())
                    {
                        ErrorCode.clear();
                        return true;
                    }
                    RxBuffer_.erase(RxBuffer_.begin(),
                                    RxBuffer_.begin() + static_cast<std::ptrdiff_t>(Preface.size()));
                    PrefaceChecked_ = true;
                }
            }
            while (RxBuffer_.size() >= FrameHeaderSize)
            {
                const auto Header = ParseFrameHeader(
                    std::span<const std::byte>(RxBuffer_.data(), RxBuffer_.size()));
                if (!Header)
                {
                    ErrorCode = make_error_code(Error::NeedMore);
                    return false;
                }
                if (!Sink.ValidateHeaderSequence(*Header, ErrorCode))
                {
                    return false;
                }
                if (Header->Length > LocalMaxFrameSize_)
                {
                    ErrorCode = make_error_code(Error::BadLength);
                    return false;
                }
                if (!HasValidFrameLength(*Header))
                {
                    ErrorCode = make_error_code(Error::BadLength);
                    return false;
                }
                if (RxBuffer_.size() < FrameHeaderSize + Header->Length)
                {
                    break;
                }
                const auto Payload = std::span<const std::byte>(
                    RxBuffer_.data() + FrameHeaderSize, Header->Length);
                const auto Result = Sink.Dispatch(*Header, Payload, ErrorCode);
                RxBuffer_.erase(RxBuffer_.begin(),
                                RxBuffer_.begin() +
                                    static_cast<std::ptrdiff_t>(FrameHeaderSize + Header->Length));
                if (!Result)
                {
                    return false;
                }
            }
            ErrorCode.clear();
            return true;
        }

        /** @brief 把待发送帧追加到输出并按客户端协议发送连接前导码。 */
        [[nodiscard]] auto Collect(std::vector<std::byte> &Output) -> bool;

    private:
        Net::any_io_executor Ex_;
        bool IsServer_{false};
        bool PrefaceChecked_{false};
        bool PrefaceSent_{false};
        std::vector<std::byte> RxBuffer_;
        std::deque<std::vector<std::byte>> TxQueue_;
        std::int64_t ConnectionSendWindow_{DefaultInitialWindow};
        std::uint32_t ConnectionReceiveWindow_{DefaultInitialWindow};
        std::uint32_t LocalMaxFrameSize_{DefaultFramePayload};
    };

} // namespace Prism::Http2::Detail
