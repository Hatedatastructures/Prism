/**
 * @file ForwardRequestSource.hpp
 * @brief 首请求 framing 使用的有界预读与上游字节源 owner。
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http1/ForwardRequestFraming.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http11::Detail
{
    /**
     * @brief 拥有预读与单次上游读取缓冲，按请求 framing 顺序交付字节。
     * @details 本对象持有内部缓冲；目标 span 由外层传输借用到对应 completion 返回。
     */
    class ForwardRequestSource final
    {
    public:
        /** @brief 接管唯一内层传输与已预读字节。 */
        ForwardRequestSource(SharedTransmission Inner, std::vector<std::byte> Preread)
            : Inner_(std::move(Inner)), Preread_(std::move(Preread))
        {
        }

        /** @brief 提供同一个内层传输供状态 owner 执行写入及控制操作。 */
        [[nodiscard]] auto Inner() const noexcept -> const SharedTransmission &
        {
            return Inner_;
        }

        /** @brief 清除关闭后不再可读的预读与上游缓冲。 */
        auto Clear() noexcept -> void
        {
            Preread_.clear();
            PrereadOffset_ = 0;
            SourceOffset_ = 0;
            SourceSize_ = 0;
            SourceFailure_ = {};
        }

        /** @brief 将仍未消费的预读和单次读取残余按顺序拷入目标缓冲。 */
        auto CopyBuffered(std::span<std::byte> Buffer) -> std::size_t
        {
            std::size_t Written = 0;
            if (PrereadOffset_ < Preread_.size())
            {
                const auto Count = (std::min)(Buffer.size(), Preread_.size() - PrereadOffset_);
                std::memcpy(Buffer.data(), Preread_.data() + PrereadOffset_, Count);
                PrereadOffset_ += Count;
                Written += Count;
            }
            if (Written < Buffer.size() && SourceOffset_ < SourceSize_)
            {
                const auto Count = (std::min)(Buffer.size() - Written, SourceSize_ - SourceOffset_);
                std::memcpy(Buffer.data() + Written, SourceBuffer_.data() + SourceOffset_, Count);
                SourceOffset_ += Count;
                Written += Count;
            }
            return Written;
        }

        /** @brief 缓冲全部消费后交付同次终态；尚有字节时保持原错误供后续交付。 */
        [[nodiscard]] auto TakeTerminalFailure() noexcept -> Fault::Failure
        {
            if (PrereadOffset_ < Preread_.size() || SourceOffset_ < SourceSize_)
            {
                return {};
            }
            return std::exchange(SourceFailure_, Fault::Failure{});
        }

        /** @brief 获取一个 framing 字节，并保留关联的终态读取失败。 */
        [[nodiscard]] auto ReadRawByte(std::byte &Byte, Fault::Failure &Failure)
            -> boost::asio::awaitable<bool>
        {
            if (CopyBuffered(std::span<std::byte>(&Byte, 1)) == 1U)
            {
                co_return true;
            }
            if (SourceFailure_.Failed())
            {
                Failure = ToBodyEndFailure(SourceFailure_);
                SourceFailure_ = {};
                co_return false;
            }
            if (!co_await FillSource(Failure))
            {
                co_return false;
            }
            co_return CopyBuffered(std::span<std::byte>(&Byte, 1)) == 1U;
        }

        /** @brief 按 Content-Length 读取字节并更新剩余长度与 typed 终态。 */
        [[nodiscard]] auto ReadContentLength(std::span<std::byte> Buffer,
                                             std::uint64_t &Remaining,
                                             Fault::Failure &Failure)
            -> boost::asio::awaitable<std::size_t>
        {
            std::size_t Written = 0;
            while (Written < Buffer.size() && Remaining != 0U)
            {
                const auto Limit = (std::min)(
                    static_cast<std::uint64_t>(Buffer.size() - Written), Remaining);
                const auto CountLimit = static_cast<std::size_t>(Limit);
                const auto Buffered = CopyBuffered(Buffer.subspan(Written, CountLimit));
                if (Buffered != 0U)
                {
                    Written += Buffered;
                    Remaining -= Buffered;
                    continue;
                }
                const auto Part = co_await Inner_->ReadSome(
                    Buffer.subspan(Written, CountLimit));
                if (Part.Bytes > Limit)
                {
                    Failure = ProtocolFailure(Error::BadLength);
                    co_return Written;
                }
                if (Part.Bytes == 0U)
                {
                    auto EndFailure = Part.Failure;
                    if (EndFailure.Succeeded())
                    {
                        EndFailure = Fault::Failure{Fault::Code::WouldBlock};
                    }
                    Failure = ToBodyEndFailure(EndFailure);
                    co_return Written;
                }
                Written += Part.Bytes;
                Remaining -= Part.Bytes;
                if (Part.Failure.Failed())
                {
                    Failure = Remaining == 0U ? Part.Failure : ToBodyEndFailure(Part.Failure);
                    co_return Written;
                }
            }
            co_return Written;
        }

        /** @brief 按当前 chunk 剩余长度读取负载字节。 */
        [[nodiscard]] auto ReadChunkData(std::span<std::byte> Buffer,
                                         std::uint64_t &Remaining,
                                         Fault::Failure &Failure)
            -> boost::asio::awaitable<std::size_t>
        {
            std::size_t Written = 0;
            while (Written < Buffer.size() && Remaining != 0U)
            {
                const auto Limit = (std::min)(
                    static_cast<std::uint64_t>(Buffer.size() - Written), Remaining);
                const auto CountLimit = static_cast<std::size_t>(Limit);
                const auto Count = CopyBuffered(Buffer.subspan(Written, CountLimit));
                if (Count != 0U)
                {
                    Written += Count;
                    Remaining -= Count;
                    continue;
                }
                if (!co_await FillSource(Failure))
                {
                    co_return Written;
                }
            }
            co_return Written;
        }

    private:
        [[nodiscard]] static auto ProtocolFailure(Error Value) -> Fault::Failure
        {
            return Fault::FromNative(make_error_code(Value));
        }

        [[nodiscard]] auto FillSource(Fault::Failure &Failure)
            -> boost::asio::awaitable<bool>
        {
            if (!Inner_)
            {
                Failure = ProtocolFailure(Error::NotOpen);
                co_return false;
            }
            SourceOffset_ = 0;
            SourceSize_ = 0;
            const auto Part = co_await Inner_->ReadSome(SourceBuffer_);
            if (Part.Bytes > SourceBuffer_.size())
            {
                Failure = ProtocolFailure(Error::BadLength);
                co_return false;
            }
            if (Part.Bytes == 0U)
            {
                auto EndFailure = Part.Failure;
                if (EndFailure.Succeeded())
                {
                    EndFailure = Fault::Failure{Fault::Code::WouldBlock};
                }
                Failure = ToBodyEndFailure(EndFailure);
                co_return false;
            }
            SourceSize_ = Part.Bytes;
            SourceFailure_ = Part.Failure;
            co_return true;
        }

        SharedTransmission Inner_;
        std::vector<std::byte> Preread_;
        std::array<std::byte, 4096> SourceBuffer_{};
        std::size_t PrereadOffset_{0};
        std::size_t SourceOffset_{0};
        std::size_t SourceSize_{0};
        Fault::Failure SourceFailure_;
    };
} // namespace Prism::Http11::Detail
