/**
 * @file Source.cpp
 * @brief HTTP/1.1 body framing 上游有界字节源实现。
 */
#include <Prism/Protocols/Http1/Forward/Request/Detail/Source.hpp>

#include <algorithm>
#include <cstring>
#include <utility>

namespace Prism::Http11::Detail
{

    auto ForwardRequestSource::CopyBuffered(const std::span<std::byte> Buffer) -> std::size_t
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

    auto ForwardRequestSource::TakeTerminalFailure() noexcept -> Fault::Failure
    {
        if (PrereadOffset_ < Preread_.size() || SourceOffset_ < SourceSize_)
        {
            return {};
        }
        return std::exchange(SourceFailure_, Fault::Failure{});
    }

    auto ForwardRequestSource::ReadRawByte(
        std::byte &Byte,
        Fault::Failure &Failure) -> boost::asio::awaitable<bool>
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

    auto ForwardRequestSource::ReadContentLength(
        const std::span<std::byte> Buffer,
        std::uint64_t &Remaining,
        Fault::Failure &Failure) -> boost::asio::awaitable<std::size_t>
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
                const auto Terminal = TakeTerminalFailure();
                if (Terminal.Failed())
                {
                    Failure = Remaining == 0U ? Terminal : ToBodyEndFailure(Terminal);
                    co_return Written;
                }
                continue;
            }
            const auto Terminal = TakeTerminalFailure();
            if (Terminal.Failed())
            {
                Failure = ToBodyEndFailure(Terminal);
                co_return Written;
            }
            const auto Part = co_await Inner_->ReadSome(Buffer.subspan(Written, CountLimit));
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

    auto ForwardRequestSource::ReadChunkData(
        const std::span<std::byte> Buffer,
        std::uint64_t &Remaining,
        Fault::Failure &Failure) -> boost::asio::awaitable<std::size_t>
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
                const auto Terminal = TakeTerminalFailure();
                if (Terminal.Failed())
                {
                    Failure = ToBodyEndFailure(Terminal);
                    co_return Written;
                }
                continue;
            }
            const auto Terminal = TakeTerminalFailure();
            if (Terminal.Failed())
            {
                Failure = ToBodyEndFailure(Terminal);
                co_return Written;
            }
            if (!co_await FillSource(Failure))
            {
                co_return Written;
            }
        }
        co_return Written;
    }

    auto ForwardRequestSource::ProtocolFailure(const Error Value) -> Fault::Failure
    {
        return Fault::FromNative(make_error_code(Value));
    }

    auto ForwardRequestSource::FillSource(Fault::Failure &Failure)
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

} // namespace Prism::Http11::Detail
