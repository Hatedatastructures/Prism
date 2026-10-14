/**
 * @file ForwardRequestState.hpp
 * @brief HTTP/1.1 首请求 framing、Upgrade 门控与半关闭状态 owner。
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Http1/ForwardRequest.hpp>
#include <Preview/Protocols/Http1/ForwardRequestFraming.hpp>
#include <Preview/Protocols/Http1/ForwardRequestSource.hpp>
#include <Preview/Protocols/Http1/ForwardRequestUpgrade.hpp>
#include <Preview/Protocols/Http1/Parser.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Http11::Detail
{
    using IoFailure = Preview::Fault::Failure;

    /**
     * @brief 独占保存首请求 body framing、Upgrade gate 与终态失败的状态 owner。
     * @details 外层 Transmission 持有本对象直到活动读写 completion 返回；本对象只借用输入 span。
     */
    class ForwardRequestState final
    {
    public:
        explicit ForwardRequestState(ForwardRequestOptions Options)
            : Source_(std::move(Options.Inner), std::move(Options.Preread)),
              Remaining_(Options.ContentLength),
              BodyMode_(Options.BodyMode),
              AwaitUpgrade_(Options.AwaitUpgrade),
              Upgrade_(Source_.Inner()->Executor())
        {
            Header_.assign(reinterpret_cast<const std::byte *>(Options.Header.data()),
                           reinterpret_cast<const std::byte *>(Options.Header.data()) +
                               Options.Header.size());
        }

        /** @brief 返回内层传输的真实执行器。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Source_.Inner()->Executor();
        }

        /** @brief 返回共享持有的内层传输导航视图。 */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission *
        {
            return Source_.Inner().get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission *
        {
            return Source_.Inner().get();
        }

        /** @brief 真实写半关闭：先提交 Upgrade 半关闭事实，再转交底层载体。 */
        auto StartWriteShutdown(Preview::Transmission::Completion Handler) -> void
        {
            if (AwaitUpgrade_ && Upgrade_.Awaiting() && Failure_.Succeeded())
            {
                Upgrade_.Shutdown();
                Failure_ = Upgrade_.Failure();
            }
            if (!Source_.Inner())
            {
                Preview::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Preview::IoResult{0, Preview::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            Source_.Inner()->WriteShutdown(std::move(Handler));
        }

        /** @brief 清除本地转发状态并交付底层关闭。 */
        [[nodiscard]] auto Close() -> Preview::Transmission::ControlResult
        {
            Closed_ = true;
            Upgrade_.Close();
            Header_.clear();
            Source_.Clear();
            if (!Source_.Inner())
            {
                return {};
            }
            return Source_.Inner()->Close();
        }

        /** @brief 记录取消事实并取消底层挂起操作；不宣称已经关闭。 */
        [[nodiscard]] auto Cancel() -> Preview::Transmission::ControlResult
        {
            if (Failure_.Succeeded())
            {
                Failure_ = Preview::Fault::FromNative(
                    std::make_error_code(std::errc::operation_canceled));
            }
            (void)Upgrade_.Cancel();
            if (!Source_.Inner())
            {
                return {};
            }
            return Source_.Inner()->Cancel();
        }

        /** @brief 数据面部分读取实现，由正式前门复用。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            if (Buffer.empty())
            {
                co_return Preview::IoResult{0, {}};
            }
            if (Closed_)
            {
                if (Failure_.Failed())
                {
                    co_return Preview::IoResult{0, Failure_};
                }
                co_return Preview::IoResult{0, IoFailure{Preview::Fault::Code::Eof}};
            }
            if (Failure_.Failed())
            {
                co_return Preview::IoResult{0, Failure_};
            }
            auto Written = CopyHeader(Buffer);
            if (Written == Buffer.size())
            {
                co_return Preview::IoResult{Written, {}};
            }
            if (BodyMode_ == ForwardBodyMode::ContentLength)
            {
                IoFailure Failure;
                Written += co_await Source_.ReadContentLength(
                    Buffer.subspan(Written), Remaining_, Failure);
                if (Failure.Failed())
                {
                    Fail(Failure, Failure);
                }
                if (Failure_.Failed() && Failure.Succeeded())
                {
                    Failure = Failure_;
                }
                if (Failure.Failed() || Written != 0U || Remaining_ != 0U)
                {
                    co_return Preview::IoResult{Written, Failure};
                }
                const auto Count = co_await ReadAfterBody(Buffer, Failure);
                if (Failure_.Failed() && Failure.Succeeded())
                {
                    Failure = Failure_;
                }
                co_return Preview::IoResult{Count, Failure};
            }
            if (BodyMode_ == ForwardBodyMode::Chunked)
            {
                IoFailure Failure;
                Written += co_await ReadChunked(Buffer.subspan(Written), Failure);
                if (Failure_.Failed() && Failure.Succeeded())
                {
                    Failure = Failure_;
                }
                if (Failure.Failed() || Written != 0U || ChunkState_ != ChunkState::Done)
                {
                    co_return Preview::IoResult{Written, Failure};
                }
                const auto Count = co_await ReadAfterBody(Buffer, Failure);
                if (Failure_.Failed() && Failure.Succeeded())
                {
                    Failure = Failure_;
                }
                co_return Preview::IoResult{Count, Failure};
            }
            if (BodyMode_ == ForwardBodyMode::None)
            {
                if (Written != 0U)
                {
                    co_return Preview::IoResult{Written, {}};
                }
                IoFailure Failure;
                const auto Count = co_await ReadAfterBody(Buffer, Failure);
                if (Failure_.Failed() && Failure.Succeeded())
                {
                    Failure = Failure_;
                }
                co_return Preview::IoResult{Count, Failure};
            }
            IoFailure Failure;
            const auto Count = co_await ReadTunnel(Buffer, Failure, Written);
            if (Failure_.Failed() && Failure.Succeeded())
            {
                Failure = Failure_;
            }
            co_return Preview::IoResult{Count, Failure};
        }

        /** @brief 数据面部分写入实现，由正式前门复用。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            if (!Source_.Inner())
            {
                co_return Preview::IoResult{
                    0, Preview::Fault::FromNative(make_error_code(Error::NotOpen))};
            }
            const auto Part = co_await Source_.Inner()->WriteSome(Buffer);
            const auto Count = Part.Bytes;
            if (Count > Buffer.size())
            {
                co_return Preview::IoResult{
                    0, Preview::Fault::FromNative(make_error_code(Error::BadLength))};
            }
            if (Part.Failure.Succeeded() && Failure_.Failed())
            {
                co_return Preview::IoResult{Count, Failure_};
            }
            if (Part.Failure.Failed() || Count == 0U || !AwaitUpgrade_ || !Upgrade_.Awaiting())
            {
                co_return Part;
            }
            Upgrade_.Observe(std::span<const std::byte>(Buffer.data(), Count));
            const auto UpgradeFailure = Upgrade_.Failure();
            if (UpgradeFailure.Failed())
            {
                Failure_ = UpgradeFailure;
            }
            co_return Preview::IoResult{Count, UpgradeFailure};
        }

        /** @brief 查询底层连接及本地 close 状态。 */
        [[nodiscard]] auto IsOpen() const -> bool
        {
            return Source_.Inner() && Source_.Inner()->IsOpen() && !Closed_;
        }

    private:
        [[nodiscard]] static auto ProtocolFailure(const Preview::Error Value) -> IoFailure
        {
            return Preview::Fault::FromNative(make_error_code(Value));
        }

        auto CopyHeader(std::span<std::byte> Buffer) -> std::size_t
        {
            if (HeaderOffset_ >= Header_.size())
            {
                return 0;
            }
            const auto Count = (std::min)(Buffer.size(), Header_.size() - HeaderOffset_);
            std::memcpy(Buffer.data(), Header_.data() + HeaderOffset_, Count);
            HeaderOffset_ += Count;
            return Count;
        }

        auto Fail(IoFailure Failure, IoFailure &Output) -> void
        {
            if (Failure.Succeeded())
            {
                Failure = ProtocolFailure(Error::IoError);
            }
            Failure_ = Failure;
            Output = Failure;
            Upgrade_.Fail(std::move(Failure));
        }

        [[nodiscard]] auto ReadLine(IoFailure &Failure) -> Net::awaitable<bool>
        {
            Line_.clear();
            while (true)
            {
                std::byte Byte{};
                if (!co_await Source_.ReadRawByte(Byte, Failure))
                {
                    Fail(Failure, Failure);
                    co_return false;
                }
                Line_.push_back(Byte);
                if (Line_.size() > MaxHdrSize)
                {
                    Fail(ProtocolFailure(Error::BadMessage), Failure);
                    co_return false;
                }
                const auto Character = static_cast<char>(std::to_integer<unsigned char>(Byte));
                if (Character == '\n')
                {
                    if (Line_.size() < 2U ||
                        static_cast<char>(std::to_integer<unsigned char>(Line_[Line_.size() - 2U])) !=
                            '\r')
                    {
                        Fail(ProtocolFailure(Error::BadMessage), Failure);
                        co_return false;
                    }
                    co_return true;
                }
                if (Line_.size() > 1U &&
                    static_cast<char>(std::to_integer<unsigned char>(Line_[Line_.size() - 2U])) ==
                        '\r' && Character != '\n')
                {
                    Fail(ProtocolFailure(Error::BadMessage), Failure);
                    co_return false;
                }
            }
        }

        auto QueueLine() -> void
        {
            Output_.insert(Output_.end(), Line_.begin(), Line_.end());
        }

        [[nodiscard]] auto ReadChunked(std::span<std::byte> Buffer,
                                       IoFailure &Failure)
            -> Net::awaitable<std::size_t>
        {
            std::size_t Written = 0;
            while (Written < Buffer.size())
            {
                if (OutputOffset_ < Output_.size())
                {
                    const auto Count = (std::min)(Buffer.size() - Written,
                                                  Output_.size() - OutputOffset_);
                    std::memcpy(Buffer.data() + Written, Output_.data() + OutputOffset_, Count);
                    OutputOffset_ += Count;
                    Written += Count;
                    if (OutputOffset_ == Output_.size())
                    {
                        Output_.clear();
                        OutputOffset_ = 0;
                    }
                    continue;
                }
                if (ChunkState_ == ChunkState::Done)
                {
                    break;
                }
                if (ChunkState_ == ChunkState::SizeLine)
                {
                    if (!co_await ReadLine(Failure))
                    {
                        co_return Written;
                    }
                    if (!ParseChunkSize(
                            std::span<const std::byte>(Line_.data(), Line_.size()),
                            ChunkRemaining_))
                    {
                        Fail(ProtocolFailure(Error::BadMessage), Failure);
                        co_return Written;
                    }
                    QueueLine();
                    if (ChunkRemaining_ == 0U)
                    {
                        ChunkState_ = ChunkState::Trailer;
                    }
                    else
                    {
                        ChunkState_ = ChunkState::Data;
                    }
                    continue;
                }
                if (ChunkState_ == ChunkState::Data)
                {
                    Written += co_await Source_.ReadChunkData(
                        Buffer.subspan(Written), ChunkRemaining_, Failure);
                    if (Failure.Failed())
                    {
                        Fail(Failure, Failure);
                    }
                    if (Failure_.Failed())
                    {
                        Failure = Failure_;
                        co_return Written;
                    }
                    if (ChunkRemaining_ == 0U)
                    {
                        ChunkState_ = ChunkState::DataCrlf;
                    }
                    continue;
                }
                if (!co_await ReadLine(Failure))
                {
                    co_return Written;
                }
                if (ChunkState_ == ChunkState::DataCrlf)
                {
                    if (Line_.size() != 2U ||
                        std::string_view(reinterpret_cast<const char *>(Line_.data()), 2U) != "\r\n")
                    {
                        Fail(ProtocolFailure(Error::BadMessage), Failure);
                        co_return Written;
                    }
                    QueueLine();
                    ChunkState_ = ChunkState::SizeLine;
                    continue;
                }
                if (Line_.size() == 2U)
                {
                    QueueLine();
                    ChunkState_ = ChunkState::Done;
                    continue;
                }
                if (!IsValidTrailer(std::string_view(
                        reinterpret_cast<const char *>(Line_.data()), Line_.size())))
                {
                    Fail(ProtocolFailure(Error::BadMessage), Failure);
                    co_return Written;
                }
                QueueLine();
            }
            co_return Written;
        }

        /** @brief 先交付已有隧道字节；部分读不为填满缓冲额外等待上游或后续 EOF。 */
        [[nodiscard]] auto ReadTunnel(std::span<std::byte> Buffer,
                                      IoFailure &Failure,
                                      std::size_t Prefix) -> Net::awaitable<std::size_t>
        {
            auto Written = Prefix + Source_.CopyBuffered(Buffer.subspan(Prefix));
            if (Written != 0U)
            {
                Failure = Source_.TakeTerminalFailure();
                co_return Written;
            }
            Failure = Source_.TakeTerminalFailure();
            if (Failure.Failed())
            {
                co_return Written;
            }
            const auto Part = co_await Source_.Inner()->ReadSome(
                Buffer.subspan(Written));
            if (Part.Bytes > Buffer.size() - Written)
            {
                Failure = ProtocolFailure(Error::BadLength);
                co_return Written;
            }
            Failure = Part.Failure;
            if (Failure.Succeeded() && Failure_.Failed())
            {
                Failure = Failure_;
            }
            co_return Written + Part.Bytes;
        }

        [[nodiscard]] auto ReadAfterBody(std::span<std::byte> Buffer,
                                         IoFailure &Failure)
            -> Net::awaitable<std::size_t>
        {
            if (!AwaitUpgrade_)
            {
                Failure = IoFailure{Preview::Fault::Code::Eof};
                co_return 0;
            }
            if (!co_await Upgrade_.Wait())
            {
                Failure = Upgrade_.Failure();
                if (Failure.Succeeded())
                {
                    Failure = IoFailure{Preview::Fault::Code::Eof};
                }
                co_return 0;
            }
            co_return co_await ReadTunnel(Buffer, Failure, 0);
        }

        ForwardRequestSource Source_;
        std::vector<std::byte> Header_;
        std::vector<std::byte> Output_;
        std::vector<std::byte> Line_;
        std::size_t HeaderOffset_{0};
        std::size_t OutputOffset_{0};
        std::uint64_t Remaining_{0};
        std::uint64_t ChunkRemaining_{0};
        ForwardBodyMode BodyMode_{ForwardBodyMode::None};
        ChunkState ChunkState_{ChunkState::SizeLine};
        IoFailure Failure_;
        bool AwaitUpgrade_{false};
        bool Closed_{false};
        UpgradeGate Upgrade_;
    };
} // namespace Preview::Http11::Detail
