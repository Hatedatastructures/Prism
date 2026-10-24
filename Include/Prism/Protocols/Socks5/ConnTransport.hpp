/**
 * @file ConnTransport.hpp
 * @brief SOCKS5 流连接的底层传输 owner
 * @details 拥有上游传输、握手超读缓冲、精确读写循环及同次读取的终态。
 *          本头不参与 SOCKS5 方法协商、认证或请求语义。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Socks5
{

    namespace Net = boost::asio;

    /**
     * @class ConnTransport
     * @brief SOCKS5 Conn 的传输和缓冲 owner
     * @tparam Memory 会话内存策略
 * @details 所有权从构造函数移交；握手期间底层一次读取的超读字节
 *          留在本对象，后续 ReadSome 优先消费这些字节。
     */
    template <Prism::Memory::Restrict Memory>
    class ConnTransport final
    {
    public:
        using Completion = Prism::Transmission::Completion;

        explicit ConnTransport(SharedTransmission Upstream, Memory &MemoryValue)
            : NextLayer_(std::move(Upstream)), Buf_(MemoryValue.Arena())
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Executor();
        }

        /** @brief 预读缓冲优先的部分读取；借用与完成沿正式前门传递。 */
        [[nodiscard]] auto ReadSome(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            if (Used_ > 0 || PendingFailure_)
            {
                co_return TakePending(Buffer);
            }
            if (!NextLayer_)
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }
            co_return co_await NextLayer_->ReadSome(Buffer);
        }

        /** @brief token 形式；命中预读缓冲或上游已释放时异步交付一次结果，否则直接透传底层。 */
        auto ReadSome(std::span<std::byte> Buffer, Completion Handler) -> void
        {
            if (Used_ > 0 || PendingFailure_ || !NextLayer_)
            {
                Prism::Transmission::PostResult(Executor(), std::move(Handler), TakePending(Buffer));
                return;
            }
            NextLayer_->ReadSome(Buffer, std::move(Handler));
        }

        /** @brief 底层透传写入。 */
        [[nodiscard]] auto WriteSome(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            if (!NextLayer_)
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }
            co_return co_await NextLayer_->WriteSome(Buffer);
        }

        /** @brief token 形式直接透传底层，不复制 buffer 或吞掉用户取消。 */
        auto WriteSome(std::span<const std::byte> Buffer, Completion Handler) -> void
        {
            if (!NextLayer_)
            {
                Prism::Transmission::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {Prism::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteSome(Buffer, std::move(Handler));
        }

        /** @brief 真实写半关闭沿正式前门转交底层；上游已释放时异步交付失败。 */
        auto WriteShutdown(Completion Handler) -> void
        {
            if (!NextLayer_)
            {
                Prism::Transmission::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {Prism::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 精确读取指定字节数，先交付缓冲字节，再报告同次读取的终态。
         * @details 完整目标字段在终态前返回成功；部分字段返回真实进度和原终态，后续读取不重试底层。
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                if (Used_ > 0)
                {
                    const auto N = std::min(Buffer.size() - Done, Used_);
                    std::memcpy(Buffer.data() + Done, Buf_.data(), N);
                    if (N < Used_)
                    {
                        std::memmove(Buf_.data(), Buf_.data() + N, Used_ - N);
                        Used_ -= N;
                    }
                    else
                    {
                        Buf_.clear();
                        Used_ = 0;
                    }
                    Done += N;
                    continue;
                }
                if (PendingFailure_)
                {
                    co_return Prism::IoResult{Done, *PendingFailure_};
                }
                if (!NextLayer_)
                {
                    co_return Prism::IoResult{
                        Done, {Prism::Fault::Code::IoError}};
                }
                std::array<std::uint8_t, 512> Chunk{};
                const auto Part = co_await NextLayer_->ReadSome(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(Chunk.data()), Chunk.size()));
                if (Part.Bytes > Chunk.size())
                {
                    co_return Prism::IoResult{
                        Done, {Prism::Fault::Code::InvalidArgument, Part.Failure.Native}};
                }
                if (Part.Bytes != 0U)
                {
                    Buf_.insert(Buf_.end(), Chunk.begin(),
                                Chunk.begin() + static_cast<std::ptrdiff_t>(Part.Bytes));
                    Used_ += Part.Bytes;
                }
                if (Part.Failure.Failed())
                {
                    PendingFailure_ = Part.Failure;
                    continue;
                }
                if (Part.Bytes == 0U)
                {
                    co_return Prism::IoResult{Done,
                        {Done == 0U ? Prism::Fault::Code::Eof
                                    : Prism::Fault::Code::BadMessage}};
                }
            }
            co_return Prism::IoResult{Done, {}};
        }

        /** @brief 循环短写直至全部字节发出。 */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const
            -> Net::awaitable<Prism::IoResult>
        {
            co_return co_await Prism::Protocol::Common::WriteAllIo(NextLayer_, Data);
        }

        [[nodiscard]] auto Underlying() noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

        [[nodiscard]] auto Underlying() const noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission *
        {
            return NextLayer_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission *
        {
            return NextLayer_.get();
        }

        [[nodiscard]] auto Release() -> SharedTransmission
        {
            return std::move(NextLayer_);
        }

        [[nodiscard]] auto HasUpstream() const noexcept -> bool
        {
            return NextLayer_ != nullptr;
        }

        [[nodiscard]] auto Close() -> Prism::Transmission::ControlResult
        {
            if (NextLayer_)
            {
                return NextLayer_->Close();
            }
            return {};
        }

        [[nodiscard]] auto Cancel() -> Prism::Transmission::ControlResult
        {
            if (NextLayer_)
            {
                return NextLayer_->Cancel();
            }
            return {};
        }

    private:
        /** @brief 消费握手超读缓冲；无缓冲或上游已释放时返回 0 字节与确定的领域失败码。 */
        [[nodiscard]] auto TakePending(std::span<std::byte> Buffer) -> Prism::IoResult
        {
            if (Used_ == 0)
            {
                if (PendingFailure_)
                {
                    return {0, *PendingFailure_};
                }
                return {0, {Prism::Fault::Code::IoError}};
            }
            const auto N = std::min(Buffer.size(), Used_);
            std::memcpy(Buffer.data(), Buf_.data(), N);
            if (N < Used_)
            {
                std::memmove(Buf_.data(), Buf_.data() + N, Used_ - N);
            }
            else
            {
                Buf_.clear();
            }
            Used_ -= N;
            return {N, {}};
        }

        SharedTransmission NextLayer_;
        typename Memory::template Buffer<std::uint8_t> Buf_;
        std::size_t Used_{0};
        std::optional<Prism::Fault::Failure> PendingFailure_; ///< 预读字节耗尽后的 sticky 读取终态。
    };

} // namespace Prism::Socks5
