/**
 * @file ConnIo.hpp
 * @brief VMess 连接的底层 partial I/O owner。
 * @details 负责上游传输导航、精确补读和短写循环；不解析 VMess 认证头，
 *          也不推进 chunk 编解码状态。
 */
#pragma once

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Fault/Compatible.hpp>
#include <Preview/Protocols/Vmess/ConnSession.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>
#include <system_error>
#include <utility>

namespace Preview::Vmess::detail
{

    namespace Net = boost::asio;

    /** @brief 精确读操作的结果，区分干净 EOF 与半包/底层错误。 */
    enum class ExactReadStatus : std::uint8_t
    {
        Complete,
        CleanEof,
        Failed,
    };

    /**
     * @brief VMess 底层传输和 partial I/O owner。
     * @tparam Memory 会话内存策略
     * @details 上游所有权仍归 ConnSession；本对象只借用会话并统一收口
     *          ReadSome/WriteSome 的短读、短写和 EOF 语义。
     */
    template <Preview::Memory::Restrict Memory>
    class ConnIo final
    {
    public:
        using Session = ConnSession<Memory>;

        /** @brief 借用会话并持有构造时的执行域；未握手或释放上游后仍交付到同一域。 */
        explicit ConnIo(Session& SessionValue, Net::any_io_executor ExecutorValue)
            : Session_(SessionValue), Executor_(std::move(ExecutorValue))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Executor_;
        }

        [[nodiscard]] auto HasUpstream() const noexcept -> bool
        {
            return Session_.NextLayer_ != nullptr;
        }

        [[nodiscard]] auto Underlying() noexcept -> Preview::SharedTransmission
        {
            return Session_.NextLayer_;
        }

        [[nodiscard]] auto Underlying() const noexcept -> Preview::SharedTransmission
        {
            return Session_.NextLayer_;
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission*
        {
            return Session_.NextLayer_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission*
        {
            return Session_.NextLayer_.get();
        }

        [[nodiscard]] auto Release() noexcept -> Preview::SharedTransmission
        {
            return Session_.Release();
        }

        /** @brief 封止并交付底层关闭；实际退出由 Activity()->Drain() 另行等待。 */
        [[nodiscard]] auto Close() noexcept -> Preview::Transmission::ControlResult
        {
            return Session_.Close();
        }

        /** @brief 可重复取消底层 I/O；成功不表示连接已关闭。 */
        [[nodiscard]] auto Cancel() noexcept -> Preview::Transmission::ControlResult
        {
            return Session_.Cancel();
        }

        /** @brief 真实写半关闭沿正式前门转交底层；读取方向保持可用。 */
        auto WriteShutdown(Preview::Transport::Detail::IoCompletion Handler) -> void
        {
            if (!Session_.NextLayer_)
            {
                Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            Session_.NextLayer_->WriteShutdown(std::move(Handler));
        }

        [[nodiscard]] auto ReadExactStatus(std::span<std::uint8_t> Buffer) -> Net::awaitable<ExactReadStatus>
        {
            if (!Session_.NextLayer_)
            {
                co_return ExactReadStatus::Failed;
            }
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                const auto Part = co_await Session_.NextLayer_->ReadSome(Preview::AsBytes(Buffer.subspan(Done)));
                if (Part.Bytes > Buffer.size() - Done)
                {
                    co_return ExactReadStatus::Failed;
                }
                if (Part.Bytes == 0)
                {
                    if (Done == 0 && (!Part.Failure.Failed() || Part.Failure.Code == Preview::Fault::Code::Eof))
                    {
                        co_return ExactReadStatus::CleanEof;
                    }
                    co_return ExactReadStatus::Failed;
                }
                if (Part.Failure.Failed())
                {
                    co_return ExactReadStatus::Failed;
                }
                Done += Part.Bytes;
            }
            co_return ExactReadStatus::Complete;
        }

        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
        {
            const auto Status = co_await ReadExactStatus(Buffer);
            co_return Status != ExactReadStatus::Complete;
        }

        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const -> Net::awaitable<bool>
        {
            if (!Session_.NextLayer_)
            {
                co_return true;
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                const auto Part = co_await Session_.NextLayer_->WriteSome(Preview::AsBytes(Data.subspan(Done)));
                if (Part.Failure.Failed() || Part.Bytes == 0 || Part.Bytes > Data.size() - Done)
                {
                    co_return true;
                }
                Done += Part.Bytes;
            }
            co_return false;
        }

        /** @brief 握手精确读取；结果保留累计字节、Fault 和 Native。 */
        [[nodiscard]] auto ReadExactIo(std::span<std::uint8_t> Buffer) -> Net::awaitable<Preview::IoResult>
        {
            Preview::IoResult Result;
            if (!Session_.NextLayer_)
            {
                Result.Failure = {Preview::Fault::Code::IoError};
                co_return Result;
            }
            while (Result.Bytes < Buffer.size())
            {
                const auto Part = co_await Session_.NextLayer_->ReadSome(
                    Preview::AsBytes(Buffer.subspan(Result.Bytes)));
                if (Part.Bytes > Buffer.size() - Result.Bytes)
                {
                    Result.Failure = {Preview::Fault::Code::IoError, Part.Failure.Native};
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

        /** @brief 握手精确写出；结果保留实际推进字节与 Native。 */
        [[nodiscard]] auto WriteAllIo(std::span<const std::uint8_t> Data) const
            -> Net::awaitable<Preview::IoResult>
        {
            Preview::IoResult Result;
            if (!Session_.NextLayer_)
            {
                Result.Failure = {Preview::Fault::Code::IoError};
                co_return Result;
            }
            while (Result.Bytes < Data.size())
            {
                const auto Part = co_await Session_.NextLayer_->WriteSome(
                    Preview::AsBytes(Data.subspan(Result.Bytes)));
                if (Part.Bytes > Data.size() - Result.Bytes)
                {
                    Result.Failure = {Preview::Fault::Code::IoError, Part.Failure.Native};
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

        /** @brief VMess 数据报 chunk 写入返回当前帧的真实 partial I/O 结果。 */
        [[nodiscard]] auto SendDatagramBytes(std::span<const std::uint8_t> Data) const
            -> Net::awaitable<Preview::IoResult>
        {
            Preview::IoResult Result;
            if (!Session_.NextLayer_)
            {
                Result.Failure = {Preview::Fault::Code::IoError};
                co_return Result;
            }
            while (Result.Bytes < Data.size())
            {
                const auto Remaining = Data.size() - Result.Bytes;
                const auto Part = co_await Session_.NextLayer_->WriteSome(
                    Preview::AsBytes(Data.subspan(Result.Bytes)));
                if (Part.Bytes > Remaining)
                {
                    Result.Bytes = Part.Bytes >
                        (std::numeric_limits<std::size_t>::max)() - Result.Bytes
                        ? (std::numeric_limits<std::size_t>::max)()
                        : Result.Bytes + Part.Bytes;
                    Result.Failure = {
                        Preview::Fault::Code::InvalidArgument, Part.Failure.Native};
                    co_return Result;
                }
                Result.Bytes += Part.Bytes;
                Result.Failure = Part.Failure;
                if (Result.Failure.Failed()) co_return Result;
                if (Part.Bytes == 0)
                {
                    Result.Failure = {Preview::Fault::Code::WouldBlock};
                    co_return Result;
                }
            }
            co_return Result;
        }

        /** @brief VMess 数据报 chunk 精确读保留 Native 并区分干净 EOF 与截断帧。 */
        [[nodiscard]] auto ReadDatagramBytes(std::span<std::uint8_t> Buffer,
                                               bool &FrameStarted)
            -> Net::awaitable<Preview::IoResult>
        {
            Preview::IoResult Result;
            if (!Session_.NextLayer_)
            {
                Result.Failure = {Preview::Fault::Code::IoError};
                co_return Result;
            }
            while (Result.Bytes < Buffer.size())
            {
                const auto Remaining = Buffer.size() - Result.Bytes;
                const auto Part = co_await Session_.NextLayer_->ReadSome(
                    Preview::AsBytes(Buffer.subspan(Result.Bytes)));
                if (Part.Bytes > Remaining)
                {
                    Result.Bytes = Part.Bytes >
                        (std::numeric_limits<std::size_t>::max)() - Result.Bytes
                        ? (std::numeric_limits<std::size_t>::max)()
                        : Result.Bytes + Part.Bytes;
                    Result.Failure = {
                        Preview::Fault::Code::InvalidArgument, Part.Failure.Native};
                    co_return Result;
                }
                Result.Bytes += Part.Bytes;
                FrameStarted = FrameStarted || Part.Bytes != 0U;
                Result.Failure = Part.Failure;
                if (Result.Failure.Failed()) co_return Result;
                if (Part.Bytes == 0)
                {
                    Result.Failure = {
                        FrameStarted ? Preview::Fault::Code::BadMessage
                                     : Preview::Fault::Code::Eof};
                    co_return Result;
                }
            }
            co_return Result;
        }

    private:
        Session& Session_;
        const Net::any_io_executor Executor_;
    };

} // namespace Preview::Vmess::detail
