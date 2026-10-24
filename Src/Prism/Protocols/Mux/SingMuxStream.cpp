/** @file SingMuxStream.cpp @brief sing-mux 子流 I/O 实现。 */
#include <Prism/Protocols/Mux/SingMux/Stream.hpp>

#include <array>
#include <cstddef>
#include <system_error>
#include <utility>

namespace Prism::Mux::SingMux
{

    auto ServerStream::StartWrite(
        const std::span<const std::byte> Buffer,
        Completion Handler) -> void
    {
        Initiate<WriteWork>(StreamWrite{
                                std::static_pointer_cast<ServerStream>(
                                    Transmission::shared_from_this()),
                                Buffer},
                            std::move(Handler));
    }

    auto ServerStream::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        if (Buffer.empty())
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{0, {}});
            return;
        }
        if (PendingReadTerminal_ && !PendingReadTerminalConsumed_.exchange(
                true, std::memory_order_acq_rel))
        {
            const auto Terminal = *PendingReadTerminal_;
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{0, Terminal});
            return;
        }
        if (!Next_)
        {
            Prism::Transmission::PostResult(
                Executor(),
                std::move(Handler), Prism::IoResult{0, Missing()});
            return;
        }
        Next_->ReadSome(Buffer, std::move(Handler));
    }

    [[nodiscard]] auto ServerStream::WritePartial(
        std::span<const std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
    {
        if (!Next_)
        {
            co_return Prism::IoResult{
                0, Prism::Fault::FromNative(std::make_error_code(std::errc::not_connected))};
        }
        if (!ResponseWritten_)
        {
            const std::array<std::byte, 1> Status{std::byte{0x00}};
            const auto StatusResult = co_await WriteAll(Status);
            if (StatusResult.Bytes == Status.size())
            {
                ResponseWritten_ = true;
            }
            if (StatusResult.Failure.Failed()) co_return Prism::IoResult{0, StatusResult.Failure};
            if (StatusResult.Bytes != Status.size())
            {
                co_return Prism::IoResult{
                    0, Prism::Fault::FromNative(std::make_error_code(std::errc::broken_pipe))};
            }
        }
        if (Buffer.empty())
        {
            co_return Prism::IoResult{};
        }
        co_return co_await WriteAll(Buffer);
    }

    [[nodiscard]] auto ServerStream::WriteAll(
        std::span<const std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            const auto Remaining = Buffer.size() - Offset;
            const auto Part = co_await Next_->WriteSome(Buffer.subspan(Offset));
            if (Part.Bytes > Remaining)
            {
                const auto Failure = Part.Failure.Failed()
                    ? Part.Failure
                    : Prism::Fault::FromNative(std::make_error_code(std::errc::broken_pipe));
                co_return Prism::IoResult{Offset, Failure};
            }
            Offset += Part.Bytes;
            if (Part.Failure.Failed()) co_return Prism::IoResult{Offset, Part.Failure};
            if (Part.Bytes == 0)
            {
                co_return Prism::IoResult{
                    Offset, Prism::Fault::FromNative(std::make_error_code(std::errc::broken_pipe))};
            }
        }
        co_return Prism::IoResult{Offset, {}};
    }

}
