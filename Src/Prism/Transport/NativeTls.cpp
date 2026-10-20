/** @file NativeTls.cpp @brief 前缀识别、TLS 握手与移交实现。 */
#include <Prism/Transport/NativeTls.hpp>
#include <Prism/Transport/Preview.hpp>

#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <span>
#include <utility>

namespace Prism::Transport::Detail
{
    struct TlsPrefix final
    {
        std::array<std::byte, 2> Bytes{};
        std::size_t Size{0};
        Fault::Failure Failure;
        bool IsTls{false};
    };

    /** @brief prefix 缓冲在本帧拥有；每个 partial 的计时器沿用同一绝对 deadline。 */
    [[nodiscard]] auto ReadTlsPrefix(
        SharedTransmission Inbound,
        const std::chrono::steady_clock::time_point Deadline)
        -> Net::awaitable<TlsPrefix>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        TlsPrefix Prefix;
        Net::steady_timer Timer(Inbound->Executor());
        Timer.expires_at(Deadline);
        while (Prefix.Size < Prefix.Bytes.size())
        {
            const auto Buffer = std::span(Prefix.Bytes).subspan(Prefix.Size);
            auto [Order, Result, TimerError] = co_await Net::experimental::make_parallel_group(
                Inbound->ReadSome(Buffer, Net::deferred), Timer.async_wait(Net::deferred))
                .async_wait(Net::experimental::wait_for_one(), Net::use_awaitable);
            if (Result.Bytes > Buffer.size())
            {
                Prefix.Failure = {Fault::Code::InvalidArgument};
                co_return Prefix;
            }
            Prefix.Size += Result.Bytes;
            Prefix.Failure = Result.Failure;
            if (Order[0] == 1 && !TimerError)
            {
                Prefix.Failure.Code = Fault::Code::Timeout;
            }
            if (Prefix.Size != 0 && Prefix.Bytes[0] != std::byte{0x16})
            {
                co_return Prefix;
            }
            if (Prefix.Size == 2)
            {
                Prefix.IsTls = Prefix.Bytes[1] == std::byte{0x03};
                co_return Prefix;
            }
            if (Prefix.Failure.Failed())
            {
                co_return Prefix;
            }
            if (Result.Bytes == 0)
            {
                Prefix.Failure = {Fault::Code::WouldBlock};
                co_return Prefix;
            }
        }
        co_return Prefix;
    }
}

namespace Prism::Transport
{
    [[nodiscard]] auto UpgradeNativeTls(NativeTlsRequest Request)
        -> Net::awaitable<NativeTlsResult>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        NativeTlsResult Result;
        if (!Request.Inbound)
        {
            Result.Failure = {Fault::Code::InvalidArgument};
            co_return Result;
        }
        if (!Request.Context)
        {
            Result.Transport = std::move(Request.Inbound);
            co_return Result;
        }
        const auto Deadline = std::chrono::steady_clock::now() + Request.Timeout;
        if (Request.Timeout <= std::chrono::steady_clock::duration::zero() || !Request.Bytes)
        {
            Result.Failure = {Fault::Code::InvalidArgument};
            if (Request.Timeout <= std::chrono::steady_clock::duration::zero())
            {
                Result.Failure = {Fault::Code::Timeout};
            }
            const auto Closed = Request.Inbound->Close();
            if (!Closed)
            {
                Result.Failure = Closed.error();
            }
            co_return Result;
        }
        auto Prefix = co_await Detail::ReadTlsPrefix(Request.Inbound, Deadline);
        if (!Prefix.IsTls && Prefix.Size != 0 &&
            (Prefix.Bytes[0] != std::byte{0x16} || Prefix.Size == Prefix.Bytes.size()))
        {
            auto Replayed = PreviewTransport::Create(Request.Inbound,
                {std::span(Prefix.Bytes).first(Prefix.Size), Request.Bytes, Prefix.Failure});
            if (!Replayed)
            {
                Result.Failure = Replayed.error();
                const auto Closed = Request.Inbound->Close();
                if (!Closed)
                {
                    Result.Failure = Closed.error();
                }
                co_return Result;
            }
            Result.Transport = std::move(*Replayed);
            co_return Result;
        }
        if (Prefix.Failure.Failed())
        {
            Result.Failure = Prefix.Failure;
            const auto Closed = Request.Inbound->Close();
            if (!Closed)
            {
                Result.Failure = Closed.error();
            }
            co_return Result;
        }
        Result.Attempted = true;
        auto Replayed = PreviewTransport::Create(Request.Inbound,
            {std::span(Prefix.Bytes).first(Prefix.Size), Request.Bytes, {}});
        if (!Replayed)
        {
            Result.Failure = Replayed.error();
            const auto Closed = Request.Inbound->Close();
            if (!Closed)
            {
                Result.Failure = Closed.error();
            }
            co_return Result;
        }
        auto Handshake = co_await Encrypted::SslHandshake(
            {std::move(*Replayed), *Request.Context, Deadline, std::move(Request.Bytes)});
        Result.Failure = Handshake.Failure;
        if (Result.Failure.Succeeded() && Handshake.Stream)
        {
            Result.Transport = MakeEncrypted(std::move(Handshake.Stream),
                std::move(Handshake.Bytes));
            co_return Result;
        }
        if (Handshake.Recovered)
        {
            const auto Closed = Handshake.Recovered->Close();
            if (!Closed)
            {
                Result.Failure = Closed.error();
            }
        }
        if (Handshake.Stream)
        {
            if (auto *Inner = Handshake.Stream->next_layer().NextLayer())
            {
                const auto Closed = Inner->Close();
                if (!Closed)
                {
                    Result.Failure = Closed.error();
                }
            }
        }
        co_return Result;
    }
}
