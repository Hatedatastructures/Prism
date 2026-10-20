/** @file MemoryStream.cpp @brief 有界内存流的状态、通知与协程 I/O 实现。 */
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>

#include <boost/asio/async_result.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstring>
#include <memory>
#include <span>
#include <system_error>
#include <tuple>
#include <utility>

namespace Prism
{
    MemoryStream::State::State(MemoryStream::ExecutorType ValueExecutor)
        : Executor(std::move(ValueExecutor)), Readable(Executor, 1), Writable(Executor, 1),
          Pool(Memory::BytePoolOptions{64U * 1024U, 64})
    {
    }

    struct MemoryStream::ReadInput final
    {
        std::shared_ptr<MemoryStream::State> In;
        std::span<std::byte> Buffer;
    };

    struct MemoryStream::WriteInput final
    {
        std::shared_ptr<MemoryStream::State> In;
        std::shared_ptr<MemoryStream::State> Peer;
        std::span<const std::byte> Buffer;
    };

    struct MemoryStream::ReadOperation final
    {
        template<class OperationState>
        auto operator()(OperationState Operation, ReadInput Input) const -> void
        {
            Transmission::ConfigureIo(Operation);
            const auto Epoch = Input.In->CancelEpoch;
            Net::steady_timer Timer(Input.In->Executor);
            if (Input.In->Timeout.count() > 0) Timer.expires_after(Input.In->Timeout);
            else Timer.expires_at((Net::steady_timer::time_point::max)());
            while (true)
            {
                if (Input.In->Closed.load()) co_return std::tuple{IoResult{0, {Fault::Code::Canceled}}};
                if (Input.In->CancelEpoch != Epoch || !!Operation.cancelled()) co_return std::tuple{IoResult{0, {Fault::Code::Canceled}}};
                if (Input.Buffer.empty()) co_return std::tuple{IoResult{}};
                if (Input.In->Count != 0)
                {
                    auto& Bytes = *Input.In->Queue[Input.In->Head];
                    const auto Count = (std::min)(Input.Buffer.size(), Bytes.Size() - Input.In->Offset);
                    std::memcpy(Input.Buffer.data(), Bytes.Bytes().data() + Input.In->Offset, Count);
                    Input.In->Offset += Count;
                    if (Input.In->Offset == Bytes.Size())
                    {
                        Input.In->Queue[Input.In->Head].reset();
                        Input.In->Head = (Input.In->Head + 1) % Input.In->Queue.size();
                        --Input.In->Count;
                        Input.In->Offset = 0;
                        (void)Input.In->Writable.try_send(boost::system::error_code{});
                    }
                    co_return std::tuple{IoResult{Count, {}}};
                }
                if (Input.In->PeerEof) co_return std::tuple{IoResult{0, {Fault::Code::Eof}}};
                auto [Order, Error, TimerError] = co_await Net::experimental::make_parallel_group(
                    Input.In->Readable.async_receive(Net::deferred), Timer.async_wait(Net::deferred))
                    .async_wait(Net::experimental::wait_for_one(), Net::deferred);
                if (Order[0] == 1 && !TimerError)
                { co_return std::tuple{IoResult{0, {Fault::Code::Timeout}}}; }
                if (Error) co_return std::tuple{Failure(Error)};
            }
        }
    };

    struct MemoryStream::WriteOperation final
    {
        template<class OperationState>
        auto operator()(OperationState Operation, WriteInput Input) const -> void
        {
            Transmission::ConfigureIo(Operation);
            const auto Epoch = Input.In->CancelEpoch;
            while (true)
            {
                if (!Input.Peer || Input.In->Closed.load() || Input.In->WriteClosed || Input.Peer->Closed.load())
                    co_return std::tuple{IoResult{0, {Fault::Code::ConnectionAborted}}};
                if (Input.In->CancelEpoch != Epoch || !!Operation.cancelled()) co_return std::tuple{IoResult{0, {Fault::Code::Canceled}}};
                if (Input.Buffer.empty()) co_return std::tuple{IoResult{}};
                if (Input.Peer->Count < Input.Peer->Queue.size()) break;
                auto [Error] = co_await Input.Peer->Writable.async_receive(Net::as_tuple(Net::deferred));
                if (Error) co_return std::tuple{Failure(Error)};
            }
            const auto Count = (std::min)(Input.Buffer.size(), Input.Peer->Pool.BlockSize());
            auto Bytes = Input.Peer->Pool.TryAcquire(Count);
            if (!Bytes) co_return std::tuple{IoResult{0, Bytes.error()}};
            std::memcpy(Bytes->WritableBytes().data(), Input.Buffer.data(), Count);
            Input.Peer->Queue[Input.Peer->Tail].emplace(std::move(*Bytes));
            Input.Peer->Tail = (Input.Peer->Tail + 1) % Input.Peer->Queue.size();
            ++Input.Peer->Count;
            (void)Input.Peer->Readable.try_send(boost::system::error_code{});
            co_return std::tuple{IoResult{Count, {}}};
        }
    };

    MemoryStream::MemoryStream(ExecutorType Executor)
        : MemoryStream(std::make_shared<State>(Net::make_strand(std::move(Executor))), {})
    {
    }

    MemoryStream::MemoryStream(std::shared_ptr<State> Input, std::weak_ptr<State> Peer)
        : Transmission(Input->Executor), In_(std::move(Input)), Peer_(std::move(Peer))
    {
    }

    auto MemoryStream::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        Completion Routed(Transport::Detail::OriginalCompletion(Executor(), std::move(Handler)));
        Net::async_initiate<Completion, void(IoResult)>(Net::co_composed<void(IoResult)>(ReadOperation{}, Executor()),
            Routed, ReadInput{In_, Buffer});
    }

    auto MemoryStream::StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void
    {
        Completion Routed(Transport::Detail::OriginalCompletion(Executor(), std::move(Handler)));
        Net::async_initiate<Completion, void(IoResult)>(Net::co_composed<void(IoResult)>(WriteOperation{}, Executor()),
            Routed, WriteInput{In_, Peer_.lock(), Buffer});
    }

    auto MemoryStream::StartWriteShutdown(Completion Handler) -> void
    {
        In_->WriteClosed = true;
        if (auto Peer = Peer_.lock()) { Peer->PeerEof = true; Notify(Peer); }
        Transmission::PostResult(Executor(), std::move(Handler), {});
    }

    auto MemoryStream::OnClose() -> ControlResult
    {
        In_->Closed.store(true);
        In_->WriteClosed = true;
        Notify(In_);
        if (auto Peer = Peer_.lock()) { Peer->PeerEof = true; Notify(Peer); }
        return {};
    }

    auto MemoryStream::OnCancel() -> ControlResult
    {
        ++In_->CancelEpoch;
        Notify(In_);
        if (auto Peer = Peer_.lock()) Notify(Peer);
        return {};
    }

    auto MemoryStream::Notify(const std::shared_ptr<State>& Value) -> void
    {
        (void)Value->Readable.try_send(boost::system::error_code{});
        (void)Value->Writable.try_send(boost::system::error_code{});
    }

    auto MemoryStream::Failure(boost::system::error_code Error) -> IoResult
    {
        return {0, Fault::FromNative(static_cast<std::error_code>(Error))};
    }

    auto MakeMemoryPair(Net::any_io_executor Executor) -> std::pair<MemoryStream, MemoryStream>
    {
        const auto Domain = Net::make_strand(std::move(Executor));
        auto First = std::make_shared<MemoryStream::State>(Domain);
        auto Second = std::make_shared<MemoryStream::State>(Domain);
        return {MemoryStream(First, Second), MemoryStream(Second, First)};
    }
}
