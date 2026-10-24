/**
 * @file SessionState.hpp
 * @brief 多路复用会话的流状态和公开会话操作。
 * @details 本文件拥有流表、入向队列和会话可用性相关的 API；窗口、写入、
 *          帧分发和最终拆除由其他职责头提供。
 */

#pragma once

#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <memory>

#include <Prism/Protocols/Mux/Detail/Session/SessionContract.hpp>
#include <cstddef>
#include <cstdint>
#include <span>

namespace Prism::Mux
{

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::TaskContextForStream(const std::uint32_t Id) const noexcept
        -> Prism::Lifecycle::TaskContext
    {
        auto Context = Prism::Lifecycle::FromParent(Identity_);
        Context.StreamId = Prism::StreamId{Id};
        return Context;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::OpenStream()
        -> Net::awaitable<std::shared_ptr<StreamHandle<Memory>>>
    {
        co_await Net::dispatch(Ex_, Net::use_awaitable);
        if (SessionClosed_ || !Raw_ || !Raw_->IsOpen())
        {
            co_return nullptr;
        }
        const auto Id = AllocateId();
        if (Id == 0)
        {
            if (StreamIdExhausted_)
            {
                ProtocolErrorTeardown();
            }
            co_return nullptr;
        }
        auto Handle = std::make_shared<StreamHandle<Memory>>(
            StreamOptions{Id, Opt_.MaxStreamRxBytes, TaskContextForStream(Id)},
            this->shared_from_this());
        Streams_[Id] = Handle;
        InitializeLocalFlow(Id);
        if (co_await RawWrite(C::BuildOpen(Id)))
        {
            RemoveStream(Id);
            co_return nullptr;
        }
        co_return Handle;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::AcceptStream()
        -> Net::awaitable<std::shared_ptr<StreamHandle<Memory>>>
    {
        co_await Net::dispatch(Ex_, Net::use_awaitable);
        while (Raw_ && Raw_->IsOpen())
        {
            if (Canceled_)
            {
                Canceled_ = false;
                co_return nullptr;
            }
            if (!Incoming_.empty())
            {
                auto Handle = Incoming_.front();
                Incoming_.pop_front();
                co_return Handle;
            }
            if (SessionClosed_)
            {
                co_return nullptr;
            }
            AcceptNotify_.reset();
            co_await AcceptNotify_.async_receive(Net::use_awaitable);
        }
        co_return nullptr;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::PushData(
        const std::uint32_t StreamId,
        const std::span<const std::uint8_t> Data) -> Net::awaitable<ProtocolEc>
    {
        co_await Net::dispatch(Ex_, Net::use_awaitable);
        if (SessionClosed_ || !Raw_ || !Raw_->IsOpen())
        {
            co_return make_error_code(Error::BrokenPipe);
        }
        std::size_t Chunk;
        if (C::MaxPayloadLen > 0)
        {
            Chunk = C::MaxPayloadLen;
        }
        else
        {
            Chunk = Data.size();
        }
        std::size_t Done = 0;
        while (Done < Data.size())
        {
            std::size_t N = (std::min)(Chunk, Data.size() - Done);
            if constexpr (UsesFlowControl())
            {
                while (N != 0 && (N = ReserveSendWindow(StreamId, N)) == 0)
                {
                    if (!co_await WaitForSendWindow(StreamId))
                    {
                        co_return make_error_code(Error::BrokenPipe);
                    }
                    N = (std::min)(Chunk, Data.size() - Done);
                }
                if (N == 0)
                {
                    co_return make_error_code(Error::BrokenPipe);
                }
            }
            const auto Ec = co_await RawWrite(C::BuildData(StreamId, Data.subspan(Done, N)));
            if (Ec)
            {
                if constexpr (UsesFlowControl())
                {
                    ReturnSendWindow(StreamId, N);
                }
                // 数据面写失败必须上抛：静默丢弃会让流进入假活状态。
                co_return Ec;
            }
            Done += N;
        }
        co_return boost::system::error_code{};
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::SendFin(const std::uint32_t StreamId)
        -> Net::awaitable<void>
    {
        co_await Net::dispatch(Ex_, Net::use_awaitable);
        // 关闭路径 best-effort：写失败不阻塞半关。
        if (Raw_ && Raw_->IsOpen())
        {
            (void)co_await RawWrite(C::BuildFin(StreamId));
        }
        co_return;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::SendRst(const std::uint32_t StreamId)
        -> Net::awaitable<void>
    {
        co_await Net::dispatch(Ex_, Net::use_awaitable);
        // 重置路径 best-effort：本端已丢弃该流。
        if (Raw_ && Raw_->IsOpen())
        {
            (void)co_await RawWrite(C::BuildRst(StreamId));
        }
        co_return;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::RemoveStream(const std::uint32_t StreamId) -> void
    {
        if (const auto It = Streams_.find(StreamId); It != Streams_.end())
        {
            if (It->second)
            {
                It->second->DetachSession();
            }
            Streams_.erase(It);
        }
        RemoveFlow(StreamId);
    }

    template <typename C, Prism::Memory::Restrict Memory>
    [[nodiscard]] inline auto Session<C, Memory>::IsOpen() const -> bool
    {
        return !SessionClosed_ && Raw_ && Raw_->IsOpen();
    }

    template <typename C, Prism::Memory::Restrict Memory>
    [[nodiscard]] inline auto Session<C, Memory>::Executor() const -> Net::any_io_executor
    {
        return Ex_;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    [[nodiscard]] inline auto Session<C, Memory>::StreamCount() const -> std::size_t
    {
        return Streams_.size();
    }

    template <typename C, Prism::Memory::Restrict Memory>
    [[nodiscard]] inline auto Session<C, Memory>::Tasks() const noexcept
        -> std::shared_ptr<Prism::Lifecycle::TaskRegistry>
    {
        return Tasks_;
    }

} // namespace Prism::Mux
