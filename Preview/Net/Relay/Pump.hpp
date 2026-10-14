/** @file Pump.hpp @brief 按真实 partial 字节、值取消和半关闭推进双向中继。 */
#pragma once
#include <Preview/Net/Relay/State.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/this_coro.hpp>

namespace Preview::Network::Relay
{
    /** @brief 持 owner 写完当前已读范围；错误同次携带的成功字节先记账。 */
    inline auto Flush(std::shared_ptr<State> Owner, std::size_t Direction, std::size_t Size)
        -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        const auto Buffer = Owner->Buffers[Direction].Bytes();
        while (Offset < Size)
        {
            const auto Part = co_await Owner->Destination(Direction)->WriteSome(Buffer.subspan(Offset, Size - Offset));
            if (Part.Bytes > Size - Offset)
            { Owner->Record(Direction, {Fault::Code::InvalidArgument}); Owner->Close(); co_return false; }
            Offset += Part.Bytes;
            Owner->Output.Total[Direction] += Part.Bytes;
            auto Flow = Foundation::TrafficObservation::Direction::Download;
            if (Direction == 0) Flow = Foundation::TrafficObservation::Direction::Upload;
            Owner->Input.Observation.Transfer(Part.Bytes, Flow);
            if (Part.Failure.Failed() || Part.Bytes == 0)
            {
                auto Failure = Part.Failure;
                if (Failure.Succeeded()) Failure = {Fault::Code::WouldBlock};
                Owner->Record(Direction, Failure);
                Owner->Close();
                co_return false;
            }
            Owner->Touch();
        }
        co_return true;
    }
    /** @brief EOF 先交付本次数据再关闭对端写方向；取消/失败停止两端，保留反向读至完成。 */
    inline auto Pump(std::shared_ptr<State> Owner, std::size_t Direction) -> Net::awaitable<void>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        while (!Owner->Closed)
        {
            auto Buffer = Owner->Buffers[Direction].WritableBytes();
            const auto Part = co_await Owner->Source(Direction)->ReadSome(Buffer);
            if (Part.Bytes > Buffer.size())
            { Owner->Record(Direction, {Fault::Code::InvalidArgument}); Owner->Close(); break; }
            if (Part.Bytes != 0 && !co_await Flush(Owner, Direction, Part.Bytes)) break;
            if (Part.Failure.Code == Fault::Code::Eof)
            {
                const auto Shutdown = co_await Owner->Destination(Direction)->WriteShutdown();
                if (!Shutdown) { Owner->Record(Direction, Shutdown.error()); Owner->Close(); }
                break;
            }
            if (Part.Failure.Failed() || Part.Bytes == 0)
            {
                auto Failure = Part.Failure;
                if (Failure.Succeeded()) Failure = {Fault::Code::WouldBlock};
                Owner->Record(Direction, Failure);
                Owner->Close();
                break;
            }
            Owner->Touch();
        }
        Owner->FinishPump();
    }
    /** @brief 只在启用 idle 时创建；同一个真实 timer 随传输活动重设，到期停止两端。 */
    inline auto WaitIdle(std::shared_ptr<State> Owner) -> Net::awaitable<void>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        while (!Owner->Closed && Owner->Completed != 2)
        {
            boost::system::error_code Error;
            co_await Owner->Idle.async_wait(Net::redirect_error(Net::use_awaitable, Error));
            if (Error == Net::error::operation_aborted)
            {
                const auto Cancellation = co_await Net::this_coro::cancellation_state;
                if (Cancellation.cancelled() != Net::cancellation_type::none) Owner->Close();
                continue;
            }
            if (Error) Owner->Record(0, Fault::FromNative(static_cast<std::error_code>(Error)));
            else Owner->Record(0, {Fault::Code::Timeout});
            Owner->Close();
        }
    }
}
