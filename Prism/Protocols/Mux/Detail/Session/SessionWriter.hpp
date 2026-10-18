/**
 * @file SessionWriter.hpp
 * @brief 多路复用会话的唯一 writer 和写入预算职责。
 * @details producer 只入队并等待完成通知；writer 在会话执行器上串行处理
 *          partial write，确保帧边界和 producer 顺序。
 */

#pragma once

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <memory>
#include <utility>

#include <Prism/Protocols/Mux/Detail/Session/SessionContract.hpp>
#include <Prism/Protocols/Mux/Detail/Session/SessionWriteLoop.hpp>

namespace Prism::Mux
{

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::EnqueueWrite(
        std::vector<std::uint8_t> Frame,
        ProtocolEc &ErrorCode) -> std::shared_ptr<WriteRequest>
    {
        if (SessionClosed_ || !Raw_ || !Raw_->IsOpen())
        {
            ErrorCode = make_error_code(Error::BrokenPipe);
            return {};
        }
        if (Opt_.MaxPendingWriteBytes != 0)
        {
            const auto Used = (std::min)(PendingWriteBytes_, Opt_.MaxPendingWriteBytes);
            if (Frame.size() > Opt_.MaxPendingWriteBytes - Used)
            {
                ErrorCode = make_error_code(Error::BadLength);
                return {};
            }
        }
        auto Request = std::make_shared<WriteRequest>(Ex_, std::move(Frame));
        PendingWrites_.push_back(Request);
        if (Opt_.MaxPendingWriteBytes != 0)
        {
            PendingWriteBytes_ += Request->Frame.size();
        }
        StartWriter();
        ErrorCode.clear();
        return Request;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::RawWrite(std::vector<std::uint8_t> Frame)
        -> Net::awaitable<ProtocolEc>
    {
        co_await Net::dispatch(Ex_, Net::use_awaitable);
        ProtocolEc ErrorCode;
        auto Request = EnqueueWrite(std::move(Frame), ErrorCode);
        if (!Request)
        {
            co_return ErrorCode;
        }
        try
        {
            // 取消只中断 producer 的 completion wait；in-flight Request 仍由 writer 持有到真实写入完成。
            co_return co_await Request->Completion.async_receive(Net::use_awaitable);
        }
        catch (...)
        {
            Request->Canceled = true;
            throw;
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    template <std::size_t Size>
    inline auto Session<C, Memory>::RawWrite(std::array<std::uint8_t, Size> Frame)
        -> Net::awaitable<ProtocolEc>
    {
        co_return co_await RawWrite(std::vector<std::uint8_t>(Frame.begin(), Frame.end()));
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::StartWriter() -> void
    {
        if (WriterRunning_ || SessionClosed_)
        {
            return;
        }
        WriterRunning_ = true;
        auto Self = this->shared_from_this();
        Prism::Lifecycle::TaskRequest Request;
        Request.Context = Prism::Lifecycle::FromParent(Identity_);
        Request.StartOnSubmit = true;
        const auto WeakSelf = std::weak_ptr<Session>(Self);
        Request.Cancel = [WeakSelf]
        { if (const auto Owner = WeakSelf.lock()) Owner->CancelRaw(); };
        if (!Tasks_->SpawnTracked(std::move(Request), RunWriter(Self)))
        { WriterRunning_ = false; FailPendingWrites(make_error_code(Error::Canceled)); }

    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::CompleteWriteRequest(
        const std::shared_ptr<WriteRequest> &Request,
        const ProtocolEc &ErrorCode) -> void
    {
        if (!Request || Request->CompletionSent)
        {
            return;
        }
        Request->CompletionSent = true;
        ReleasePendingWriteBudget(Request);
        (void)Request->Completion.try_send(boost::system::error_code{}, ErrorCode);
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::FailPendingWrites(const ProtocolEc &ErrorCode) -> void
    {
        while (!PendingWrites_.empty())
        {
            auto Request = std::move(PendingWrites_.front());
            PendingWrites_.pop_front();
            if (Request)
            {
                Request->Canceled = true;
                CompleteWriteRequest(Request, ErrorCode);
            }
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::WriteLoop() -> Net::awaitable<void>
    {
        co_await Net::dispatch(Ex_, Net::use_awaitable);
        std::shared_ptr<WriteRequest> Request;
        try
        {
            while (!PendingWrites_.empty())
            {
                Request = std::move(PendingWrites_.front());
                PendingWrites_.pop_front();
                if (!Request)
                {
                    continue;
                }
                if (Request->Canceled)
                {
                    CompleteWriteRequest(Request, make_error_code(Error::Canceled));
                    Request.reset();
                    continue;
                }

                ProtocolEc ErrorCode = make_error_code(Error::BrokenPipe);
                if (!SessionClosed_ && Raw_ && Raw_->IsOpen())
                {
                    ErrorCode = co_await Detail::WriteFrame(Raw_, Request->Frame);
                }
                if (ErrorCode)
                {
                    Teardown(ErrorCode);
                    if (Raw_)
                    {
                        (void)Raw_->Close();
                    }
                    CompleteWriteRequest(Request, ErrorCode);
                    Request.reset();
                    break;
                }
                CompleteWriteRequest(Request, ErrorCode);
                Request.reset();
            }
        }
        catch (...)
        {
            const auto ErrorCode = make_error_code(Error::IoError);
            Teardown(ErrorCode);
            if (Raw_)
            {
                (void)Raw_->Close();
            }
            CompleteWriteRequest(Request, ErrorCode);
            Request.reset();
        }
        WriterRunning_ = false;
        co_return;
    }

} // namespace Prism::Mux
