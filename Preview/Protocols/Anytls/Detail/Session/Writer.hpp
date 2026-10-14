/** @file Writer.hpp @brief AnyTLS 唯一完整帧 writer，拥有 encoded buffer 和每个 producer completion。 */
#pragma once
#include <Preview/Protocols/Anytls/Frame.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/system_error.hpp>
#include <deque>
#include <exception>
#include <system_error>

namespace Preview::Anytls::Detail
{
    struct WriteResult final
    {
        std::size_t PayloadBytes{0};
        Preview::Fault::Failure Failure{};
    };

    [[nodiscard]] inline auto WriterFailureFromException(std::exception_ptr Exception) noexcept
        -> Preview::Fault::Failure
    {
        try
        {
            if (Exception) std::rethrow_exception(Exception);
        }
        catch (const boost::system::system_error &Error)
        {
            return Preview::Fault::FromNative(static_cast<std::error_code>(Error.code()));
        }
        catch (const std::system_error &Error)
        {
            return Preview::Fault::FromNative(Error.code());
        }
        catch (...)
        {
            return {Preview::Fault::Code::IoError};
        }
        return {Preview::Fault::Code::IoError};
    }

    class FrameWriter final : public std::enable_shared_from_this<FrameWriter>
    {
        struct Entry final
        {
            Entry(Net::any_io_executor Ex, std::vector<std::byte> Value)
                : Wire(std::move(Value)), Completion(Ex, 1) {}
            std::vector<std::byte> Wire;
            Net::experimental::channel<void(boost::system::error_code, WriteResult)> Completion;
            bool Completed{false};
        };
    public:
        FrameWriter(Preview::SharedTransmission Stream, std::shared_ptr<Preview::Lifecycle::TaskRegistry> Tasks)
            : Stream_(std::move(Stream)), Tasks_(std::move(Tasks)) {}
        auto BindIdentity(Preview::Lifecycle::TaskIdentity Identity) -> void
        { Identity_ = Identity; }
        /** @brief 接管完整帧并等唯一 writer 完成；取消不销毁 writer 借用的帧，错误返回实际 payload byte。 */
        [[nodiscard]] auto Send(Frame Value) -> Net::awaitable<WriteResult>
        {
            co_await Net::dispatch(Tasks_->Executor(), Net::use_awaitable);
            if (Closed_)
                co_return WriteResult{.Failure = {Preview::Fault::Code::Canceled}};
            if (Value.Payload.size() > 65535)
                co_return WriteResult{.Failure = {Preview::Fault::Code::InvalidArgument}};
            auto Item = std::make_shared<Entry>(Tasks_->Executor(), Encode(std::move(Value)));
            Queue_.push_back(Item);
            if (!Running_)
            {
                Running_ = true;
                Preview::Lifecycle::TaskRequest Request{.Context = Preview::Lifecycle::FromParent(Identity_), .StartOnSubmit = true};
                const auto Weak = weak_from_this();
                Request.Cancel = [Weak] { if (const auto Owner = Weak.lock()) Owner->Close(); };
                const auto Spawned = Tasks_->SpawnTracked(std::move(Request), Pump(shared_from_this()));
                if (!Spawned)
                {
                    Queue_.pop_back();
                    RecordFailure(Spawned.error());
                    Complete(Item, WriteResult{.Failure = Spawned.error()});
                    (void)Close();
                }
            }
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            boost::system::error_code Error;
            const auto Result = co_await Item->Completion.async_receive(Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
                co_return WriteResult{.Failure = Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error))};
            co_return Result;
        }
        /** @brief 所属 executor 封止 writer、完成所有排队 producer；active buffer 由实际 I/O task 持有到退出。 */
        auto Close() noexcept
            -> std::expected<void, Preview::Fault::Failure>
        {
            if (Closed_)
            {
                if (FirstFailure_.Failed()) return std::unexpected(FirstFailure_);
                return std::expected<void, Preview::Fault::Failure>{};
            }
            Closed_ = true;
            while (!Queue_.empty())
            {
                Complete(Queue_.front(), WriteResult{.Failure = {Preview::Fault::Code::Canceled}});
                Queue_.pop_front();
            }
            if (Stream_)
            {
                try
                {
                    const auto Canceled = Stream_->Cancel();
                    if (!Canceled) RecordFailure(Canceled.error());
                }
                catch (...)
                {
                    RecordFailure(WriterFailureFromException(std::current_exception()));
                }
                try
                {
                    const auto Closed = Stream_->Close();
                    if (!Closed) RecordFailure(Closed.error());
                }
                catch (...)
                {
                    RecordFailure(WriterFailureFromException(std::current_exception()));
                }
            }
            if (FirstFailure_.Failed()) return std::unexpected(FirstFailure_);
            return std::expected<void, Preview::Fault::Failure>{};
        }
    private:
        auto RecordFailure(Preview::Fault::Failure Failure) noexcept -> void
        {
            if (!FirstFailure_.Failed()) FirstFailure_ = Failure;
        }

        static auto Complete(const std::shared_ptr<Entry>& Item, WriteResult Result) noexcept -> void
        {
            if (Item->Completed) return;
            Item->Completed = true;
            (void)Item->Completion.try_send(boost::system::error_code{}, Result);
        }
        static auto Pump(std::shared_ptr<FrameWriter> Owner) -> Net::awaitable<void>
        {
            try
            {
                while (!Owner->Closed_ && !Owner->Queue_.empty())
                {
                    const auto Item = Owner->Queue_.front(); Owner->Queue_.pop_front();
                    Owner->Active_ = Item;
                    std::size_t Offset = 0;
                    Preview::Fault::Failure Failure;
                    while (Offset < Item->Wire.size() && !Owner->Closed_)
                    {
                        Preview::IoResult Part;
                        try
                        {
                            Part = co_await Owner->Stream_->WriteSome(
                                std::span(Item->Wire).subspan(Offset));
                        }
                        catch (...)
                        {
                            Failure = WriterFailureFromException(std::current_exception());
                            break;
                        }
                        const auto Count = Part.Bytes;
                        if (Count > Item->Wire.size() - Offset)
                        {
                            Failure = {Preview::Fault::Code::IoError};
                            break;
                        }
                        Offset += Count;
                        Owner->ActivePayloadBytes_ = Offset > 7U ? Offset - 7U : 0U;
                        if (Part.Failure.Failed()) { Failure = Part.Failure; break; }
                        if (Count == 0U) { Failure = {Preview::Fault::Code::IoError}; break; }
                    }
                    if (Failure.Succeeded() && Offset != Item->Wire.size())
                    {
                        Failure = Owner->Closed_
                            ? Preview::Fault::Failure{Preview::Fault::Code::Canceled}
                            : Preview::Fault::Failure{Preview::Fault::Code::IoError};
                    }
                    if (Failure.Failed()) Owner->RecordFailure(Failure);
                    Complete(Item, WriteResult{
                        .PayloadBytes = Offset > 7U ? Offset - 7U : 0U,
                        .Failure = Failure});
                    Owner->Active_.reset();
                    Owner->ActivePayloadBytes_ = 0U;
                    if (Failure.Failed()) (void)Owner->Close();
                }
            }
            catch (...)
            {
                if (Owner->Active_)
                {
                    const auto Failure = WriterFailureFromException(std::current_exception());
                    Owner->RecordFailure(Failure);
                    Complete(Owner->Active_, WriteResult{
                        .PayloadBytes = Owner->ActivePayloadBytes_, .Failure = Failure});
                }
                Owner->Active_.reset();
                Owner->ActivePayloadBytes_ = 0U;
                Owner->Close();
            }
            Owner->Running_ = false;
        }
        Preview::SharedTransmission Stream_;
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Tasks_;
        Preview::Lifecycle::TaskIdentity Identity_;
        std::deque<std::shared_ptr<Entry>> Queue_;
        std::shared_ptr<Entry> Active_;
        std::size_t ActivePayloadBytes_{0U};
        Preview::Fault::Failure FirstFailure_;
        bool Closed_{false}, Running_{false};
    };
}
