/**
 * @file Wire.cpp
 * @brief Wire.hpp writer 状态与写入实现。
 */
#include <Prism/Protocols/Xhttp/Detail/Wire.hpp>

namespace Prism::Xhttp::Detail
{

    WireWriter::WireWriter(Net::any_io_executor Executor,
                   Sink SinkFunction,
                   FailureCallback FailureFunction)
            : Ex_(std::move(Executor)), Sink_(std::move(SinkFunction)),
              Failure_(std::move(FailureFunction)),
              Idle_(std::make_shared<IdleChannel>(Ex_, 1)){
        }

    [[nodiscard]] auto WireWriter::Write(std::span<const std::byte> Data)
            -> Net::awaitable<WriteResult>{
            if (Data.empty())
            {
                co_return WriteResult{};
            }
            if (Closed_ || !Sink_)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected)));
            }

            std::shared_ptr<RequestState> Request;
            bool Queued = false;
            try
            {
                Request = std::make_shared<RequestState>(Ex_, Data);
                Queue_.push_back(Request);
                Queued = true;
                Start();
            }
            catch (const std::bad_alloc &)
            {
                const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
                if (Queued && !WriterRunning_)
                {
                    RecordFailure(Failure);
                    FailQueued(Failure, false);
                    SignalIdle();
                }
                else if (Request)
                {
                    (void)Request->Done.try_send(
                        boost::system::error_code{}, Failure);
                }
                co_return std::unexpected(Failure);
            }

            boost::system::error_code WaitEc;
            const auto Failure = co_await Request->Done.async_receive(
                Net::redirect_error(Net::use_awaitable, WaitEc));
            if (WaitEc)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(WaitEc)));
            }
            if (Failure.Failed())
                co_return std::unexpected(Failure);
            co_return WriteResult{};
        }

    void WireWriter::Close(){
            Closed_ = true;
            FailQueued(Prism::Fault::FromNative(
                static_cast<std::error_code>(
                    boost::system::errc::make_error_code(boost::system::errc::not_connected))),
                false);
            SignalIdle();
            MarkRetiredIfDrained();
        }

    [[nodiscard]] auto WireWriter::Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
            Close();
            while (WriterRunning_ || !Queue_.empty())
            {
                boost::system::error_code WaitError;
                (void)co_await Idle_->async_receive(
                    Net::redirect_error(Net::use_awaitable, WaitError));
                if (WaitError)
                    co_return std::unexpected(Prism::Fault::FromNative(
                        static_cast<std::error_code>(WaitError)));
            }
            if (FirstFailure_.Failed())
                co_return std::unexpected(FirstFailure_);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

    WireWriter::RequestState::RequestState(Net::any_io_executor Executor, std::span<const std::byte> Data)
                : Data(Data.begin(), Data.end()), Done(Executor, 1){
            }

    void WireWriter::Start(){
            if (WriterRunning_ || Closed_ || Queue_.empty())
            {
                return;
            }
            WriterRunning_ = true;
            auto Self = shared_from_this();
            try
            {
                Net::co_spawn(
                    Ex_, [Self]() -> Net::awaitable<void> { co_await Self->Loop(); },
                    [Self](std::exception_ptr Exception)
                    { Self->CompleteLoop(std::move(Exception)); });
            }
            catch (const std::bad_alloc &)
            {
                WriterRunning_ = false;
                throw;
            }
        }

    void WireWriter::FailQueued(Prism::Fault::Failure Failure, bool Record){
            while (!Queue_.empty())
            {
                auto Request = std::move(Queue_.front());
                Queue_.pop_front();
                (void)Request->Done.try_send(boost::system::error_code{}, Failure);
                if (Record) RecordFailure(Failure);
            }
        }

    auto WireWriter::RecordFailure(Prism::Fault::Failure Failure) -> void{
            if (FirstFailure_.Succeeded() && Failure.Failed()) FirstFailure_ = Failure;
        }

    auto WireWriter::SignalIdle() -> void{
            if (!WriterRunning_ && Queue_.empty())
                (void)Idle_->try_send(boost::system::error_code{}, FirstFailure_);
        }

    auto WireWriter::MarkRetiredIfDrained() noexcept -> void{
            if (Closed_ && !WriterRunning_ && Queue_.empty() && !ActiveRequest_)
            {
                Retired_.store(true, std::memory_order_release);
            }
        }

    auto WireWriter::Loop() -> Net::awaitable<void>{
            while (!Queue_.empty())
            {
                auto Request = std::move(Queue_.front());
                Queue_.pop_front();
                ActiveRequest_ = Request;
                Prism::Fault::Failure Failure;
                if (Closed_ || !Sink_)
                {
                    Failure = Prism::Fault::FromNative(static_cast<std::error_code>(
                        boost::system::errc::make_error_code(boost::system::errc::not_connected)));
                }
                else
                {
                    const auto Result = co_await Sink_(Request->Data);
                    if (!Result) Failure = Result.error();
                }
                (void)Request->Done.try_send(boost::system::error_code{}, Failure);
                ActiveRequest_.reset();
                RecordFailure(Failure);
                if (Failure.Failed())
                {
                    Closed_ = true;
                    FailQueued(Failure, false);
                    NotifyFailure(Failure);
                    break;
                }
            }
            co_return;
        }

    auto WireWriter::CompleteLoop(std::exception_ptr Exception) noexcept -> void{
            if (Exception)
            {
                const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception));
                Closed_ = true;
                if (ActiveRequest_)
                {
                    (void)ActiveRequest_->Done.try_send(
                        boost::system::error_code{}, Failure);
                    ActiveRequest_.reset();
                }
                RecordFailure(Failure);
                FailQueued(Failure, false);
                NotifyFailure(Failure);
            }
            WriterRunning_ = false;
            SignalIdle();
            MarkRetiredIfDrained();
        }

    void WireWriter::NotifyFailure(Prism::Fault::Failure Failure) noexcept{
            if (FailureNotified_ || !Failure_)
            {
                return;
            }
            FailureNotified_ = true;
            auto Callback = std::move(Failure_);
            try
            {
                Callback(Failure);
            }
            catch (...)
            {
                RecordFailure(Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
            }
        }

} // namespace Prism::Xhttp::Detail
