/** @file ReadDeadline.cpp @brief Operations HTTP 请求读取期限任务的生命周期实现。 */

#include <Prism/Operations/Http/Detail/ReadDeadline.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <exception>
#include <utility>

namespace Prism::Operations::HttpConnection::Detail
{

    namespace
    {

        auto RecordReadDeadlineFailure(
            const std::shared_ptr<ReadDeadlineTask> &Task,
            const boost::system::error_code &Error) noexcept -> void
        {
            if (Task->Failure)
            {
                return;
            }
            Task->Failure = Error;
            Task->Failed = true;
            if (!Task->Actions.ReportFailure)
            {
                Task->FailureOwnerNotificationFailed.store(true, std::memory_order_release);
                return;
            }
            try
            {
                Task->Actions.ReportFailure(Task, Error);
            }
            catch (...)
            {
                Task->FailureOwnerNotificationFailed.store(true, std::memory_order_release);
            }
        }

    } // namespace

    auto HasUnexpectedReadDeadlineError(
        const ReadDeadlineErrorSource Source,
        const boost::system::error_code &Error) noexcept -> bool
    {
        return Error &&
               (Source != ReadDeadlineErrorSource::TimerWait ||
                Error != Net::error::operation_aborted);
    }

    ReadDeadlineTask::ReadDeadlineTask(
        Net::any_io_executor Executor,
        const std::chrono::milliseconds Deadline,
        ReadDeadlineActions ActionsValue)
        : Timer(std::make_shared<Net::steady_timer>(Executor)),
          Completion(Executor, 1),
          FailureOwnerPublication(std::move(Executor), 1),
          Actions(std::move(ActionsValue))
    {
        Timer->expires_after(Deadline);
    }

    /** @brief 按值持有 deadline task，直到 timer wait 完成。 */
    [[nodiscard]] auto WaitForReadDeadline(
        std::shared_ptr<ReadDeadlineTask> Task) -> Net::awaitable<void>
    {
        boost::system::error_code Error;
        co_await Task->Timer->async_wait(Net::redirect_error(Net::use_awaitable, Error));
        CompleteReadDeadlineWait(Task, Error);
    }

    auto StartReadDeadline(
        const std::shared_ptr<Net::ip::tcp::socket> &Socket,
        const std::chrono::milliseconds Deadline,
        ReadDeadlineActions Actions) -> std::shared_ptr<ReadDeadlineTask>
    {
        const auto Task = std::make_shared<ReadDeadlineTask>(
            Socket->get_executor(), Deadline, std::move(Actions));
        Net::co_spawn(
            Socket->get_executor(),
            WaitForReadDeadline(Task),
            [Task](std::exception_ptr Failure)
            {
                CompleteReadDeadlineTask(Task, Failure);
            });
        return Task;
    }

    auto CompleteReadDeadlineWait(
        const std::shared_ptr<ReadDeadlineTask> &Task,
        const boost::system::error_code &WaitError) noexcept -> void
    {
        if (WaitError == Net::error::operation_aborted)
        {
            return;
        }
        if (HasUnexpectedReadDeadlineError(ReadDeadlineErrorSource::TimerWait, WaitError))
        {
            RecordReadDeadlineFailure(Task, WaitError);
            return;
        }

        boost::system::error_code CancelError;
        try
        {
            CancelError = Task->Actions.CancelSocket();
        }
        catch (...)
        {
            CancelError = boost::system::errc::make_error_code(boost::system::errc::io_error);
        }
        if (HasUnexpectedReadDeadlineError(ReadDeadlineErrorSource::SocketCancel, CancelError))
        {
            RecordReadDeadlineFailure(Task, CancelError);
        }
    }

    auto CompleteReadDeadlineTask(
        const std::shared_ptr<ReadDeadlineTask> &Task,
        const std::exception_ptr &Failure) noexcept -> void
    {
        if (Failure && !Task->Failure)
        {
            RecordReadDeadlineFailure(
                Task, boost::system::errc::make_error_code(boost::system::errc::io_error));
        }
        Task->Finished = true;
        if (!Task->Completion.try_send(boost::system::error_code{}))
        {
            RecordReadDeadlineFailure(
                Task, boost::system::errc::make_error_code(boost::system::errc::io_error));
        }
    }

    auto CancelReadDeadline(
        const std::shared_ptr<ReadDeadlineTask> &Task) -> Net::awaitable<bool>
    {
        if (!Task)
        {
            co_return true;
        }
        boost::system::error_code CancelError;
        try
        {
            static_cast<void>(Task->Timer->cancel());
        }
        catch (const boost::system::system_error &Error)
        {
            CancelError = Error.code();
        }
        catch (...)
        {
            CancelError = boost::system::errc::make_error_code(boost::system::errc::io_error);
        }
        if (CancelError && !Task->Finished)
        {
            RecordReadDeadlineFailure(Task, CancelError);
        }
        if (!Task->Finished)
        {
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            boost::system::error_code ReceiptError;
            co_await Task->Completion.async_receive(
                Net::redirect_error(Net::use_awaitable, ReceiptError));
            if (ReceiptError || !Task->Finished)
            {
                co_return false;
            }
        }
        if (Task->Failed)
        {
            if (Task->FailureOwnerNotificationFailed.load(std::memory_order_acquire))
            {
                co_return false;
            }
            boost::system::error_code PublicationError;
            co_await Task->FailureOwnerPublication.async_receive(
                Net::redirect_error(Net::use_awaitable, PublicationError));
            if (PublicationError ||
                !Task->FailureOwnerPublished.load(std::memory_order_acquire))
            {
                co_return false;
            }
        }
        co_return !Task->Failed;
    }

} // namespace Prism::Operations::HttpConnection::Detail
