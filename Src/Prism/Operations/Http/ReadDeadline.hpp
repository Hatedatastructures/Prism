/**
 * @file ReadDeadline.hpp
 * @brief Operations HTTP 请求读取期限任务。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <chrono>
#include <exception>
#include <functional>
#include <memory>
#include <optional>

namespace Prism::Operations::HttpConnection::Detail
{

    namespace Net = boost::asio;

    enum class ReadDeadlineErrorSource
    {
        TimerWait,
        TimerCancel,
        SocketCancel,
    };

    struct ReadDeadlineTask;

    struct ReadDeadlineActions final
    {
        std::function<boost::system::error_code()> CancelSocket;
        std::function<void(const std::shared_ptr<ReadDeadlineTask> &,
            const boost::system::error_code &)> ReportFailure;
    };

    struct ReadDeadlineTask final
    {
        ReadDeadlineTask(Net::any_io_executor Executor,
            std::chrono::milliseconds Deadline,
            ReadDeadlineActions ActionsValue);

        std::shared_ptr<Net::steady_timer> Timer;
        Net::experimental::channel<void(boost::system::error_code)> Completion;
        Net::experimental::channel<void(boost::system::error_code)> FailureOwnerPublication;
        ReadDeadlineActions Actions;
        std::optional<boost::system::error_code> Failure;
        std::atomic<bool> FailureOwnerPublished{false};
        std::atomic<bool> FailureOwnerNotificationFailed{false};
        bool Finished{false};
        bool Failed{false};
    };

    [[nodiscard]] auto StartReadDeadline(
        const std::shared_ptr<Net::ip::tcp::socket> &Socket,
        std::chrono::milliseconds Deadline,
        ReadDeadlineActions Actions) -> std::shared_ptr<ReadDeadlineTask>;

    auto CompleteReadDeadlineWait(
        const std::shared_ptr<ReadDeadlineTask> &Task,
        const boost::system::error_code &WaitError) noexcept -> void;

    auto CompleteReadDeadlineTask(
        const std::shared_ptr<ReadDeadlineTask> &Task,
        const std::exception_ptr &Failure) noexcept -> void;

    [[nodiscard]] auto CancelReadDeadline(
        const std::shared_ptr<ReadDeadlineTask> &Task) -> Net::awaitable<bool>;

    [[nodiscard]] auto HasUnexpectedReadDeadlineError(
        ReadDeadlineErrorSource Source,
        const boost::system::error_code &Error) noexcept -> bool;

} // namespace Prism::Operations::HttpConnection::Detail
