/**
 * @file HttpConnectionLifecycle.hpp
 * @brief HTTP 连接 socket、准入登记与排空生命周期 owner。
 * @details listener 状态串行器管理连接登记，每个连接串行器独立处理 socket 操作。
 */

#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <atomic>
#include <exception>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Operations::HttpConnection
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    [[nodiscard]] inline auto StateFailureFromException(std::exception_ptr Failure) noexcept
        -> Prism::Fault::Failure
    {
        try
        {
            if (Failure) std::rethrow_exception(Failure);
        }
        catch (const boost::system::system_error &Error)
        {
            return Prism::Fault::FromNative(static_cast<std::error_code>(Error.code()));
        }
        catch (const std::system_error &Error)
        {
            return Prism::Fault::FromNative(Error.code());
        }
        catch (...)
        {
            return {Prism::Fault::Code::IoError};
        }
        return {Prism::Fault::Code::IoError};
    }

    struct ConnectionState final
    {
        explicit ConnectionState(Net::any_io_executor Executor);

        Net::strand<Net::any_io_executor> Strand;
        std::shared_ptr<Tcp::socket> Socket;
        std::atomic<bool> HandlerActive{false};
        std::atomic<bool> ResponseOutstanding{false};
        std::atomic<bool> CloseRequested{false};
    };

    auto CloseSocketOnConnectionStrand(
        const std::shared_ptr<ConnectionState> &Connection) noexcept -> void;

    /** @brief 完整响应写完后先半关闭发送方向，再由连接 owner 正常关闭 socket。 */
    auto CloseCompletedResponseOnConnectionStrand(
        const std::shared_ptr<ConnectionState> &Connection) noexcept -> void;

    template <typename StateValue>
    inline auto RequestConnectionCloseOnStateStrand(
        const std::shared_ptr<StateValue> &State,
        const std::shared_ptr<ConnectionState> &Connection) noexcept -> void
    {
        if (Connection->HandlerActive.load(std::memory_order_acquire))
        {
            Connection->CloseRequested.store(true, std::memory_order_release);
            return;
        }
        if (Connection->CloseRequested.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }
        try
        {
            Net::post(Connection->Strand,
                      [Connection] { CloseSocketOnConnectionStrand(Connection); });
        }
        catch (...)
        {
            State->StateOperationFailed.store(true, std::memory_order_release);
        }
    }

    template <typename StateValue>
    inline auto CloseAdmissionOnStateStrand(
        const std::shared_ptr<StateValue> &State) noexcept -> void
    {
        boost::system::error_code Error;
        if (State->Acceptor.is_open())
        {
            State->Acceptor.cancel(Error);
            if (Error)
            {
                if (!State->DrainFailure)
                {
                    State->DrainFailure = Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error));
                }
                State->StateOperationFailed.store(true, std::memory_order_release);
                Error.clear();
            }
            State->Acceptor.close(Error);
            if (Error)
            {
                if (!State->DrainFailure)
                {
                    State->DrainFailure = Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error));
                }
                State->StateOperationFailed.store(true, std::memory_order_release);
            }
        }
        State->Running.store(false, std::memory_order_release);
        for (const auto &Connection : State->ActiveConnections)
        {
            if (Connection &&
                !Connection->ResponseOutstanding.load(std::memory_order_acquire))
            {
                RequestConnectionCloseOnStateStrand(State, Connection);
            }
        }
    }

    template <typename StateValue>
    inline auto CloseConnectionsOnStateStrand(
        const std::shared_ptr<StateValue> &State) noexcept -> void
    {
        for (const auto &Connection : State->ActiveConnections)
        {
            if (Connection)
            {
                RequestConnectionCloseOnStateStrand(State, Connection);
            }
        }
    }

    template <typename StateValue>
    inline auto CloseOnStateStrand(const std::shared_ptr<StateValue> &State) noexcept -> void
    {
        CloseAdmissionOnStateStrand(State);
        CloseConnectionsOnStateStrand(State);
    }

    template <typename StateValue>
    inline auto FinishConnectionOnStateStrand(
        const std::shared_ptr<StateValue> &State,
        const std::shared_ptr<ConnectionState> &Connection) noexcept -> void
    {
        const auto It = std::find(
            State->ActiveConnections.begin(), State->ActiveConnections.end(), Connection);
        if (It == State->ActiveConnections.end())
        {
            return;
        }
        State->ActiveConnections.erase(It);
        const auto LastConnection =
            State->ActiveConnectionCount.fetch_sub(1U, std::memory_order_acq_rel) == 1U;
        if (LastConnection && State->Draining.load(std::memory_order_acquire))
        {
            try
            {
                (void)State->DrainTimer.cancel();
            }
            catch (...)
            {
                State->StateOperationFailed.store(true, std::memory_order_release);
            }
        }
    }

    template <typename StateValue>
    inline auto FinishConnection(const std::shared_ptr<StateValue> &State,
                                 const std::shared_ptr<ConnectionState> &Connection) noexcept -> void
    {
        try
        {
            Net::post(
                State->StateStrand,
                [State, Connection] { FinishConnectionOnStateStrand(State, Connection); });
        }
        catch (...)
        {
            State->StateOperationFailed.store(true, std::memory_order_release);
        }
    }

    template <typename StateValue>
    class ConnectionGuard final
    {
    public:
        ConnectionGuard(std::shared_ptr<StateValue> StateValueObject,
                        std::shared_ptr<ConnectionState> ConnectionValue)
            : State_(std::move(StateValueObject)), Connection_(std::move(ConnectionValue))
        {
        }

        ~ConnectionGuard()
        {
            FinishConnection(State_, Connection_);
        }

        ConnectionGuard(const ConnectionGuard &) = delete;
        auto operator=(const ConnectionGuard &) -> ConnectionGuard & = delete;

    private:
        std::shared_ptr<StateValue> State_;
        std::shared_ptr<ConnectionState> Connection_;
    };


}
