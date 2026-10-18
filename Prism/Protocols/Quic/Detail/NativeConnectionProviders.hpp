/**
 * @file NativeConnectionProviders.hpp
 * @brief 原生 QUIC stream/datagram provider owner。
 * @details 外部 Provider 持弱连接、共享状态和独立 Io/PMR owner；连接等待队列
 *          只持 State，避免 executor 队列反向强 pin context。关闭完成后即使原
 *          Native 已释放，channel 析构仍有有效 executor；没有整 Runtime/Worker pin。
 */

#pragma once


#include <optional>

#include <Prism/Protocols/Quic/Detail/NativeConnection.hpp>

namespace Prism::Quic::Detail
{
    /** @brief 队列动作按状态、连接、原 executor context 的逆序析构。 */
    struct StreamProviderActionOwner final
    {
        std::shared_ptr<Prism::Executor::ContextOwner> Context;
        std::shared_ptr<NativeConnection> Connection;
        std::shared_ptr<StreamState> State;
    };

    /** @brief 数据报关闭/取消动作固定 channel、Native 与原 executor context。 */
    struct DatagramProviderActionOwner final
    {
        std::shared_ptr<Prism::Executor::ContextOwner> Context;
        std::shared_ptr<NativeConnection> Connection;
        std::shared_ptr<DatagramState> State;
    };

    /** @brief 原 executor 完成单条 stream 的关闭命令并保留实际 callback receipt。 */
    struct StreamProviderCloseActionOwner final
    {
        NativeStreamActivity::CloseOperation Reservation;
        std::shared_ptr<NativeStreamActivity> Activity;
        std::shared_ptr<StreamState> State;
        NativeConnection::OperationReservation ConnectionReservation;
        std::shared_ptr<NativeConnection> Connection;
    };

    inline auto CloseStreamProvider(StreamProviderCloseActionOwner Action) -> void
    {
        StreamProvider::ControlResult Result{};
        if (!Action.State)
        {
            Result = std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        else if (!Action.State->NativeTerminal.load(std::memory_order_acquire))
        {
            Action.State->Closed = true;
            Action.State->LocalWriteClosed = true;
            (void)Action.State->Notify.try_send(boost::system::error_code{});
            (void)Action.State->FinAcknowledgedNotify.try_send(boost::system::error_code{});
            if (!Action.Connection)
            {
                Result = std::unexpected(Prism::Fault::FromNative(
                    ToStdError(Prism::Error::BrokenPipe)));
            }
            else
            {
                try
                {
                    Action.Connection->CloseStream(Action.State);
                    if (Action.State->StreamCloseFailure.Failed())
                    {
                        Result = std::unexpected(Action.State->StreamCloseFailure);
                    }
                }
                catch (const std::bad_alloc &)
                {
                    Result = std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
                }
                catch (...)
                {
                    Result = std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::IoError});
                }
            }
        }
        Action.Activity->CompleteClose(std::move(Result));
    }

    /** @brief 原 executor 关闭本连接的数据报状态，不关闭公共入口 socket。 */
    inline auto CloseDatagramProvider(std::shared_ptr<NativeConnection> Owner,std::shared_ptr<DatagramState> State) -> void
    {
        if(!State || State->Closed)return;
        State->Closed=true;
        (void)State->Notify.try_send(boost::system::error_code{});
        if(Owner)Owner->CloseDatagram(State);
    }

    inline auto ReturnZero() -> Net::awaitable<std::size_t>
    {
        co_return 0;
    }

    inline auto FailedShutdown(Prism::Fault::Failure Failure)
        -> Net::awaitable<StreamProvider::ShutdownResult>
    {
        co_return std::unexpected(std::move(Failure));
    }

    inline auto NativeStream::Read(
        const std::span<std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        ErrorCode.clear();
        if (!State_ || Buffer.empty())
        {
            return ReturnZero();
        }
        const auto Provider = weak_from_this().lock();
        if (!Provider || !Activity_)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            return ReturnZero();
        }
        auto Reservation = Activity_->BeginOperation(Provider);
        if (!Reservation)
        {
            auto BufferedRead = Activity_->BeginBufferedRead(Provider);
            if (!BufferedRead)
            {
                ErrorCode = Prism::Fault::ToNative(BufferedRead.error());
                return ReturnZero();
            }
            return ReadOwned(std::move(*BufferedRead), Buffer, ErrorCode);
        }
        return ReadOwned(std::move(*Reservation), Buffer, ErrorCode);
    }

    inline auto NativeStream::ReadOwned(
        NativeStreamActivity::Operation Reservation,
        const std::span<std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        const auto Provider = std::static_pointer_cast<NativeStream>(Reservation.Carrier());
        if (!Provider || !Provider->State_)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }
        const auto State = Provider->State_;
        co_await Net::dispatch(State->Executor, Net::use_awaitable);
        const auto Connection = Provider->Owner_.lock();
        std::optional<NativeConnection::OperationReservation> NativeReservation;
        if (Connection)
        {
            NativeReservation.emplace(Connection);
        }
        while (true)
        {
            if (State->Canceled)
            {
                State->Canceled = false;
                ErrorCode = ToStdError(Prism::Error::Canceled);
                co_return 0;
            }
            if (!State->Received.empty())
            {
                auto &Front = State->Received.front();
                const auto Length = std::min(Buffer.size(), Front.size());
                std::memcpy(Buffer.data(), Front.data(), Length);
                if (Length == Front.size())
                {
                    State->Received.pop_front();
                }
                else
                {
                    Front.erase(Front.begin(), Front.begin() + static_cast<std::ptrdiff_t>(Length));
                }
                if (Length != 0 && Connection && NativeReservation && *NativeReservation)
                {
                    if (State->NativeTerminal.load(std::memory_order_acquire))
                    {
                        Connection->OnTerminalStreamReadConsumed(Length);
                    }
                    else
                    {
                        Connection->OnStreamReadConsumed(State->Id, Length);
                    }
                }
                co_return Length;
            }
            if (State->PeerReset)
            {
                ErrorCode = State->PeerReadFailure;
                co_return 0;
            }
            if (State->PeerFin)
            {
                co_return 0;
            }
            if (State->Closed || !Connection || !NativeReservation || !*NativeReservation)
            {
                ErrorCode = ToStdError(Prism::Error::BrokenPipe);
                co_return 0;
            }
            State->Notify.reset();
            boost::system::error_code NotifyError;
            co_await State->Notify.async_receive(Net::redirect_error(Net::use_awaitable, NotifyError));
            if (NotifyError && State->Closed)
            {
                if (!State->PeerFin)
                {
                    ErrorCode = ToStdError(Prism::Error::BrokenPipe);
                }
                co_return 0;
            }
        }
    }

    inline auto NativeStream::Write(
        const std::span<const std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        ErrorCode.clear();
        if (!State_ || Buffer.empty())
        {
            return ReturnZero();
        }
        const auto Provider = weak_from_this().lock();
        if (!Provider || !Activity_)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            return ReturnZero();
        }
        auto Reservation = Activity_->BeginOperation(Provider);
        if (!Reservation)
        {
            ErrorCode = Prism::Fault::ToNative(Reservation.error());
            return ReturnZero();
        }
        return WriteOwned(std::move(*Reservation), Buffer, ErrorCode);
    }

    inline auto NativeStream::WriteOwned(
        NativeStreamActivity::Operation Reservation,
        const std::span<const std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        const auto Provider = std::static_pointer_cast<NativeStream>(Reservation.Carrier());
        if (!Provider || !Provider->State_)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }
        const auto State = Provider->State_;
        co_await Net::dispatch(State->Executor, Net::use_awaitable);
        const auto Connection = Provider->Owner_.lock();
        if (!Connection)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }
        NativeConnection::OperationReservation NativeReservation{Connection};
        if (!NativeReservation)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }
        if (State->PeerStopSending)
        {
            ErrorCode = State->PeerWriteFailure;
            co_return 0;
        }
        if (State->Closed || State->LocalWriteClosed)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }
        std::vector<std::byte> Copy(Buffer.begin(), Buffer.end());
        co_return co_await Connection->WriteStream(State->Id, std::move(Copy), ErrorCode);
    }

    inline auto NativeStream::Close() -> StreamProvider::ControlResult
    {
        const auto Provider = weak_from_this().lock();
        if (!Provider || !State_ || !Activity_)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (Activity_->CloseAccepted())
        {
            Activity_->Seal();
            return {};
        }
        if (State_->NativeTerminal.load(std::memory_order_acquire))
        {
            Activity_->MarkNativeTerminal(State_->StreamCloseFailure);
            Activity_->Seal();
            return {};
        }
        const auto Connection = Owner_.lock();
        if (!Connection)
        {
            if (Activity_->CloseAccepted() ||
                State_->NativeTerminal.load(std::memory_order_acquire))
            {
                Activity_->Seal();
                return {};
            }
            return std::unexpected(
                Prism::Fault::FromNative(ToStdError(Prism::Error::BrokenPipe)));
        }
        auto Reservation = Activity_->BeginClose(Provider);
        if (!Reservation)
        {
            if (Activity_->CloseAccepted() ||
                State_->NativeTerminal.load(std::memory_order_acquire))
            {
                Activity_->Seal();
                return {};
            }
            return std::unexpected(Reservation.error());
        }
        if (!*Reservation)
        {
            Activity_->Seal();
            return {};
        }
        NativeConnection::OperationReservation ConnectionReservation{Connection};
        if (!ConnectionReservation)
        {
            Activity_->RollbackClose();
            if (Activity_->CloseAccepted() ||
                State_->NativeTerminal.load(std::memory_order_acquire))
            {
                Activity_->Seal();
                return {};
            }
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        StreamProviderCloseActionOwner Action{
            std::move(*Reservation), Activity_, State_,
            std::move(ConnectionReservation), Connection};
        try
        {
            Net::dispatch(State_->Executor,
                [Action = std::move(Action)]() mutable { CloseStreamProvider(std::move(Action)); });
        }
        catch (const std::bad_alloc &)
        {
            Activity_->RollbackClose();
            if (Activity_->CloseAccepted() ||
                State_->NativeTerminal.load(std::memory_order_acquire))
            {
                Activity_->Seal();
                return {};
            }
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        catch (...)
        {
            Activity_->RollbackClose();
            if (Activity_->CloseAccepted() ||
                State_->NativeTerminal.load(std::memory_order_acquire))
            {
                Activity_->Seal();
                return {};
            }
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        Activity_->CommitClose();
        return {};
    }

    inline auto NativeStream::ShutdownWrite()
        -> Net::awaitable<StreamProvider::ShutdownResult>
    {
        const auto Provider = weak_from_this().lock();
        if (!Provider || !Activity_)
        {
            return FailedShutdown(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Reservation = Activity_->BeginOperation(Provider);
        if (!Reservation)
        {
            return FailedShutdown(Reservation.error());
        }
        return ShutdownOwned(Provider, std::move(*Reservation));
    }

    inline auto NativeStream::ShutdownOwned(
        std::shared_ptr<NativeStream> Owner,
        NativeStreamActivity::Operation Reservation)
        -> Net::awaitable<StreamProvider::ShutdownResult>
    {
        (void)Reservation;
        if (!Owner || !Owner->State_)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto State = Owner->State_;
        co_await Net::dispatch(State->Executor, Net::use_awaitable);
        if (State->FinSenderDrained)
        {
            co_return StreamProvider::ShutdownResult{};
        }
        const auto Connection = Owner->Owner_.lock();
        if (!Connection)
        {
            if (State->LocalWriteFailure.Failed())
            {
                co_return std::unexpected(State->LocalWriteFailure);
            }
            co_return std::unexpected(Prism::Fault::FromNative(
                ToStdError(Prism::Error::BrokenPipe)));
        }
        NativeConnection::OperationReservation NativeReservation{Connection};
        if (!NativeReservation)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                ToStdError(Prism::Error::BrokenPipe)));
        }
        co_return co_await Connection->ShutdownStreamWrite(State);
    }

inline auto NativeDatagram::Receive(
        const std::span<std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        ErrorCode.clear();
        if (!State_ || Buffer.empty())
        {
            co_return 0;
        }
        const auto Provider = weak_from_this().lock();
        if (!Provider)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }
        co_await Net::dispatch(State_->Executor, Net::use_awaitable);
        const auto Connection = Provider->Owner_.lock();
        std::optional<NativeConnection::OperationReservation> Reservation;
        if (Connection)
        {
            Reservation.emplace(Connection);
        }
        while (true)
        {
            if (State_->Canceled)
            {
                State_->Canceled = false;
                ErrorCode = ToStdError(Prism::Error::Canceled);
                co_return 0;
            }
            if (auto Datagram = State_->Inbox.Dequeue())
            {
                const auto Length = std::min(Buffer.size(), Datagram->size());
                if (Length != 0U)
                {
                    std::memcpy(Buffer.data(), Datagram->data(), Length);
                }
                co_return Length;
            }
            if (State_->Closed)
            {
                ErrorCode = ToStdError(Prism::Error::BrokenPipe);
                co_return 0;
            }
            if (!Connection || !Reservation || !*Reservation)
            {
                ErrorCode = ToStdError(Prism::Error::BrokenPipe);
                co_return 0;
            }

            State_->Notify.reset();
            boost::system::error_code NotifyError;
            co_await State_->Notify.async_receive(Net::redirect_error(Net::use_awaitable, NotifyError));
            if (NotifyError && State_->Closed)
            {
                ErrorCode = ToStdError(Prism::Error::BrokenPipe);
                co_return 0;
            }
        }
    }

    inline auto NativeDatagram::Send(
        const std::span<const std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        ErrorCode.clear();
        if (!State_)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }
        const auto Provider = weak_from_this().lock();
        if (!Provider)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }
        co_await Net::dispatch(State_->Executor, Net::use_awaitable);
        const auto Connection = Provider->Owner_.lock();
        if (!Connection)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }
        NativeConnection::OperationReservation Reservation{Connection};
        if (!Reservation)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }
        if (State_->Closed)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }
        std::vector<std::byte> Copy(Buffer.begin(), Buffer.end());
        const auto Sent = co_await Connection->WriteDatagram(std::move(Copy), ErrorCode);
        co_return Sent;
    }

    inline auto NativeDatagram::Close() -> void
    {
        auto Connection = Owner_.lock();
        if (!State_ || !Connection)
        {
            return;
        }
        DatagramProviderActionOwner Action{Context_, std::move(Connection), State_};
        NativeConnection::OperationReservation Activity{Action.Connection};
        if (!Activity)
        {
            return;
        }
        const auto Executor = Action.State->Executor;
        Net::dispatch(Executor, [Action = std::move(Action), Activity = std::move(Activity)]() mutable
        {
            (void)Activity;
            CloseDatagramProvider(std::move(Action.Connection), std::move(Action.State));
        });
    }

    inline auto NativeDatagram::Cancel() -> void
    {
        auto Connection = Owner_.lock();
        if (!State_ || !Connection)
        {
            return;
        }
        DatagramProviderActionOwner Action{Context_, std::move(Connection), State_};
        NativeConnection::OperationReservation Activity{Action.Connection};
        if (!Activity)
        {
            return;
        }
        const auto Executor = Action.State->Executor;
        Net::dispatch(Executor, [Action = std::move(Action), Activity = std::move(Activity)]() mutable
        {
            (void)Activity;
            if (!Action.State->Closed)
            {
                Action.State->Canceled = true;
                (void)Action.State->Notify.try_send(boost::system::error_code{});
            }
        });
    }


} // namespace Prism::Quic::Detail
