/** @file Relay.cpp @brief 有界双向中继状态、泵循环与运行入口。 */
#include <Prism/Net/Relay/Relay.hpp>
#include <Prism/Net/Services/StreamRelay.hpp>
#include <Prism/Contract/Services/FirstTransferObserver.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Network::Relay
{
    namespace
    {
        class RelayState final
        {
        public:
            RelayState(Request Value, std::array<Memory::OwnedBytes, 2> Storage)
                : Input(std::move(Value)), Buffers(std::move(Storage)),
                  Executor(Net::make_strand(Input.Inbound->Executor())), Idle(Executor)
            {
            }

            auto Record(const std::size_t Direction, Fault::Failure Failure) noexcept -> void
            {
                if (Failure.Succeeded()) return;
                if (Output.DirectionFailure[Direction].Succeeded())
                {
                    Output.DirectionFailure[Direction] = Failure;
                }
                if (Output.Failure.Succeeded() || Output.Failure.Code == Fault::Code::Canceled)
                {
                    Output.Failure = Failure;
                }
            }

            auto Close() -> void
            {
                if (Closed) return;
                Closed = true;
                CloseCarrier(Input.Inbound, 0);
                CloseCarrier(Input.Outbound, 1);
                (void)Idle.cancel();
            }

            auto FinishPump() -> void
            {
                ++Completed;
                if (Completed == 2) (void)Idle.cancel();
            }

            auto Touch() -> void
            {
                if (Input.IdleTimeout.count() > 0)
                {
                    Idle.expires_after(Input.IdleTimeout);
                }
            }

            [[nodiscard]] auto Source(const std::size_t Direction) const
                -> SharedTransmission
            {
                return Direction == 0 ? Input.Inbound : Input.Outbound;
            }

            [[nodiscard]] auto Destination(const std::size_t Direction) const
                -> SharedTransmission
            {
                return Direction == 0 ? Input.Outbound : Input.Inbound;
            }

            auto ReportFirstTransfer(const std::size_t Direction) noexcept -> void
            {
                if (Direction >= FirstTransferReported.size() ||
                    FirstTransferReported[Direction] || !Input.FirstTransfer)
                {
                    return;
                }
                FirstTransferReported[Direction] = true;
                Input.FirstTransfer->OnFirstTransfer(Direction);
            }

            Request Input;
            std::array<Memory::OwnedBytes, 2> Buffers;
            Net::strand<Net::any_io_executor> Executor;
            Net::steady_timer Idle;
            Result Output;
            std::size_t Completed{0};
            bool Closed{false};
            std::array<bool, 2> FirstTransferReported{};

        private:
            auto CloseCarrier(const SharedTransmission &Carrier,
                              const std::size_t Direction) -> void
            {
                const auto Cancel = Carrier->Cancel();
                if (!Cancel) Record(Direction, Cancel.error());
                const auto Close = Carrier->Close();
                if (!Close) Record(Direction, Close.error());
            }
        };

        [[nodiscard]] auto Flush(const std::shared_ptr<RelayState> Owner,
                                 const std::size_t Direction,
                                 const std::size_t Size) -> Net::awaitable<bool>
        {
            std::size_t Offset = 0;
            const auto Buffer = Owner->Buffers[Direction].Bytes();
            while (Offset < Size)
            {
                const auto Part = co_await Owner->Destination(Direction)->WriteSome(
                    Buffer.subspan(Offset, Size - Offset));
                if (Part.Bytes > Size - Offset)
                {
                    Owner->Record(Direction, {Fault::Code::InvalidArgument});
                    Owner->Close();
                    co_return false;
                }
                Offset += Part.Bytes;
                Owner->Output.Total[Direction] += Part.Bytes;
                if (Part.Bytes != 0U) Owner->ReportFirstTransfer(Direction);
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

        [[nodiscard]] auto Pump(const std::shared_ptr<RelayState> Owner,
                                const std::size_t Direction) -> Net::awaitable<void>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            while (!Owner->Closed)
            {
                auto Buffer = Owner->Buffers[Direction].WritableBytes();
                const auto Part = co_await Owner->Source(Direction)->ReadSome(Buffer);
                if (Part.Bytes > Buffer.size())
                {
                    Owner->Record(Direction, {Fault::Code::InvalidArgument});
                    Owner->Close();
                    break;
                }
                if (Part.Bytes != 0 && !co_await Flush(Owner, Direction, Part.Bytes)) break;
                if (Part.Failure.Code == Fault::Code::Eof)
                {
                    const auto Shutdown = co_await Owner->Destination(Direction)->WriteShutdown();
                    if (!Shutdown)
                    {
                        Owner->Record(Direction, Shutdown.error());
                        Owner->Close();
                    }
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

        [[nodiscard]] auto WaitIdle(const std::shared_ptr<RelayState> Owner)
            -> Net::awaitable<void>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            while (!Owner->Closed && Owner->Completed != 2)
            {
                boost::system::error_code Error;
                co_await Owner->Idle.async_wait(
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error == Net::error::operation_aborted)
                {
                    const auto Cancellation = co_await Net::this_coro::cancellation_state;
                    if (Cancellation.cancelled() != Net::cancellation_type::none)
                    {
                        Owner->Close();
                    }
                    continue;
                }
                if (Error)
                {
                    Owner->Record(0, Fault::FromNative(static_cast<std::error_code>(Error)));
                }
                else
                {
                    Owner->Record(0, {Fault::Code::Timeout});
                }
                Owner->Close();
            }
        }

        [[nodiscard]] auto Reject(Request Input, Fault::Failure Failure)
            -> Net::awaitable<Result>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            Result Output{.Failure = Failure};
            std::array<SharedTransmission, 2> Carriers{
                std::move(Input.Inbound), std::move(Input.Outbound)};
            for (std::size_t Direction = 0; Direction < Carriers.size(); ++Direction)
            {
                const auto &Carrier = Carriers[Direction];
                if (!Carrier) continue;
                const auto Close = Carrier->Close();
                if (!Close)
                {
                    Output.DirectionFailure[Direction] = Close.error();
                    Output.Failure = Close.error();
                    continue;
                }
                auto Activity = Carrier->Activity();
                if (!Activity)
                {
                    Output.DirectionFailure[Direction] = {Fault::Code::Blocked};
                    Output.Failure = {Fault::Code::Blocked};
                    continue;
                }
                const auto DrainResult = co_await Activity->Drain();
                if (!DrainResult)
                {
                    Output.DirectionFailure[Direction] = DrainResult.error();
                    Output.Failure = DrainResult.error();
                }
            }
            co_return Output;
        }

        [[nodiscard]] auto RunOnExecutor(const std::shared_ptr<RelayState> Owner)
            -> Net::awaitable<Result>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            Owner->Touch();
            using Net::experimental::awaitable_operators::operator&&;
            auto Upload = Net::co_spawn(
                Owner->Executor, Pump(Owner, 0), Net::use_awaitable);
            auto Download = Net::co_spawn(
                Owner->Executor, Pump(Owner, 1), Net::use_awaitable);
            if (Owner->Input.IdleTimeout.count() > 0)
            {
                auto Idle = Net::co_spawn(
                    Owner->Executor, WaitIdle(Owner), Net::use_awaitable);
                co_await (std::move(Upload) && std::move(Download) && std::move(Idle));
            }
            else
            {
                co_await (std::move(Upload) && std::move(Download));
            }
            Owner->Close();
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            const auto First = co_await Owner->Input.Inbound->Activity()->Drain();
            if (!First) Owner->Record(0, First.error());
            const auto Second = co_await Owner->Input.Outbound->Activity()->Drain();
            if (!Second) Owner->Record(1, Second.error());
            co_return std::move(Owner->Output);
        }
    }

    auto Run(Request Input) -> Net::awaitable<Result>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        if (!Input.Inbound || !Input.Outbound)
        {
            co_return co_await Reject(std::move(Input), {Fault::Code::BadGateway});
        }
        if (!Input.Bytes)
        {
            co_return co_await Reject(std::move(Input),
                                      {Fault::Code::ResourceUnavailable});
        }
        if (Input.BufferSize < 2 || Input.BufferSize > Input.Bytes->BlockSize())
        {
            co_return co_await Reject(std::move(Input), {Fault::Code::InvalidArgument});
        }
        auto Upload = Input.Bytes->TryAcquire(Input.BufferSize);
        if (!Upload) co_return co_await Reject(std::move(Input), Upload.error());
        auto Download = Input.Bytes->TryAcquire(Input.BufferSize);
        if (!Download) co_return co_await Reject(std::move(Input), Download.error());
        std::array<Memory::OwnedBytes, 2> Buffers{
            std::move(*Upload), std::move(*Download)};
        auto Owner = std::make_shared<RelayState>(std::move(Input), std::move(Buffers));
        co_return co_await Net::co_spawn(
            Owner->Executor, RunOnExecutor(Owner), Net::use_awaitable);
    }
}

namespace Prism::Network
{
    StreamRelayService::StreamRelayService(StreamRelayOptions Options)
        : Options_(std::move(Options))
    {
    }

    auto StreamRelayService::Run(Prism::Contract::StreamRelayRequest Request)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return RunOwned(Options_, std::move(Request));
    }

    auto StreamRelayService::RunOwned(
        StreamRelayOptions Options,
        Prism::Contract::StreamRelayRequest Request)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Prism::Foundation::TrafficObservation Observation{
            Options.Traffic,
            Prism::Foundation::TrafficEvent{
                .Generation = Request.Metadata.TaskIdentity.Generation,
                .Worker = Request.Metadata.TaskIdentity.WorkerId,
                .Session = Request.Metadata.TaskIdentity.SessionId,
                .Stream = Request.Metadata.TaskIdentity.StreamId,
                .Task = Request.Metadata.TaskIdentity.TaskId,
                .Account = Request.AccountId}};
        Observation.Transfer(Request.InitialUploadBytes,
            Prism::Foundation::TrafficObservation::Direction::Upload);
        const auto Result = co_await Prism::Network::Relay::Run(
            {std::move(Request.Inbound), std::move(Request.Outbound),
             Options.BufferSize, Options.IdleTimeout, Observation, Options.Bytes});
        Observation.Complete(Result.Failure);
        if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }
}
