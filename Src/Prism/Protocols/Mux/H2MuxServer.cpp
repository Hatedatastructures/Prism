/** @file H2MuxServer.cpp @brief H2Mux 连接根会话所有者实现。 */
#include <Prism/Protocols/Mux/H2Mux/Http2Server.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <new>
#include <span>
#include <system_error>
#include <utility>

namespace Prism::Mux::H2Mux
{

    Http2Server::Http2Server(Prism::SharedTransmission Inbound, const std::size_t MaxStreams)
        : State_(std::make_shared<Http2State>(std::move(Inbound), MaxStreams))
    {
        State_->Session = std::make_shared<Prism::Http2::Session>(State_->Strand, true);
        const auto WeakState = std::weak_ptr<Http2State>(State_);
        State_->Session->OnHeaders = [WeakState](
            const std::int32_t Id,
            const Prism::Http2::HeaderList &Headers,
            const bool EndStream)
        {
            if (const auto State = WeakState.lock()) State->OnHeaders(Id, Headers, EndStream);
        };
        State_->Session->OnData = [WeakState](
            const std::int32_t Id, const std::span<const std::byte> Data)
        {
            if (const auto State = WeakState.lock()) State->OnData(Id, Data);
        };
        State_->Session->OnStreamClose = [WeakState](
            const Prism::Http2::StreamReceiveClosure &Closure)
        {
            if (const auto State = WeakState.lock()) State->OnRemoteClose(Closure);
        };
    }

    auto Http2Server::Run()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        struct RunCompletionGuard final
        {
            std::shared_ptr<Http2State> State;
            bool Published{false};

            auto Publish() noexcept -> void
            {
                if (Published) return;
                Published = true;
                State->NotifyRunCompleted();
            }

            ~RunCompletionGuard() noexcept { Publish(); }
        } Completion{State_};

        const auto Started = State_->StartRetirementPump();
        if (!Started)
        {
            State_->RecordFailure(Started.error());
            State_->Close();
        }
        else
        {
            try
            {
                const auto LoopResult = co_await RunLoop();
                if (!LoopResult)
                {
                    const auto Failure = LoopResult.error();
                    if (Failure.Code != Prism::Fault::Code::Canceled ||
                        !State_->CloseRequested.load(std::memory_order_acquire))
                        State_->RecordConnectionTerminal(Failure);
                    State_->RecordCloseCancellation(Failure);
                }
            }
            catch (const boost::system::system_error &Exception)
            {
                const auto Failure = Prism::Fault::FromNative(
                    static_cast<std::error_code>(Exception.code()));
                State_->RecordConnectionTerminal(Failure);
                State_->RecordCloseCancellation(Failure);
            }
            catch (const std::system_error &Exception)
            {
                const auto Failure = Prism::Fault::FromNative(Exception.code());
                State_->RecordConnectionTerminal(Failure);
                State_->RecordCloseCancellation(Failure);
            }
            catch (const std::bad_alloc &)
            {
                const Prism::Fault::Failure Failure{
                    Prism::Fault::Code::ResourceUnavailable,
                    std::make_error_code(std::errc::not_enough_memory)};
                State_->RecordConnectionTerminal(Failure);
                State_->RecordFailure(Failure);
            }
            State_->Close();
        }
        (void)co_await State_->Drain();
        co_await Net::dispatch(State_->Strand, Net::use_awaitable);
        Completion.Publish();
        State_->RefreshRetirement();
        const auto Failure = State_->FirstFailure.Load();
        if (Failure.Failed()) co_return std::unexpected(Failure);
        if (!State_->Retired.load(std::memory_order_acquire))
        {
            const auto CloseFailure = State_->CloseCancellation.Load();
            if (CloseFailure.Failed()) co_return std::unexpected(CloseFailure);
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto Http2Server::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Drained = co_await State_->Drain();
        if (Drained) co_return Drained;
        co_await Net::dispatch(State_->Strand, Net::use_awaitable);
        if (!State_->RetirementPumpStarted)
        {
            State_->RecordFailure(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (State_->RunCompleted.load(std::memory_order_acquire))
            co_return co_await State_->Drain();

        co_await State_->WaitForRunCompletion();
        co_await Net::dispatch(State_->Strand, Net::use_awaitable);
        if (!State_->RunCompleted.load(std::memory_order_acquire))
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        co_return co_await State_->Drain();
    }

    auto Http2Server::RunLoop()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::dispatch(State_->Strand, Net::use_awaitable);
        const auto MaxAdvertised = (std::min)(
            State_->MaxStreams,
            static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()));
        const std::array<Prism::Http2::SettingsEntry, 1> Settings{{
            {Prism::Http2::SettingsMaxConcurrentStreams,
             static_cast<std::uint32_t>(MaxAdvertised)}}};
        State_->Session->SendSettings(Settings);
        const auto SettingsFlush = co_await State_->Flush();
        if (SettingsFlush.CloseCanceled)
        {
            State_->RecordCloseCancellation(SettingsFlush.Error);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        if (!SettingsFlush)
        {
            co_return std::unexpected(SettingsFlush.Error);
        }
        std::array<std::byte, 16 * 1024> Buffer{};
        while (!State_->Closed && State_->Raw && State_->Raw->IsOpen())
        {
            const auto Part = co_await State_->Raw->ReadSome(Buffer);
            co_await Net::dispatch(State_->Strand, Net::use_awaitable);
            if (Part.Bytes > Buffer.size())
            {
                co_return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::InvalidArgument, Part.Failure.Native});
            }
            bool CloseCancellation = false;
            if (Part.Bytes != 0U)
            {
                std::error_code FeedError;
                const auto Fed = State_->Session->Feed(
                    std::span<const std::byte>(Buffer.data(), Part.Bytes), FeedError);
                if (!Fed)
                {
                    co_return std::unexpected(FeedError
                        ? Prism::Fault::FromNative(FeedError)
                        : Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
                }
                State_->ApplyRefusedStreams();
                const auto Flushed = co_await State_->Flush();
                if (Flushed.CloseCanceled)
                {
                    State_->RecordCloseCancellation(Flushed.Error);
                    CloseCancellation = true;
                }
                else if (!Flushed)
                {
                    co_return std::unexpected(Flushed.Error);
                }
            }
            if (Part.Failure.Failed())
            {
                if (Part.Failure.Code == Prism::Fault::Code::Eof)
                {
                    State_->RecordConnectionTerminal(Part.Failure);
                    break;
                }
                // 仅根 owner 的 Close 会取消 Raw 读；标记先于 strand 上的 Close 发布。
                if (Part.Failure.Code != Prism::Fault::Code::Canceled ||
                    !State_->CloseRequested.load(std::memory_order_acquire))
                    co_return std::unexpected(Part.Failure);
                break;
            }
            if (Part.Bytes != 0U && CloseCancellation)
            {
                break;
            }
            if (Part.Bytes == 0U)
            {
                State_->RecordConnectionTerminal(
                    Prism::Fault::Failure{Prism::Fault::Code::Eof});
                break;
            }
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto Http2Server::AcceptStream() -> Net::awaitable<std::shared_ptr<Http2Stream>>
    {
        co_await Net::dispatch(State_->Strand, Net::use_awaitable);
        while (!State_->Closed)
        {
            if (!State_->Incoming.empty())
            {
                auto Stream = std::move(State_->Incoming.front());
                State_->Incoming.pop_front();
                Stream->MarkIncomingPending(false);
                co_return Stream;
            }
            State_->Notify.reset();
            co_await State_->Notify.async_receive(Net::use_awaitable);
            co_await Net::dispatch(State_->Strand, Net::use_awaitable);
        }
        co_return nullptr;
    }

    auto Http2Server::Close() -> void
    {
        auto State = State_;
        State->CloseRequested.store(true, std::memory_order_release);
        Net::dispatch(State->Strand, [State] { State->Close(); });
    }

    auto Http2Server::Executor() const -> Net::any_io_executor
    {
        return State_->Strand;
    }

} // namespace Prism::Mux::H2Mux
