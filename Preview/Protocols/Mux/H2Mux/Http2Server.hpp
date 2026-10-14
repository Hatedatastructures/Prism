/** @file Http2Server.hpp @brief H2Mux HTTP/2 根 owner、并发准入和流实际退休。 */
#pragma once
#include <Preview/Protocols/Mux/H2Mux/Http2Dispatch.hpp>
#include <algorithm>
#include <array>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <new>
#include <system_error>
#include <utility>
namespace Preview::Mux::H2Mux
{
    class Http2Server final : public std::enable_shared_from_this<Http2Server>
    {
    public:
        Http2Server(Preview::SharedTransmission Inbound, const std::size_t MaxStreams)
            : State_(std::make_shared<Http2State>(std::move(Inbound), MaxStreams))
        {
            State_->Session = std::make_shared<Preview::Http2::Session>(State_->Strand, true);
            const auto WeakState = std::weak_ptr<Http2State>(State_);
            State_->Session->OnHeaders = [WeakState](
                const std::int32_t Id,
                const Preview::Http2::HeaderList &Headers,
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
                const Preview::Http2::StreamReceiveClosure &Closure)
            {
                if (const auto State = WeakState.lock()) State->OnRemoteClose(Closure);
            };
        }

        /** @brief 外部 frame scope await root；退出前关闭连接并等待所有实际 retirement。 */
        [[nodiscard]] auto Run()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
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
                    if (!LoopResult) State_->RecordFailure(LoopResult.error());
                }
                catch (const boost::system::system_error &Exception)
                {
                    State_->RecordFailure(Preview::Fault::FromNative(
                        static_cast<std::error_code>(Exception.code())));
                }
                catch (const std::system_error &Exception)
                {
                    State_->RecordFailure(Preview::Fault::FromNative(Exception.code()));
                }
                catch (const std::bad_alloc &)
                {
                    State_->RecordFailure(Preview::Fault::Failure{
                        Preview::Fault::Code::ResourceUnavailable,
                        std::make_error_code(std::errc::not_enough_memory)});
                }
                State_->Close();
            }
            const auto Drained = co_await State_->Drain();
            if (!Drained) State_->RecordFailure(Drained.error());
            co_await Net::dispatch(State_->Strand, Net::use_awaitable);
            State_->RunCompleted.store(true, std::memory_order_release);
            State_->RefreshRetirement();
            const auto Failure = State_->FirstFailure.Load();
            if (Failure.Failed()) co_return std::unexpected(Failure);
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        /** @brief 重试同一连接的物理 drain；失败首因与 Run 共用 FailureState。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_return co_await State_->Drain();
        }

        /** @brief 只读物理退休事实；历史 Failure 不阻止已排空 owner 退休。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            return State_ && State_->Retired.load(std::memory_order_acquire);
        }

        auto BindIdentity(Preview::Lifecycle::TaskIdentity Identity) -> void
        {
            State_->Identity = Identity;
        }

    private:
        /** @brief 在固定 strand 中读取 HTTP/2 frame 并保留首个传输或协议失败。 */
        [[nodiscard]] auto RunLoop()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_await Net::dispatch(State_->Strand, Net::use_awaitable);
            const auto MaxAdvertised = (std::min)(
                State_->MaxStreams,
                static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()));
            const std::array<Preview::Http2::SettingsEntry, 1> Settings{{
                {Preview::Http2::SettingsMaxConcurrentStreams,
                 static_cast<std::uint32_t>(MaxAdvertised)}}};
            State_->Session->SendSettings(Settings);
            const auto SettingsFlush = co_await State_->Flush();
            if (!SettingsFlush)
            {
                co_return std::unexpected(SettingsFlush.error());
            }
            std::array<std::byte, 16 * 1024> Buffer{};
            while (!State_->Closed && State_->Raw && State_->Raw->IsOpen())
            {
                const auto Part = co_await State_->Raw->ReadSome(Buffer);
                co_await Net::dispatch(State_->Strand, Net::use_awaitable);
                if (Part.Failure.Failed())
                {
                    if (!State_->Closed && Part.Failure.Code != Preview::Fault::Code::Eof &&
                        Part.Failure.Code != Preview::Fault::Code::Canceled)
                        co_return std::unexpected(Part.Failure);
                    break;
                }
                if (Part.Bytes == 0) break;
                std::error_code FeedError;
                const auto Fed = State_->Session->Feed(
                    std::span<const std::byte>(Buffer.data(), Part.Bytes), FeedError);
                if (!Fed)
                {
                    co_return std::unexpected(FeedError
                        ? Preview::Fault::FromNative(FeedError)
                        : Preview::Fault::Failure{Preview::Fault::Code::ProtocolError});
                }
                State_->ApplyRefusedStreams();
                const auto Flushed = co_await State_->Flush();
                if (!Flushed) co_return std::unexpected(Flushed.error());
            }
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

    public:
        /** @brief 交付下一个 admitted stream；超限请求只收到 REFUSED_STREAM。 */
        [[nodiscard]] auto AcceptStream() -> Net::awaitable<std::shared_ptr<Http2Stream>>
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

        auto Close() -> void
        {
            auto State = State_;
            Net::dispatch(State->Strand, [State] { State->Close(); });
        }

        auto Cancel() -> void { Close(); }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return State_->Strand;
        }

    private:
        std::shared_ptr<Http2State> State_;
    };
}
