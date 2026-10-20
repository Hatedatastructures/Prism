/**
 * @file Http2State.hpp
 * @brief H2Mux HTTP/2 会话的并发准入、共享传输及流退休 owner。
 */
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>

namespace Prism::Mux::H2Mux
{
    class Http2Stream;

    struct Http2State final : std::enable_shared_from_this<Http2State>
    {
        using FlushChannel = Net::experimental::channel<void(boost::system::error_code)>;
        using DrainChannel = Net::experimental::concurrent_channel<void(boost::system::error_code)>;
        using StreamDrainChannel = Net::experimental::concurrent_channel<void(boost::system::error_code)>;
        using Failure = Prism::Fault::Failure;

        struct FlushResult final
        {
            Failure Error;
            bool CloseCanceled{false};

            [[nodiscard]] explicit operator bool() const noexcept
            {
                return Error.Succeeded();
            }

            [[nodiscard]] auto operator!() const noexcept -> bool
            {
                return Error.Failed();
            }
        };

        Http2State(Prism::SharedTransmission RawValue, const std::size_t MaxStreamsValue);

        Net::strand<Net::any_io_executor> Strand;
        Prism::SharedTransmission Raw;
        const std::size_t MaxStreams;
        std::shared_ptr<Prism::Http2::Session> Session;
        Net::experimental::channel<void(boost::system::error_code)> Notify;
        Net::experimental::channel<void(boost::system::error_code)> RetirementNotify;
        StreamDrainChannel StreamDrainNotify;
        Net::experimental::channel<void(boost::system::error_code)> RunCompletionNotify;
        std::shared_ptr<DrainChannel> DrainGate;
        std::shared_ptr<FlushChannel> FlushGate;
        std::deque<std::shared_ptr<Http2Stream>> Incoming;
        std::map<std::int32_t, std::shared_ptr<Http2Stream>> Streams;
        std::deque<std::int32_t> DeferredRefusedStreams;
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Tasks;
        Prism::Lifecycle::TaskIdentity Identity;
        Prism::Fault::FailureState FirstFailure;
        Prism::Fault::FailureState CloseCancellation;
        Prism::Fault::FailureState ConnectionTerminal;
        std::atomic<bool> CloseRequested{false};
        bool Closed{false};
        bool RetirementPumpStarted{false};
        bool TasksDrained{false};
        bool RawDrained{false};
        std::atomic<bool> RunCompleted{false};
        std::atomic<bool> Retired{false};

        auto OnHeaders(std::int32_t StreamId, const Prism::Http2::HeaderList &Headers,
                       bool EndStream) -> void;
        auto OnData(std::int32_t StreamId, std::span<const std::byte> Data) -> void;
        auto OnRemoteClose(const Prism::Http2::StreamReceiveClosure &Closure) -> void;
        auto ApplyRefusedStreams() -> void;
        auto RemoveIncoming(std::int32_t StreamId) -> void;
        [[nodiscard]] auto IsIncoming(std::int32_t StreamId) const -> bool;
        auto StartRetirementPump() -> std::expected<void, Failure>;
        [[nodiscard]] auto RunRetirementPump() -> Net::awaitable<void>;
        auto QueueRetirement() -> void;
        auto NotifyStreamDrain() -> void;
        auto RetireStream(std::int32_t StreamId, const std::shared_ptr<Http2Stream> &Stream) -> void;
        auto RecordFailure(Failure Value) noexcept -> void;
        auto RecordConnectionTerminal(Failure Value) noexcept -> void;
        [[nodiscard]] auto ConnectionCloseFailure() const noexcept -> Failure;
        auto RecordCloseCancellation(Failure Value) noexcept -> void;
        [[nodiscard]] auto Drain() -> Net::awaitable<std::expected<void, Failure>>;
        [[nodiscard]] auto DrainStreams() -> Net::awaitable<bool>;
        [[nodiscard]] auto DrainRaw() -> Net::awaitable<bool>;
        auto RefreshRetirement() noexcept -> void;
        auto NotifyRunCompleted() noexcept -> void;
        [[nodiscard]] auto WaitForRunCompletion() -> Net::awaitable<void>;
        [[nodiscard]] auto WriteAll(std::span<const std::byte> Data)
            -> Net::awaitable<std::expected<void, Failure>>;
        [[nodiscard]] auto Flush() -> Net::awaitable<FlushResult>;
        auto Close() -> void;
    };
}
