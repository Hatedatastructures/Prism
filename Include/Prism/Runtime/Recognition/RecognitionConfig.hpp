/**
 * @file RecognitionConfig.hpp
 * @brief Recognition control, result, and transport cleanup contracts.
 */

#pragma once

#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Runtime/Recognition/Profile.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <system_error>
#include <vector>

namespace Prism::Recognition
{

    namespace Net = boost::asio;

    /**
     * @enum RecognitionControlEvent
     * @brief Caller-owned asynchronous recognition stop event.
     */
    enum class RecognitionControlEvent : std::uint8_t
    {
        Cancelled,
        TimedOut,
    };

    struct RecognizeResult;

    /**
     * @struct RecognitionControl
     * @brief Caller-owned cancellation and total-deadline checks.
     * @details The coordinator computes one effective total deadline and uses
     *          a fresh internal timer for each in-flight operation without
     *          resetting that deadline per candidate. A caller that owns a
     *          timer can expose its state via Cancelled and Deadline. Wait must
     *          be a repeatable factory; WaitCancellationSafe declares that the
     *          factory cooperates with CancelTransport so every losing race can
     *          complete.
     */
    struct RecognitionControl
    {
        using Clock = std::chrono::steady_clock;
        using WaitFn = std::function<Net::awaitable<RecognitionControlEvent>()>;
        using CancelFn = std::function<void()>;

        Clock::time_point Deadline{Clock::time_point::max()};
        std::function<bool()> Cancelled{};
        WaitFn Wait{};
        CancelFn CancelTransport{};
        // Wait 必须可重复创建，并能在取消钩子触发后收口。
        bool WaitCancellationSafe{false};

        [[nodiscard]] auto IsCancelled() const -> bool
        {
            return Cancelled && Cancelled();
        }

        [[nodiscard]] auto IsExpired(Clock::time_point Now = Clock::now()) const noexcept -> bool
        {
            return Deadline != Clock::time_point::max() && Now >= Deadline;
        }
    };

    struct ControlRaceRequest
    {
        RecognitionControl Control;
        RecognitionControl::Clock::time_point Deadline{RecognitionControl::Clock::time_point::max()};
    };

    namespace detail
    {

        template <typename T>
        struct ControlRaceResult
        {
            T Value{};
            RecognitionControlEvent Event{RecognitionControlEvent::Cancelled};
            bool Controlled{false};
        };

    } // namespace detail

    /**
     * @struct RecognizeResult
     * @brief 已编译 Profile 的候选、载体和取消结果。
     * @details 识别结果由接入阶段消费，协议工厂随后产生唯一正式数据面。
     */
    struct RecognizeResult
    {
        Prism::Contract::ProtocolType detected{Prism::Contract::ProtocolType::Unknown};
        SharedTransmission transport;
        std::vector<std::byte> preread;
        std::string scheme;
        bool success{false};

        RecognitionMode Mode{RecognitionMode::Configured};
        RecognitionStatus Status{RecognitionStatus::NoMatch};
        CandidateId Candidate{InvalidCandidate};
        std::string CandidateName;
        std::error_code Error{};
        bool Polluted{false};
        bool Cancelled{false};
        std::size_t ProbeBytes{0};
        std::uint16_t CryptoTrials{0};
        Prism::Fault::Code FaultCode{Prism::Fault::Code::Success};
        boost::system::error_code NativeError{};
        CarrierMetadata Carrier{};
    };

    struct ResultStatusRequest
    {
        RecognizeResult* Result{nullptr};
        RecognitionStatus Status{RecognitionStatus::NoMatch};
        std::error_code Error{};
        bool Polluted{false};
    };


} // namespace Prism::Recognition
