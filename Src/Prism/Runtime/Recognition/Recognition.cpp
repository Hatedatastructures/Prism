/** @file Recognition.cpp @brief 基于 Profile 的正式识别入口实现。 */
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Runtime/Recognition/Types.hpp>

#include <Prism/Runtime/Recognition/ConfiguredMode.hpp>
#include <Prism/Runtime/Recognition/MixedTrialMode.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>

#include <utility>

namespace Prism::Recognition
{
    [[nodiscard]] auto ToStringView(RecognitionMode Mode) noexcept -> std::string_view
    {
        switch (Mode)
        {
        case RecognitionMode::Configured: return "Configured";
        case RecognitionMode::Deterministic: return "Deterministic";
        case RecognitionMode::MixedTrial: return "MixedTrial";
        }
        return "Unknown";
    }

    [[nodiscard]] auto ToStringView(RecognitionStatus Status) noexcept -> std::string_view
    {
        switch (Status)
        {
        case RecognitionStatus::Accepted: return "accepted";
        case RecognitionStatus::NoMatch: return "no_match";
        case RecognitionStatus::Ambiguous: return "ambiguous";
        case RecognitionStatus::BudgetExceeded: return "budget_exceeded";
        case RecognitionStatus::TimedOut: return "timed_out";
        case RecognitionStatus::EndOfStream: return "end_of_stream";
        case RecognitionStatus::IoError: return "io_error";
        case RecognitionStatus::Polluted: return "polluted";
        }
        return "unknown";
    }

    auto DeterministicMode::Recognize(SharedTransmission Inbound, ProbeBuffer& Buffer,
        RecognitionControl Control) -> Net::awaitable<RecognizeResult>
    {
        if (!Profile_ || Profile_->Mode() != RecognitionMode::Deterministic)
        {
            co_return RecognizeResult{};
        }
        co_return co_await Coordinator_.Recognize(
            std::move(Inbound), Buffer, std::move(Control));
    }

    auto Pipeline::Recognize(SharedTransmission Transport) -> Net::awaitable<RecognizeResult>
    {
        if (!Profile_ || !Transport || !Bytes_)
        {
            if (Transport && !Bytes_)
            {
                (void)Transport->Close();
            }
            RecognizeResult Result;
            Result.Status = RecognitionStatus::IoError;
            Result.FaultCode = Prism::Fault::Code::InvalidArgument;
            co_return Result;
        }
        ProbeBuffer Buffer(Profile_->Budget().MaxProbeBytes, Bytes_);
        co_return co_await Recognize(std::move(Transport), Buffer, {});
    }

    auto Pipeline::Recognize(SharedTransmission Transport, ProbeBuffer& Buffer,
        RecognitionControl Control) -> Net::awaitable<RecognizeResult>
    {
        if (!Profile_ || !Transport || !Buffer.Bytes())
        {
            if (Transport && !Buffer.Bytes())
            {
                (void)Transport->Close();
            }
            RecognizeResult Result;
            Result.Status = RecognitionStatus::IoError;
            Result.FaultCode = Prism::Fault::Code::InvalidArgument;
            co_return Result;
        }
        if (Profile_->Mode() == RecognitionMode::Configured)
        {
            ConfiguredMode Mode(Profile_, Trace_);
            co_return co_await Mode.Recognize(std::move(Transport), Buffer, std::move(Control));
        }
        if (Profile_->Mode() == RecognitionMode::Deterministic)
        {
            DeterministicMode Mode(Profile_, Trace_);
            co_return co_await Mode.Recognize(std::move(Transport), Buffer, std::move(Control));
        }
        MixedTrialMode Mode(Profile_, Trace_);
        co_return co_await Mode.Recognize(std::move(Transport), Buffer, std::move(Control));
    }
}
