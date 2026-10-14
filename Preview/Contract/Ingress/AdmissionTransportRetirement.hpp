/** @file AdmissionTransportRetirement.hpp @brief 单条入站传输的真实 close/drain 回执。 */
#pragma once

#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>
#include <exception>
#include <expected>
#include <memory>
#include <new>
#include <system_error>

namespace Preview::Contract
{
    namespace Net = boost::asio;

    struct AdmissionRetirementResult final
    {
        bool Complete{true};
        Preview::Fault::Failure Error{};
    };

    inline auto PreserveAdmissionFailure(
        Preview::Fault::Failure &Primary,
        const Preview::Fault::Failure &Next) noexcept -> void
    {
        if (!Primary.Failed() && Next.Failed()) Primary = Next;
    }

    inline auto MergeAdmissionRetirementResult(
        AdmissionRetirementResult &Primary,
        const AdmissionRetirementResult &Next) noexcept -> void
    {
        Primary.Complete = Primary.Complete && Next.Complete;
        PreserveAdmissionFailure(Primary.Error, Next.Error);
    }

    [[nodiscard]] inline auto AdmissionFailureFromException(std::exception_ptr Exception) noexcept
        -> Preview::Fault::Failure
    {
        try
        {
            if (Exception) std::rethrow_exception(Exception);
        }
        catch (const boost::system::system_error &Error)
        {
            return Preview::Fault::FromNative(static_cast<std::error_code>(Error.code()));
        }
        catch (const std::system_error &Error)
        {
            return Preview::Fault::FromNative(Error.code());
        }
        catch (const std::bad_alloc &)
        {
            return {Preview::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)};
        }
        catch (...)
        {
            return {Preview::Fault::Code::GenericError};
        }
        return {Preview::Fault::Code::GenericError};
    }

    /** @brief 仅在 accepted control 不重发的前提下确认原 transport carrier 已实际退栈。 */
    [[nodiscard]] inline auto DrainAdmissionTransport(
        const Preview::SharedTransmission &Transport)
        -> Net::awaitable<AdmissionRetirementResult>
    {
        AdmissionRetirementResult Result;
        if (!Transport) co_return Result;
        std::shared_ptr<Preview::Contract::CarrierActivity> Activity;
        try
        {
            Activity = Transport->Activity();
            if (!Activity)
            {
                Result.Complete = false;
                Result.Error = {Preview::Fault::Code::Blocked};
                co_return Result;
            }
            Activity->Seal();
            const auto Drained = co_await Activity->Drain();
            if (!Drained) PreserveAdmissionFailure(Result.Error, Drained.error());
        }
        catch (...)
        {
            PreserveAdmissionFailure(Result.Error,
                AdmissionFailureFromException(std::current_exception()));
        }
        if (!Activity || !Activity->IsRetired())
        {
            Result.Complete = false;
            PreserveAdmissionFailure(Result.Error,
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        co_return Result;
    }

    /** @brief 对单条 carrier 只投递一次 Cancel/Close，随后按原 activity 回执重试 drain。 */
    [[nodiscard]] inline auto RetireAdmissionTransport(
        const Preview::SharedTransmission &Transport,
        bool &CancelAttempted,
        bool &CloseAttempted)
        -> Net::awaitable<AdmissionRetirementResult>
    {
        AdmissionRetirementResult Result;
        if (!Transport) co_return Result;
        if (!CancelAttempted)
        {
            CancelAttempted = true;
            try
            {
                const auto Cancel = Transport->Cancel();
                if (!Cancel) PreserveAdmissionFailure(Result.Error, Cancel.error());
            }
            catch (...)
            {
                PreserveAdmissionFailure(Result.Error,
                    AdmissionFailureFromException(std::current_exception()));
            }
        }
        if (!CloseAttempted)
        {
            CloseAttempted = true;
            try
            {
                const auto Closed = Transport->Close();
                if (!Closed) PreserveAdmissionFailure(Result.Error, Closed.error());
            }
            catch (...)
            {
                PreserveAdmissionFailure(Result.Error,
                    AdmissionFailureFromException(std::current_exception()));
            }
        }

        auto Drain = co_await DrainAdmissionTransport(Transport);
        MergeAdmissionRetirementResult(Result, Drain);
        co_return Result;
    }
}
