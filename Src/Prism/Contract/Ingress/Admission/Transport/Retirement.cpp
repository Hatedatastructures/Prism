/** @file Retirement.cpp @brief 单条入站传输的真实 close/drain 实现。 */
#include <Prism/Contract/Ingress/Admission/Transport/Retirement.hpp>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <boost/system/system_error.hpp>

#include <exception>
#include <memory>
#include <new>
#include <system_error>

namespace Prism::Contract
{
    auto AdmissionFailureFromException(std::exception_ptr Exception) noexcept
        -> Prism::Fault::Failure
    {
        try
        {
            if (Exception) std::rethrow_exception(Exception);
        }
        catch (const boost::system::system_error &Error)
        {
            return Prism::Fault::FromNative(static_cast<std::error_code>(Error.code()));
        }
        catch (const std::system_error &Error)
        {
            return Prism::Fault::FromNative(Error.code());
        }
        catch (const std::bad_alloc &)
        {
            return {Prism::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)};
        }
        catch (...)
        {
            return {Prism::Fault::Code::GenericError};
        }
        return {Prism::Fault::Code::GenericError};
    }

    auto DrainAdmissionTransport(
        const Prism::SharedTransmission &Transport)
        -> Net::awaitable<AdmissionRetirementResult>
    {
        AdmissionRetirementResult Result;
        if (!Transport) co_return Result;
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity;
        try
        {
            Activity = Transport->Activity();
            if (!Activity)
            {
                Result.Complete = false;
                Result.Error = {Prism::Fault::Code::Blocked};
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
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_return Result;
    }

    auto RetireAdmissionTransport(
        const Prism::SharedTransmission &Transport,
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
