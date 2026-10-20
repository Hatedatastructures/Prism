/** @file TlsCarrierHelpers.cpp @brief TLS carrier 共用失败和输入退休实现。 */

#include <Prism/Composition/Recognition/TlsCarrierHelpers.hpp>
#include <Prism/Composition/Recognition/TlsCarrierFailure.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <system_error>
#include <utility>

namespace Prism::Composition::Recognition
{
    namespace Detail
    {
        [[nodiscard]] auto FailureFromProtocolError(Prism::Error Value) noexcept
            -> Prism::Fault::Failure
        {
            if (Value == Prism::Error::None) return {};
            const auto Native = Prism::make_error_code(Value);
            return {Prism::Fault::ToCode(Native), static_cast<std::error_code>(Native)};
        }

        auto SetCarrierFailure(
            Core::CarrierAcceptResult &Result,
            const Prism::Fault::Failure &Failure) -> void
        {
            Result.Code = Failure.Code;
            Result.NativeError = Failure.Native;
        }

        [[nodiscard]] auto RetireCarrierInput(
            Prism::SharedTransmission Inbound,
            Prism::Fault::Failure Cause)
            -> Net::awaitable<Prism::Fault::Failure>
        {
            if (!Inbound) co_return Cause;
            auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(
                std::move(Inbound));
            if (!Prepared) co_return Cause;
            auto Admission = std::move(*Prepared);
            co_return co_await Admission.Retire(Cause);
        }
    } // namespace Detail
} // namespace Prism::Composition::Recognition
