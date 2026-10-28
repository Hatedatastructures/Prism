/** @file CarrierFailure.hpp @brief TLS carrier 协议错误映射声明。 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/Recognition/Candidate.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Composition::Recognition::Detail
{

    /** @brief 保留 carrier wire 错误的 category/value 与领域错误码。 */
    [[nodiscard]] auto FailureFromProtocolError(Prism::Error Value) noexcept
        -> Prism::Fault::Failure;

    auto SetCarrierFailure(
        Prism::Recognition::CarrierAcceptResult &Result,
        const Prism::Fault::Failure &Failure) -> void;

    [[nodiscard]] auto RetireCarrierInput(
        Prism::SharedTransmission Inbound,
        Prism::Fault::Failure Cause)
        -> boost::asio::awaitable<Prism::Fault::Failure>;

} // namespace Prism::Composition::Recognition::Detail
