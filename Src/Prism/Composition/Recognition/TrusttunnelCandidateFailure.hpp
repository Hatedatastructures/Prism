/** @file TrusttunnelCandidateFailure.hpp @brief TrustTunnel 候选的私有失败映射声明。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/Recognition/Candidate.hpp>

namespace Prism::Composition::Recognition::Detail
{

    /** @brief 将协议完整失败原样映射到 Recognition owner 结果。 */
    auto SetTrusttunnelFailure(
        Prism::Recognition::CarrierAcceptResult &Result,
        const Prism::Fault::Failure &Failure) -> void;

} // namespace Prism::Composition::Recognition::Detail
