/** @file InnerProtocolDispatch.hpp @brief TLS 内层候选工厂的私有构造 seam。 */
#pragma once

#include <Prism/Composition/Recognition/CandidateModel.hpp>
#include <Prism/Contract/Ingress/StreamFactory.hpp>

#include <memory>
#include <vector>

namespace Prism::Composition::Recognition
{
    /** @brief 为 LayeredCandidate 的白盒合同测试与生产装配创建内层候选分派器。 */
    [[nodiscard]] auto MakeInnerProtocolDispatch(
        std::vector<std::shared_ptr<const CandidateInnerBinding>> Candidates)
        -> std::shared_ptr<Prism::Contract::StreamFactory>;
}
