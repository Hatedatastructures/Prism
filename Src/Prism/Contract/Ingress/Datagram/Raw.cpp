/** @file Raw.cpp @brief raw ingress generation 使用预约实现。 */
#include <Prism/Contract/Ingress/Datagram/Raw.hpp>

#include <expected>

namespace Prism::Contract
{
    auto RawDatagramIngressSnapshot::Binding::AcquireUse() const
        -> std::expected<Prism::Foundation::GenerationUseLease, Prism::Fault::Failure>
    {
        if (!UseState)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        return UseState->Acquire();
    }

    auto RawDatagramIngressSnapshot::AcquireUse() const
        -> std::expected<Prism::Foundation::GenerationUseLease, Prism::Fault::Failure>
    {
        if (!UseState_)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        return UseState_->Acquire();
    }
}
