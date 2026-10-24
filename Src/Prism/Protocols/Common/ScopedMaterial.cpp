/** @file ScopedMaterial.cpp @brief QUIC 凭据材料 pin 实现。 */

#include <Prism/Protocols/Common/Authentication/ScopedMaterial.hpp>

#include <utility>

namespace Prism::Protocols
{
    auto ScopedMaterial::Pin(
        std::shared_ptr<const Prism::Account::AccountBinding> Binding,
        const Prism::Account::CredentialMaterial& Material)
        -> std::expected<ScopedMaterial, Prism::Fault::Failure>
    {
        if (!Binding)
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        for (const auto& Entry : Binding->Materials()->Credentials())
        {
            if (&Entry == &Material) return ScopedMaterial(std::move(Binding), &Material);
        }
        return std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
    }
} // namespace Prism::Protocols
