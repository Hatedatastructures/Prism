/** @file ScopedMaterial.hpp @brief 已选凭据材料的真实Binding pin，不创建另一份账户账本。 */
#pragma once
#include <Prism/Account/Binding.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <expected>
#include <memory>
#include <utility>
namespace Prism::Protocols
{
    /** @brief 冷选择后持有原Binding与其中唯一材料；所有借用有效到本pin释放。 */
    class ScopedMaterial final
    {
    public:
        ScopedMaterial() = default;
        [[nodiscard]] static auto Pin(std::shared_ptr<const Prism::Account::AccountBinding> Binding,
            const Prism::Account::CredentialMaterial& Material)
            -> std::expected<ScopedMaterial, Prism::Fault::Failure>;
        explicit operator bool() const noexcept { return Binding_ && Material_; }
        [[nodiscard]] auto Binding() const noexcept -> const std::shared_ptr<const Prism::Account::AccountBinding>&
        { return Binding_; }
        [[nodiscard]] auto Material() const noexcept -> const Prism::Account::CredentialMaterial& { return *Material_; }
    private:
        ScopedMaterial(std::shared_ptr<const Prism::Account::AccountBinding> Binding,
            const Prism::Account::CredentialMaterial* Material) : Binding_(std::move(Binding)), Material_(Material) {}
        std::shared_ptr<const Prism::Account::AccountBinding> Binding_;
        const Prism::Account::CredentialMaterial* Material_{nullptr};
    };
}
