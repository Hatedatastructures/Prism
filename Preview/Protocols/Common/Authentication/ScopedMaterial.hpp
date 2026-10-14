/** @file ScopedMaterial.hpp @brief 已选凭据材料的真实Binding pin，不创建另一份账户账本。 */
#pragma once
#include <Preview/Account/Binding.hpp>
#include <expected>
#include <memory>
namespace Preview::Protocols
{
    /** @brief 冷选择后持有原Binding与其中唯一材料；所有借用有效到本pin释放。 */
    class ScopedMaterial final
    {
    public:
        ScopedMaterial() = default;
        [[nodiscard]] static auto Pin(std::shared_ptr<const Preview::Account::AccountBinding> Binding,
            const Preview::Account::CredentialMaterial& Material)
            -> std::expected<ScopedMaterial, Preview::Fault::Failure>
        {
            if (!Binding) return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            for (const auto& Entry : Binding->Materials()->Credentials())
                if (&Entry == &Material) return ScopedMaterial(std::move(Binding), &Material);
            return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
        }
        explicit operator bool() const noexcept { return Binding_ && Material_; }
        [[nodiscard]] auto Binding() const noexcept -> const std::shared_ptr<const Preview::Account::AccountBinding>&
        { return Binding_; }
        [[nodiscard]] auto Material() const noexcept -> const Preview::Account::CredentialMaterial& { return *Material_; }
    private:
        ScopedMaterial(std::shared_ptr<const Preview::Account::AccountBinding> Binding,
            const Preview::Account::CredentialMaterial* Material) : Binding_(std::move(Binding)), Material_(Material) {}
        std::shared_ptr<const Preview::Account::AccountBinding> Binding_;
        const Preview::Account::CredentialMaterial* Material_{nullptr};
    };
}
