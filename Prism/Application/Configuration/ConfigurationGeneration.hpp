/**
 * @file ConfigurationGeneration.hpp
 * @brief 不可变 Prism 配置 generation。
 */
#pragma once

#include <Prism/Application/Configuration/PrismConfiguration.hpp>
#include <Prism/Application/Configuration/ResolvedSecrets.hpp>
#include <Prism/Composition/Builtin/Snapshot.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>

#include <cstddef>
#include <memory>
#include <string_view>
#include <utility>

namespace Prism::Application::Configuration
{

    class GenerationBuilder;

    struct ConfigurationGenerationData final
    {
        Prism::GenerationId Id{};
        PrismConfiguration Configuration{};
        Prism::Composition::Builtin::CapabilitySet Capabilities{};
        std::shared_ptr<const Prism::Composition::Builtin::BuiltinSnapshot> Builtins{};
        std::shared_ptr<const ResolvedSecrets> SecretStore{};
    };

    /** @brief 已校验、可被会话 pin 的配置 generation。 */
    class ConfigurationGeneration final : public Prism::Foundation::GenerationLifetime
    {
    public:
        ConfigurationGeneration(const ConfigurationGeneration &) = delete;
        auto operator=(const ConfigurationGeneration &) -> ConfigurationGeneration & = delete;
        ConfigurationGeneration(ConfigurationGeneration &&) = delete;
        auto operator=(ConfigurationGeneration &&) -> ConfigurationGeneration & = delete;

        [[nodiscard]] auto Id() const noexcept -> Prism::GenerationId override
        {
            return Id_;
        }

        [[nodiscard]] auto Generation() const noexcept -> Prism::GenerationId
        {
            return Id();
        }

        [[nodiscard]] auto Configuration() const noexcept -> const PrismConfiguration &
        {
            return Configuration_;
        }

        [[nodiscard]] auto Capabilities() const noexcept
            -> Prism::Composition::Builtin::CapabilitySet
        {
            return Capabilities_;
        }

        [[nodiscard]] auto AvailableCapabilities() const noexcept
            -> Prism::Composition::Builtin::CapabilitySet
        {
            return Capabilities();
        }

        [[nodiscard]] auto Builtins() const noexcept
            -> const std::shared_ptr<const Prism::Composition::Builtin::BuiltinSnapshot> &
        {
            return Builtins_;
        }

        /**
         * @brief 查找 generation 持有的解析秘密。
         * @param Reference SecretRef 名称
         * @return 只读秘密字节；未找到时为空视图
         */
        [[nodiscard]] auto LookupSecret(std::string_view Reference) const
            -> ResolvedSecrets::View
        {
            return SecretStore_ ? SecretStore_->Lookup(Reference) : ResolvedSecrets::View{};
        }

    private:
        friend class GenerationBuilder;

        explicit ConfigurationGeneration(ConfigurationGenerationData Data)
            : Id_(Data.Id),
              Configuration_(std::move(Data.Configuration)),
              Capabilities_(Data.Capabilities),
              Builtins_(std::move(Data.Builtins)),
              SecretStore_(std::move(Data.SecretStore))
        {
        }

        const Prism::GenerationId Id_;
        const PrismConfiguration Configuration_;
        const Prism::Composition::Builtin::CapabilitySet Capabilities_;
        const std::shared_ptr<const Prism::Composition::Builtin::BuiltinSnapshot> Builtins_;
        const std::shared_ptr<const ResolvedSecrets> SecretStore_;
    };

    using ConfigurationGenerationPtr = std::shared_ptr<const ConfigurationGeneration>;
    using SharedConfigurationGeneration = ConfigurationGenerationPtr;

} // namespace Prism::Application::Configuration
