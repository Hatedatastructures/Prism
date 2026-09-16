/**
 * @file ConfigurationGeneration.hpp
 * @brief 不可变 Preview 配置 generation。
 */
#pragma once

#include <Preview/Application/Configuration/PreviewConfiguration.hpp>
#include <Preview/Application/Configuration/ResolvedSecrets.hpp>
#include <Preview/Composition/Builtin/Snapshot.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>

#include <cstddef>
#include <memory>
#include <string_view>
#include <utility>

namespace Preview::Application::Configuration
{

    class GenerationBuilder;

    struct ConfigurationGenerationData final
    {
        Preview::GenerationId Id{};
        PreviewConfiguration Configuration{};
        Preview::Composition::Builtin::CapabilitySet Capabilities{};
        std::shared_ptr<const Preview::Composition::Builtin::BuiltinSnapshot> Builtins{};
        std::shared_ptr<const ResolvedSecrets> SecretStore{};
    };

    /** @brief 已校验、可被会话 pin 的配置 generation。 */
    class ConfigurationGeneration final
    {
    public:
        ConfigurationGeneration(const ConfigurationGeneration &) = delete;
        auto operator=(const ConfigurationGeneration &) -> ConfigurationGeneration & = delete;
        ConfigurationGeneration(ConfigurationGeneration &&) = delete;
        auto operator=(ConfigurationGeneration &&) -> ConfigurationGeneration & = delete;

        [[nodiscard]] auto Id() const noexcept -> Preview::GenerationId
        {
            return Id_;
        }

        [[nodiscard]] auto Generation() const noexcept -> Preview::GenerationId
        {
            return Id();
        }

        [[nodiscard]] auto Configuration() const noexcept -> const PreviewConfiguration &
        {
            return Configuration_;
        }

        [[nodiscard]] auto Capabilities() const noexcept
            -> Preview::Composition::Builtin::CapabilitySet
        {
            return Capabilities_;
        }

        [[nodiscard]] auto AvailableCapabilities() const noexcept
            -> Preview::Composition::Builtin::CapabilitySet
        {
            return Capabilities();
        }

        [[nodiscard]] auto Builtins() const noexcept
            -> const std::shared_ptr<const Preview::Composition::Builtin::BuiltinSnapshot> &
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

        const Preview::GenerationId Id_;
        const PreviewConfiguration Configuration_;
        const Preview::Composition::Builtin::CapabilitySet Capabilities_;
        const std::shared_ptr<const Preview::Composition::Builtin::BuiltinSnapshot> Builtins_;
        const std::shared_ptr<const ResolvedSecrets> SecretStore_;
    };

    using ConfigurationGenerationPtr = std::shared_ptr<const ConfigurationGeneration>;
    using SharedConfigurationGeneration = ConfigurationGenerationPtr;

} // namespace Preview::Application::Configuration
