/**
 * @file PreparedConfiguration.hpp
 * @brief 配置校验阶段到 generation 构造阶段的安全密钥交接。
 */
#pragma once

#include <Prism/Application/Configuration/PrismConfiguration.hpp>
#include <Prism/Application/Configuration/ResolvedSecrets.hpp>

#include <memory>
#include <utility>

namespace Prism::Application::Configuration
{

    class ConfigurationParser;
    class GenerationBuilder;

    namespace Detail
    {
        class SecretResolutionTransaction;
    } // namespace Detail

    class PreparedConfiguration final
    {
    public:
        PreparedConfiguration(const PreparedConfiguration &) = delete;
        auto operator=(const PreparedConfiguration &) -> PreparedConfiguration & = delete;
        PreparedConfiguration(PreparedConfiguration &&) noexcept;
        auto operator=(PreparedConfiguration &&) noexcept -> PreparedConfiguration &;
        ~PreparedConfiguration();

        [[nodiscard]] auto Configuration() const noexcept -> const PrismConfiguration &;

    private:
        friend class ConfigurationParser;
        friend class GenerationBuilder;

        PreparedConfiguration(PrismConfiguration Configuration,
                              std::unique_ptr<Detail::SecretResolutionTransaction> Resolution);
        [[nodiscard]] auto Resolution() noexcept -> Detail::SecretResolutionTransaction &;
        [[nodiscard]] auto TakeConfiguration() && -> PrismConfiguration;
        [[nodiscard]] auto TakeResolvedSecrets() && -> std::unique_ptr<ResolvedSecrets>;

        PrismConfiguration Configuration_;
        std::unique_ptr<Detail::SecretResolutionTransaction> Resolution_;
    };



    inline auto PreparedConfiguration::Configuration() const noexcept -> const PrismConfiguration &
    {
        return Configuration_;
    }

    inline auto PreparedConfiguration::TakeConfiguration() && -> PrismConfiguration
    {
        return std::move(Configuration_);
    }

} // namespace Prism::Application::Configuration
