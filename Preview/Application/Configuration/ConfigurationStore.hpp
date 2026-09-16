/**
 * @file ConfigurationStore.hpp
 * @brief 当前配置 generation 的原子快照存储。
 */
#pragma once

#include <Preview/Application/Configuration/ConfigurationError.hpp>
#include <Preview/Application/Configuration/ConfigurationGeneration.hpp>

#include <atomic>
#include <expected>
#include <utility>

namespace Preview::Application::Configuration
{

    /** @brief 保存当前 generation，并为会话提供共享 pin。 */
    class ConfigurationStore final
    {
    public:
        explicit ConfigurationStore(ConfigurationGenerationPtr Initial = {})
            : Current_(std::move(Initial))
        {
        }

        [[nodiscard]] auto Current() const noexcept -> ConfigurationGenerationPtr
        {
            return Current_.load(std::memory_order_acquire);
        }

        /** @brief 会话取得共享持有权后，旧 generation 会一直存活到会话结束。 */
        [[nodiscard]] auto Pin() const noexcept -> ConfigurationGenerationPtr
        {
            return Current();
        }

        [[nodiscard]] auto Publish(ConfigurationGenerationPtr Generation)
            -> std::expected<void, ConfigurationError>
        {
            if (!Generation || !Generation->Id())
            {
                return std::unexpected(MakeConfigurationError(
                    ConfigurationErrorCode::InvalidGeneration,
                    "Generation",
                    "a non-empty generation with a non-zero id is required"));
            }

            auto CurrentGeneration = Current();
            while (true)
            {
                if (CurrentGeneration && CurrentGeneration->Id() >= Generation->Id())
                {
                    return std::unexpected(MakeConfigurationError(
                        ConfigurationErrorCode::PublishConflict,
                        "Generation.Id",
                        "generation id must increase monotonically"));
                }
                if (Current_.compare_exchange_weak(CurrentGeneration,
                                                   Generation,
                                                   std::memory_order_release,
                                                   std::memory_order_acquire))
                {
                    return {};
                }
            }
        }

    private:
        std::atomic<ConfigurationGenerationPtr> Current_{};
    };

} // namespace Preview::Application::Configuration
