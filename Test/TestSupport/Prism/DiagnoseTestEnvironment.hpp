/**
 * @file DiagnoseTestEnvironment.hpp
 * @brief 每个 backend 测试 executable 唯一的 Diagnose owner。
 */
#pragma once

#include <Prism/Application/DiagnoseRuntime.hpp>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>

namespace Prism::TestSupport
{

    class DiagnoseTestEnvironment final
    {
    public:
        explicit DiagnoseTestEnvironment(const std::string_view Name,
                                         const std::size_t QueueCapacity = 4096U)
        {
            const auto Stamp = std::chrono::steady_clock::now().time_since_epoch().count();
            Root_ = std::filesystem::temp_directory_path() /
                    ("prism-diagnose-" + std::string(Name) + "-" + std::to_string(Stamp));
            std::error_code Error;
            std::filesystem::create_directories(Root_, Error);
            Configuration_.Logging.Directory = Root_ / "logs";
            Configuration_.Logging.QueueCapacity = QueueCapacity;
            Configuration_.Logging.FileName = "prism.log";
        }

        DiagnoseTestEnvironment(const DiagnoseTestEnvironment &) = delete;
        auto operator=(const DiagnoseTestEnvironment &) -> DiagnoseTestEnvironment & = delete;

        ~DiagnoseTestEnvironment() noexcept
        {
            (void)Runtime_.FinalizeShutdown();
            std::error_code Error;
            std::filesystem::remove_all(Root_, Error);
        }

        [[nodiscard]] auto Configuration() noexcept
            -> Prism::Application::DiagnoseRuntimeConfiguration &
        {
            return Configuration_;
        }

        [[nodiscard]] auto Runtime() noexcept -> Prism::Application::DiagnoseRuntime &
        {
            return Runtime_;
        }

        [[nodiscard]] auto Root() const noexcept -> const std::filesystem::path &
        {
            return Root_;
        }

        auto Install() -> std::expected<void, Prism::Application::DiagnoseRuntimeError>
        {
            return Runtime_.Install(Configuration_);
        }

        /** @brief 重试 worker 短暂持有的 epoch registry gate，不吞掉其他准备错误。 */
        [[nodiscard]] auto PrepareEpochAfterRegistryContention(
            const Prism::Application::DiagnoseRuntimeConfiguration &Configuration)
            -> std::expected<Prism::Diagnose::RenderEpochPin,
                Prism::Application::DiagnoseRuntimeError>
        {
            constexpr auto MaxBusyRetries = 64U;
            for (auto Attempt = 0U; Attempt < MaxBusyRetries; ++Attempt)
            {
                auto Prepared = Runtime_.PrepareEpoch(Configuration);
                if (Prepared ||
                    Prepared.error().Code !=
                        Prism::Application::DiagnoseRuntimeErrorCode::ResourceUnavailable ||
                    Prepared.error().Message != "Diagnose epoch registry is busy")
                {
                    return Prepared;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
            return Runtime_.PrepareEpoch(Configuration);
        }

    private:
        std::filesystem::path Root_{};
        Prism::Application::DiagnoseRuntimeConfiguration Configuration_{};
        Prism::Application::DiagnoseRuntime Runtime_{};
    };

} // namespace Prism::TestSupport
