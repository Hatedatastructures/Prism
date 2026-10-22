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

    private:
        std::filesystem::path Root_{};
        Prism::Application::DiagnoseRuntimeConfiguration Configuration_{};
        Prism::Application::DiagnoseRuntime Runtime_{};
    };

} // namespace Prism::TestSupport
