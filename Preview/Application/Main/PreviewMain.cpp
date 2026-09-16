/**
 * @file PreviewMain.cpp
 * @brief PrismPreview 独立启动入口。
 */

#include <Preview/Application/Application.hpp>

#include <filesystem>
#include <system_error>
#include <utility>

auto main(int Argc, char *Argv[]) -> int
{
    std::filesystem::path ConfigurationPath;
    if (Argc > 1)
    {
        ConfigurationPath = std::filesystem::path(Argv[1]);
    }
    else
    {
        std::error_code Error;
        auto ExecutablePath = std::filesystem::absolute(
            Argc > 0 && Argv[0] != nullptr ? std::filesystem::path(Argv[0]) :
                                                std::filesystem::path("PrismPreview.exe"),
            Error);
        if (Error || ExecutablePath.empty())
        {
            Error.clear();
            ExecutablePath = std::filesystem::current_path(Error) / "PrismPreview.exe";
        }
        ConfigurationPath = ExecutablePath.parent_path() / "PreviewConfiguration.json";
    }
    Preview::Application::Options Options;
    Options.ConfigurationPath = std::move(ConfigurationPath);
    Preview::Application::Application App(std::move(Options));
    return App.Run();
}
