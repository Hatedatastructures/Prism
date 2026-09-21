/**
 * @file PreviewMain.cpp
 * @brief PrismPreview 独立启动入口。
 */

#include <Preview/Application/Application.hpp>

#include <filesystem>
#include <cctype>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
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
    Options.SecretResolver = [](const std::string_view Reference)
        -> std::optional<std::string>
    {
        std::string Name{"PRISM_PREVIEW_SECRET_"};
        Name.reserve(Name.size() + Reference.size());
        for (const auto Character : Reference)
        {
            const auto Byte = static_cast<unsigned char>(Character);
            if (std::isalnum(Byte) != 0)
            {
                Name.push_back(static_cast<char>(std::toupper(Byte)));
            }
            else
            {
                Name.push_back('_');
            }
        }
        const auto *Value = std::getenv(Name.c_str());
        if (Value == nullptr || *Value == '\0')
        {
            return std::nullopt;
        }
        return std::string(Value);
    };
    Preview::Application::Application App(std::move(Options));
    return App.Run();
}
