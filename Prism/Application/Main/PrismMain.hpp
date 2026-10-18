/**
 * @file PrismMain.hpp
 * @brief Prism 独立启动入口。
 */

#pragma once

#include <Prism/Application/Application.hpp>
#include <Prism/Application/Main/ExecutablePath.hpp>

#include <filesystem>
#include <cctype>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace
{

    [[nodiscard]] auto ResolvePrismSecret(const std::string_view Reference)
        -> std::optional<std::string>
    {
        std::string Name{"PRISM_SECRET_"};
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
    }

} // namespace

auto main(int Argc, char *Argv[]) -> int
{
    const auto Executable = Prism::Application::Main::ExecutablePath();
    if (!Executable)
    {
        std::cerr << "无法确定当前 Prism 可执行文件位置，原生错误值："
                  << Executable.error().Native.value() << '\n';
        return EXIT_FAILURE;
    }
    std::filesystem::path ConfigurationPath;
    if (Argc > 1)
    {
        ConfigurationPath = std::filesystem::path(Argv[1]);
    }
    else
    {
        ConfigurationPath = Executable->parent_path() / "PrismConfiguration.json";
    }
    Prism::Application::Options Options;
    Options.ConfigurationPath = std::move(ConfigurationPath);
    Options.SecretResolver = ResolvePrismSecret;
    Options.OperationsWebDirectory = Executable->parent_path().parent_path() / "Web";
    Prism::Application::Application App(std::move(Options));
    return App.Run();
}
