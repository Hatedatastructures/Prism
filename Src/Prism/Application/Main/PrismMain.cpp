/**
 * @file PrismMain.cpp
 * @brief Prism 独立进程入口与当前可执行路径解析。
 */

#include <Prism/Application/Application.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <array>
#include <cctype>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace Prism::Application::Main
{

    [[nodiscard]] auto ExecutablePath()
        -> std::expected<std::filesystem::path, Prism::Fault::Failure>
    {
#if defined(_WIN32)
        std::array<wchar_t, 32768> Buffer{};
        const auto Count = GetModuleFileNameW(nullptr, Buffer.data(),
            static_cast<DWORD>(Buffer.size()));
        if (Count == 0)
        {
            return std::unexpected(Prism::Fault::FromNative(std::error_code(
                static_cast<int>(GetLastError()), std::system_category())));
        }
        if (Count >= Buffer.size())
        {
            return std::unexpected(Prism::Fault::FromNative(
                std::make_error_code(std::errc::filename_too_long)));
        }
        return std::filesystem::path(std::wstring_view(Buffer.data(), Count));
#elif defined(__linux__)
        std::error_code Error;
        auto Result = std::filesystem::read_symlink("/proc/self/exe", Error);
        if (Error)
        {
            return std::unexpected(Prism::Fault::FromNative(Error));
        }
        if (!Result.is_absolute())
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }
        return Result;
#else
        return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Unsupported});
#endif
    }

} // namespace Prism::Application::Main

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
