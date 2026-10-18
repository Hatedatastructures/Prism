/** @file ExecutablePath.hpp @brief 由宿主系统取得当前生产入口的实际文件位置。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <array>
#include <expected>
#include <filesystem>
#include <string_view>
#include <system_error>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace Prism::Application::Main
{
    /**
     * @brief 在启动冷路径取得可执行文件绝对路径，失败保留平台原生错误。
     * @details 返回值独占路径；函数无 executor、取消或半关闭，不持有文件句柄。
     *          配置与资源路径由入口根据此路径派生；不根据工作目录或 argv 猜测另一个入口。
     */
    [[nodiscard]] inline auto ExecutablePath()
        -> std::expected<std::filesystem::path, Prism::Fault::Failure>
    {
#if defined(_WIN32)
        std::array<wchar_t, 32768> Buffer{};
        const auto Count = GetModuleFileNameW(nullptr, Buffer.data(), static_cast<DWORD>(Buffer.size()));
        if (Count == 0)
            return std::unexpected(Prism::Fault::FromNative(
                std::error_code(static_cast<int>(GetLastError()), std::system_category())));
        if (Count >= Buffer.size())
            return std::unexpected(Prism::Fault::FromNative(
                std::make_error_code(std::errc::filename_too_long)));
        return std::filesystem::path(std::wstring_view(Buffer.data(), Count));
#elif defined(__linux__)
        std::error_code Error;
        auto Result = std::filesystem::read_symlink("/proc/self/exe", Error);
        if (Error) return std::unexpected(Prism::Fault::FromNative(Error));
        if (!Result.is_absolute())
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
        return Result;
#else
        return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Unsupported});
#endif
    }
}
