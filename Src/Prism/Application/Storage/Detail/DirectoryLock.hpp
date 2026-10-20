/** @file DirectoryLock.hpp @brief Application 存储目录单写锁的私有 OS 句柄。 */
#pragma once

#include <cstdint>
#include <filesystem>

namespace Prism::Application::Storage::Detail
{
    class DirectoryLock final
    {
    public:
        DirectoryLock() = default;
        DirectoryLock(const DirectoryLock&) = delete;
        auto operator=(const DirectoryLock&) -> DirectoryLock& = delete;
        ~DirectoryLock() noexcept;

        /** @brief 每实例仅允许一次成功打开；换目录前必须显式 Close。 */
        auto Open(const std::filesystem::path& Directory) -> void;
        auto Close() noexcept -> void;

    private:
#ifdef _WIN32
        static constexpr auto InvalidHandle = static_cast<std::uintptr_t>(-1);
        std::uintptr_t Handle_{InvalidHandle};
#else
        int Handle_{-1};
#endif
    };
}
