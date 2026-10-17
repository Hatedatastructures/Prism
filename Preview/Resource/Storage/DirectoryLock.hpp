/** @file DirectoryLock.hpp @brief 数据目录单写锁；持有 OS 句柄，崩溃后由系统释放，不靠删除锁文件。 */
#pragma once
#include <filesystem>
#include <stdexcept>
#include <system_error>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace Preview::Resource::Storage
{
    class DirectoryLock final
    {
    public:
        DirectoryLock() = default;
        DirectoryLock(const DirectoryLock&) = delete;
        auto operator=(const DirectoryLock&) -> DirectoryLock& = delete;
        ~DirectoryLock() noexcept { Close(); }
        /** @brief 仅存储线程调用；失败保留原文件，绝不清理其他实例的数据。 */
        auto Open(const std::filesystem::path& Directory) -> void
        {
            std::filesystem::create_directories(Directory);
            const auto Path = Directory / "instance.lock";
#ifdef _WIN32
            Handle_ = CreateFileW(Path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (Handle_ == INVALID_HANDLE_VALUE) throw std::system_error(static_cast<int>(GetLastError()), std::system_category());
#else
            Handle_ = ::open(Path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
            if (Handle_ < 0) throw std::system_error(errno, std::generic_category());
            if (::flock(Handle_, LOCK_EX | LOCK_NB) != 0)
            {
                const auto Code = errno;
                Close();
                throw std::system_error(Code, std::generic_category());
            }
#endif
        }
        auto Close() noexcept -> void
        {
#ifdef _WIN32
            if (Handle_ != INVALID_HANDLE_VALUE) { CloseHandle(Handle_); Handle_ = INVALID_HANDLE_VALUE; }
#else
            if (Handle_ >= 0) { ::close(Handle_); Handle_ = -1; }
#endif
        }
    private:
#ifdef _WIN32
        HANDLE Handle_{INVALID_HANDLE_VALUE};
#else
        int Handle_{-1};
#endif
    };
}
