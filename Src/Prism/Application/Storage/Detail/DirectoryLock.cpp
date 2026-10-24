/** @file DirectoryLock.cpp @brief Application 存储目录单写锁的 OS 句柄管理。 */
#include <Prism/Application/Storage/Detail/DirectoryLock.hpp>

#include <cerrno>
#include <filesystem>
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

namespace Prism::Application::Storage::Detail
{
    DirectoryLock::~DirectoryLock() noexcept
    {
        Close();
    }

    auto DirectoryLock::Open(const std::filesystem::path& Directory) -> void
    {
#ifdef _WIN32
        const bool AlreadyOpen = Handle_ != InvalidHandle;
#else
        const bool AlreadyOpen = Handle_ >= 0;
#endif
        if (AlreadyOpen)
            throw std::system_error(std::make_error_code(std::errc::device_or_resource_busy));

        std::filesystem::create_directories(Directory);
        const auto Path = Directory / "instance.lock";
#ifdef _WIN32
        const auto Native = CreateFileW(Path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (Native == INVALID_HANDLE_VALUE)
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category());
        Handle_ = reinterpret_cast<std::uintptr_t>(Native);
#else
        const auto Native = ::open(Path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (Native < 0) throw std::system_error(errno, std::generic_category());
        if (::flock(Native, LOCK_EX | LOCK_NB) != 0)
        {
            const auto Code = errno;
            ::close(Native);
            throw std::system_error(Code, std::generic_category());
        }
        Handle_ = Native;
#endif
    }

    auto DirectoryLock::Close() noexcept -> void
    {
#ifdef _WIN32
        if (Handle_ != InvalidHandle)
        {
            CloseHandle(reinterpret_cast<HANDLE>(Handle_));
            Handle_ = InvalidHandle;
        }
#else
        if (Handle_ >= 0)
        {
            ::close(Handle_);
            Handle_ = -1;
        }
#endif
    }
}
