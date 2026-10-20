/** @file DirectoryLockTest.cpp @brief 验证重复打开失败后仍保留原目录锁。 */
#include <gtest/gtest.h>

#include <Prism/Application/Storage/Detail/DirectoryLock.hpp>

#include <chrono>
#include <filesystem>
#include <string>
#include <system_error>

namespace
{
    [[nodiscard]] auto CaptureOpenFailure(
        Prism::Application::Storage::Detail::DirectoryLock& Lock,
        const std::filesystem::path& Directory) -> std::error_code
    {
        try
        {
            Lock.Open(Directory);
        }
        catch (const std::system_error& Error)
        {
            return Error.code();
        }
        return {};
    }

    class TemporaryDirectory final
    {
    public:
        TemporaryDirectory()
        {
            const auto Stamp = std::chrono::steady_clock::now().time_since_epoch().count();
            Path_ = std::filesystem::temp_directory_path() /
                ("PrismDirectoryLockTest-" + std::to_string(Stamp));
            std::filesystem::create_directory(Path_);
        }

        ~TemporaryDirectory() noexcept
        {
            static_cast<void>(Cleanup());
        }

        [[nodiscard]] auto Cleanup() noexcept -> std::error_code
        {
            std::error_code Error;
            std::filesystem::remove_all(Path_, Error);
            return Error;
        }

        [[nodiscard]] auto Path() const noexcept -> const std::filesystem::path& { return Path_; }

    private:
        std::filesystem::path Path_;
    };
}

TEST(ResourceDirectoryLock, ReopenFailurePreservesOriginalHandleUntilClose)
{
    TemporaryDirectory Directory;
    Prism::Application::Storage::Detail::DirectoryLock Owner;
    Owner.Open(Directory.Path());
    EXPECT_THROW(Owner.Open(Directory.Path()), std::system_error);

    Prism::Application::Storage::Detail::DirectoryLock Contender;
    EXPECT_THROW(Contender.Open(Directory.Path()), std::system_error);

    Owner.Close();
    EXPECT_NO_THROW(Contender.Open(Directory.Path()));
    Contender.Close();

    const auto CleanupError = Directory.Cleanup();
    EXPECT_EQ(CleanupError, std::error_code{}) << CleanupError.message();
}

TEST(ResourceDirectoryLock, DifferentDirectoryReopenIsRejectedAndBothLocksRemainUsable)
{
    TemporaryDirectory Directories;
    const auto FirstDirectory = Directories.Path() / "first";
    const auto SecondDirectory = Directories.Path() / "second";
    Prism::Application::Storage::Detail::DirectoryLock Owner;
    Owner.Open(FirstDirectory);

    EXPECT_EQ(CaptureOpenFailure(Owner, SecondDirectory),
        std::make_error_code(std::errc::device_or_resource_busy));

    Prism::Application::Storage::Detail::DirectoryLock FirstContender;
    Prism::Application::Storage::Detail::DirectoryLock SecondContender;
    EXPECT_THROW(FirstContender.Open(FirstDirectory), std::system_error);
    EXPECT_NO_THROW(SecondContender.Open(SecondDirectory));

    Owner.Close();
    EXPECT_NO_THROW(FirstContender.Open(FirstDirectory));
    SecondContender.Close();
    EXPECT_NO_THROW(SecondContender.Open(SecondDirectory));
    FirstContender.Close();
    SecondContender.Close();

    const auto CleanupError = Directories.Cleanup();
    EXPECT_EQ(CleanupError, std::error_code{}) << CleanupError.message();
}
