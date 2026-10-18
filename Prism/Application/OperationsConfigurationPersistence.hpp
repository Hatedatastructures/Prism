/** @file OperationsConfigurationPersistence.hpp @brief Reload 应用前的同目录原子配置替换与回滚。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace Prism::Application::OperationsConfigurationPersistence
{
    using Failure = Prism::Fault::Failure;

    /** @brief 先原子替换配置文件，Reload 发布失败时用内存副本恢复原文件。 */
    class FileTransaction final
    {
    public:
        FileTransaction() = default;
        FileTransaction(const FileTransaction &) = delete;
        auto operator=(const FileTransaction &) -> FileTransaction & = delete;
        FileTransaction(FileTransaction &&Other) noexcept
            : Path_(std::move(Other.Path_)), Temporary_(std::move(Other.Temporary_)),
              Original_(std::move(Other.Original_)), HadOriginal_(Other.HadOriginal_),
              Active_(std::exchange(Other.Active_, false))
        {
        }
        auto operator=(FileTransaction &&Other) noexcept -> FileTransaction &
        {
            if (this != &Other)
            {
                (void)Rollback();
                Wipe(Original_);
                Path_ = std::move(Other.Path_); Temporary_ = std::move(Other.Temporary_);
                Original_ = std::move(Other.Original_); HadOriginal_ = Other.HadOriginal_;
                Active_ = std::exchange(Other.Active_, false);
            }
            return *this;
        }
        ~FileTransaction() noexcept
        {
            (void)Rollback();
            Wipe(Original_);
        }

        [[nodiscard]] static auto Replace(
            const std::filesystem::path &Path, const std::string_view Json,
            const std::uint64_t Operation) -> std::expected<FileTransaction, Failure>
        {
            if (Path.empty() || Json.empty() || Operation == 0U)
                return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            FileTransaction Result;
            Result.Path_ = Path;
            Result.Temporary_ = Path;
            Result.Temporary_ += ".operations-" + std::to_string(Operation) + ".tmp";
            std::error_code Error;
            if (std::filesystem::exists(Result.Temporary_, Error) || Error)
                return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
            Result.HadOriginal_ = std::filesystem::exists(Path, Error);
            if (Error) return std::unexpected(Failure{Prism::Fault::Code::IoError});
            if (Result.HadOriginal_)
            {
                std::ifstream File(Path, std::ios::binary);
                if (!File) return std::unexpected(Failure{Prism::Fault::Code::IoError});
                Result.Original_.assign(std::istreambuf_iterator<char>(File), std::istreambuf_iterator<char>());
                if (File.bad()) return std::unexpected(Failure{Prism::Fault::Code::IoError});
            }
            if (!Write(Result.Temporary_, Json)) return std::unexpected(Failure{Prism::Fault::Code::IoError});
            if (Result.HadOriginal_)
            {
                const auto Permissions = std::filesystem::status(Path, Error).permissions();
                if (Error)
                {
                    (void)Remove(Result.Temporary_);
                    return std::unexpected(Failure{Prism::Fault::Code::IoError});
                }
                std::filesystem::permissions(Result.Temporary_, Permissions, Error);
                if (Error)
                {
                    (void)Remove(Result.Temporary_);
                    return std::unexpected(Failure{Prism::Fault::Code::IoError});
                }
            }
            if (!ReplacePath(Result.Temporary_, Path))
            {
                (void)Remove(Result.Temporary_);
                return std::unexpected(Failure{Prism::Fault::Code::IoError});
            }
            Result.Active_ = true;
            return Result;
        }

        /** @brief Reload 发布成功后放弃内存副本；临时文件已随原子替换消失。 */
        auto Commit() noexcept -> void
        {
            Active_ = false;
            Wipe(Original_);
        }

        /** @brief 原子恢复原始配置；失败时保留副本供析构重试。 */
        [[nodiscard]] auto Rollback() noexcept -> std::expected<void, Failure>
        {
            if (!Active_) return {};
            auto Restored = false;
            if (HadOriginal_)
            {
                if (!Write(Temporary_, Original_))
                    return std::unexpected(Failure{Prism::Fault::Code::IoError});
                Restored = ReplacePath(Temporary_, Path_);
                if (!Restored) (void)Remove(Temporary_);
            }
            else Restored = Remove(Path_);
            if (!Restored) return std::unexpected(Failure{Prism::Fault::Code::IoError});
            Active_ = false;
            Wipe(Original_);
            return {};
        }

    private:
        [[nodiscard]] static auto Write(const std::filesystem::path &Path,
                                        const std::string_view Text) noexcept -> bool
        {
            try
            {
                std::ofstream File(Path, std::ios::binary | std::ios::out | std::ios::trunc);
                if (!File) return false;
                File.write(Text.data(), static_cast<std::streamsize>(Text.size()));
                File.flush();
                return static_cast<bool>(File);
            }
            catch (...) { return false; }
        }

        [[nodiscard]] static auto Remove(const std::filesystem::path &Path) noexcept -> bool
        {
            std::error_code Error;
            (void)std::filesystem::remove(Path, Error);
            if (Error) return false;
            return !std::filesystem::exists(Path, Error) && !Error;
        }

        [[nodiscard]] static auto ReplacePath(
            const std::filesystem::path &Source, const std::filesystem::path &Destination) noexcept -> bool
        {
#if defined(_WIN32)
            return ::MoveFileExW(Source.c_str(), Destination.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
#else
            std::error_code Error;
            std::filesystem::rename(Source, Destination, Error);
            return !Error;
#endif
        }

        static auto Wipe(std::string &Value) noexcept -> void
        {
            volatile char *Bytes = Value.data();
            for (std::size_t Index = 0; Index < Value.size(); ++Index) Bytes[Index] = 0;
            Value.clear();
        }

        std::filesystem::path Path_;
        std::filesystem::path Temporary_;
        std::string Original_;
        bool HadOriginal_{false};
        bool Active_{false};
    };
}
