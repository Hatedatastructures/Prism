/**
 * @file PathSinkOwner.hpp
 * @brief 按规范化文件路径共享的唯一轮转文件句柄 owner。
 */
#pragma once

#include <Prism/Foundation/Utility/Diagnose/Detail/RenderEpoch.hpp>

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Diagnose::Detail
{
    /** @brief 单条格式化记录提交给共享物理路径 owner 的 epoch 策略。 */
    struct PathWritePolicy final
    {
        RenderMode Mode{RenderMode::CompactHuman};
        std::uint64_t RotateBytes{0U};
        std::uint32_t RotateFiles{0U};
    };

    /** @brief 同一路径跨 Diagnose epoch 共用一个顺序写入的物理文件 owner。 */
    class PathSinkOwner final
    {
    public:
        ~PathSinkOwner() noexcept
        {
            (void)Close();
        }

        [[nodiscard]] static auto ResolvePath(const BackendSettings &Settings)
            -> std::expected<std::filesystem::path, BackendError>
        {
            std::error_code Error;
            const auto Requested = Settings.Logging.Directory / Settings.Logging.FileName;
            auto Canonical = std::filesystem::weakly_canonical(Requested, Error);
            if (Error)
            {
                return std::unexpected(BackendError{BackendErrorCode::FileOpen,
                    Requested.string(), "cannot resolve Diagnose log path"});
            }
            return Canonical;
        }

        [[nodiscard]] static auto Create(const std::filesystem::path &Path,
            const RenderMode InitialMode)
            -> std::expected<std::shared_ptr<PathSinkOwner>, BackendError>
        {
            auto Owner = std::shared_ptr<PathSinkOwner>(new PathSinkOwner(Path));
            if (const auto Directories = Owner->CreateDirectories(); !Directories)
            {
                return std::unexpected(Directories.error());
            }
            std::error_code Error;
            const auto Exists = std::filesystem::exists(Path, Error);
            if (Error)
            {
                return std::unexpected(BackendError{BackendErrorCode::FileOpen,
                    Path.string(), "cannot inspect Diagnose log file"});
            }
            if (Exists)
            {
                Owner->CreatedForPrepare_ = false;
                if (std::filesystem::is_directory(Path, Error) || Error)
                {
                    return std::unexpected(BackendError{BackendErrorCode::FileOpen,
                        Path.string(), "Diagnose log path is not a file"});
                }
                Owner->Size_ = std::filesystem::file_size(Path, Error);
                if (Error)
                {
                    return std::unexpected(BackendError{BackendErrorCode::FileOpen,
                        Path.string(), "cannot read Diagnose log size"});
                }
                if (Owner->Size_ != 0U)
                {
                    Owner->Mode_ = Owner->ExistingMode();
                    Owner->NeedsLegacyArchive_ = !Owner->Mode_.has_value();
                }
            }
            if (!Owner->Mode_)
            {
                Owner->Mode_ = InitialMode;
            }
            Owner->File_.open(Path, std::ios::binary | std::ios::out | std::ios::app);
            if (!Owner->File_.is_open())
            {
                return std::unexpected(BackendError{BackendErrorCode::FileOpen,
                    Path.string(), "cannot open Diagnose log file"});
            }
            Owner->FileOpened_ = true;
            return Owner;
        }

        PathSinkOwner(const PathSinkOwner &) = delete;
        auto operator=(const PathSinkOwner &) -> PathSinkOwner & = delete;

        [[nodiscard]] auto Write(const std::string_view Payload, const PathWritePolicy &Policy) -> bool
        {
            if (Closed_ || FileFailed_)
            {
                return false;
            }
            const auto Added = static_cast<std::uint64_t>(Payload.size()) + 1U;
            if (Added > UINT64_MAX - Size_)
            {
                return MarkFailed();
            }
            if (NeedsLegacyArchive_)
            {
                File_.flush();
                if (!File_.good())
                {
                    return MarkFailed();
                }
                File_.close();
                if (File_.fail() || !ArchiveLegacyFile())
                {
                    return MarkFailed();
                }
                File_.clear();
                File_.open(Path_, std::ios::binary | std::ios::out | std::ios::trunc);
                if (!File_.is_open())
                {
                    return MarkFailed();
                }
                NeedsLegacyArchive_ = false;
                Size_ = 0U;
                Mode_ = Policy.Mode;
            }
            if (!Mode_)
            {
                Mode_ = Policy.Mode;
            }
            if (!SameMode(*Mode_, Policy.Mode) &&
                !Rotate(*Mode_, Policy.Mode, Policy.RotateFiles))
            {
                return MarkFailed();
            }
            Mode_ = Policy.Mode;
            if (Size_ != 0U && Size_ + Added > Policy.RotateBytes &&
                !Rotate(Policy.Mode, Policy.Mode, Policy.RotateFiles))
            {
                return MarkFailed();
            }
            File_.write(Payload.data(), static_cast<std::streamsize>(Payload.size()));
            File_.put('\n');
            if (!File_.good())
            {
                return MarkFailed();
            }
            Size_ += Added;
            EverWritten_ = true;
            return true;
        }
        [[nodiscard]] auto Flush() -> bool
        {
            if (Closed_ || FileFailed_)
            {
                return false;
            }
            File_.flush();
            return File_.good() || MarkFailed();
        }

        [[nodiscard]] auto Close() noexcept -> bool
        {
            if (Closed_)
            {
                return CloseSucceeded_;
            }
            if (File_.is_open())
            {
                File_.flush();
                if (!File_.good())
                {
                    (void)MarkFailed();
                }
                File_.close();
                if (File_.fail())
                {
                    (void)MarkFailed();
                }
            }
            Closed_ = true;
            if (CreatedForPrepare_ && FileOpened_ && !EverWritten_)
            {
                std::error_code Error;
                std::filesystem::remove(Path_, Error);
                if (Error)
                {
                    (void)MarkFailed();
                }
            }
            if (!EverWritten_)
            {
                RemovePreparedDirectories();
            }
            return CloseSucceeded_;
        }
        [[nodiscard]] auto ErrorCount() const noexcept -> std::uint64_t
        {
            return ErrorCount_.load(std::memory_order_relaxed);
        }

        [[nodiscard]] auto Path() const noexcept -> const std::filesystem::path &
        {
            return Path_;
        }

    private:
        explicit PathSinkOwner(std::filesystem::path PathValue)
            : Path_(std::move(PathValue))
        {
        }

        /** @brief 冷准备仅创建缺失目录，并记录本 owner 实际创建的路径供回滚释放。 */
        [[nodiscard]] auto CreateDirectories() -> std::expected<void, BackendError>
        {
            std::vector<std::filesystem::path> Missing;
            auto Directory = Path_.parent_path();
            for (auto Parent = Directory; !Parent.empty(); Parent = Parent.parent_path())
            {
                std::error_code Error;
                const auto Exists = std::filesystem::exists(Parent, Error);
                if (Error)
                {
                    return std::unexpected(BackendError{BackendErrorCode::Directory,
                        Parent.string(), "cannot inspect Diagnose log directory"});
                }
                if (Exists)
                {
                    if (!std::filesystem::is_directory(Parent, Error) || Error)
                    {
                        return std::unexpected(BackendError{BackendErrorCode::Directory,
                            Parent.string(), "Diagnose log parent is not a directory"});
                    }
                    break;
                }
                Missing.push_back(Parent);
                const auto Next = Parent.parent_path();
                if (Next == Parent)
                {
                    break;
                }
            }
            for (auto Entry = Missing.rbegin(); Entry != Missing.rend(); ++Entry)
            {
                std::error_code Error;
                const auto Created = std::filesystem::create_directory(*Entry, Error);
                if (Error)
                {
                    std::error_code ExistsError;
                    const auto Exists = std::filesystem::exists(*Entry, ExistsError);
                    if (ExistsError || !Exists || !std::filesystem::is_directory(*Entry, ExistsError) ||
                        ExistsError)
                    {
                        RemovePreparedDirectories();
                        return std::unexpected(BackendError{BackendErrorCode::Directory,
                            Entry->string(), "cannot create Diagnose log directory"});
                    }
                }
                else if (Created)
                {
                    CreatedDirectories_.push_back(*Entry);
                }
                else
                {
                    std::error_code ExistsError;
                    if (!std::filesystem::is_directory(*Entry, ExistsError) || ExistsError)
                    {
                        RemovePreparedDirectories();
                        return std::unexpected(BackendError{BackendErrorCode::Directory,
                            Entry->string(), "Diagnose log parent is not a directory"});
                    }
                }
            }
            return {};
        }

        /** @brief 逆序移除本 owner 创建且仍为空的目录，不触碰已有或非空目录。 */
        auto RemovePreparedDirectories() noexcept -> void
        {
            for (auto Entry = CreatedDirectories_.rbegin(); Entry != CreatedDirectories_.rend(); ++Entry)
            {
                std::error_code Error;
                std::filesystem::remove(*Entry, Error);
            }
            CreatedDirectories_.clear();
        }

        [[nodiscard]] auto Rotate(const RenderMode CurrentMode, const RenderMode NextMode,
            const std::uint32_t RotateFiles) -> bool
        {
            if (!Flush())
            {
                return false;
            }
            File_.close();
            if (File_.fail())
            {
                return false;
            }
            const auto Rotated = CurrentMode == NextMode
                ? RotateCurrentFile(RotateFiles)
                : ArchiveCurrentMode(CurrentMode, RotateFiles);
            if (!Rotated)
            {
                ReopenAppend();
                return false;
            }
            File_.open(Path_, std::ios::binary | std::ios::out | std::ios::trunc);
            if (!File_.is_open())
            {
                ReopenAppend();
                return false;
            }
            if (CurrentMode != NextMode && !RemoveExcessModeArchives(NextMode, RotateFiles))
            {
                return MarkFailed();
            }
            Size_ = 0U;
            Mode_ = NextMode;
            return true;
        }

        [[nodiscard]] auto ExistingMode() const -> std::optional<RenderMode>
        {
            std::ifstream Input(Path_, std::ios::binary);
            char First = '\0';
            while (Input.get(First) &&
                (First == '\r' || First == '\n' || First == ' ' || First == '\t'))
            {
            }
            if (!Input)
            {
                return {};
            }
            if (First == '{')
            {
                return RenderMode::Structured;
            }
            return {};
        }

        [[nodiscard]] auto ArchiveLegacyFile() -> bool
        {
            std::error_code Error;
            const auto Base = std::filesystem::path(Path_.string() + ".legacy");
            auto Destination = Base;
            for (std::uint32_t Index = 0U; Index <= 64U; ++Index)
            {
                if (!std::filesystem::exists(Destination, Error))
                {
                    if (Error)
                    {
                        return false;
                    }
                    std::filesystem::rename(Path_, Destination, Error);
                    return !Error;
                }
                if (Error)
                {
                    return false;
                }
                Destination = std::filesystem::path(Base.string() + "." + std::to_string(Index + 1U));
            }
            return false;
        }

        [[nodiscard]] auto ArchiveCurrentMode(const RenderMode Mode,
            const std::uint32_t RotateFiles) -> bool
        {
            auto RotatedFiles = std::uint32_t{0U};
            for (auto Index = 1U; Index < RotateFiles; ++Index)
            {
                std::error_code Error;
                if (!std::filesystem::exists(RotationPath(Index), Error))
                {
                    if (Error)
                    {
                        return false;
                    }
                    break;
                }
                ++RotatedFiles;
            }
            const auto Offset = static_cast<std::uint32_t>(Size_ != 0U);
            const auto CurrentFiles = RotatedFiles + Offset;
            if (CurrentFiles == 0U)
            {
                return RemoveModeArchivesFrom(Mode, RotateFiles + 1U) &&
                    RemoveExcessRotations(RotateFiles);
            }
            const auto FirstDiscarded = RotateFiles - CurrentFiles + 1U;
            if (!RemoveModeArchivesFrom(Mode, FirstDiscarded))
            {
                return false;
            }
            for (auto Index = FirstDiscarded - 1U; Index > 0U; --Index)
            {
                const auto Source = ModeArchivePath(Mode, Index);
                std::error_code Error;
                if (!std::filesystem::exists(Source, Error))
                {
                    if (Error)
                    {
                        return false;
                    }
                    continue;
                }
                std::filesystem::rename(Source, ModeArchivePath(Mode, Index + CurrentFiles), Error);
                if (Error)
                {
                    return false;
                }
            }
            if (Offset != 0U)
            {
                std::error_code Error;
                std::filesystem::rename(Path_, ModeArchivePath(Mode, 1U), Error);
                if (Error)
                {
                    return false;
                }
            }
            for (auto Index = 1U; Index <= RotatedFiles; ++Index)
            {
                std::error_code Error;
                std::filesystem::rename(RotationPath(Index),
                    ModeArchivePath(Mode, Index + Offset), Error);
                if (Error)
                {
                    return false;
                }
            }
            return RemoveExcessRotations(RotateFiles);
        }

        [[nodiscard]] auto RotateCurrentFile(const std::uint32_t RotateFiles) -> bool
        {
            if (!RemoveExcessRotations(RotateFiles) || !RemoveOldest(RotateFiles) ||
                !ShiftRotated(RotateFiles) || !MoveCurrent())
            {
                return false;
            }
            return true;
        }

        [[nodiscard]] auto RemoveModeArchivesFrom(const RenderMode Mode,
            const std::uint32_t FirstIndex) -> bool
        {
            std::error_code Error;
            for (auto Index = FirstIndex; Index <= 64U; ++Index)
            {
                std::filesystem::remove(ModeArchivePath(Mode, Index), Error);
                if (Error)
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] auto RemoveExcessModeArchives(const RenderMode Mode,
            const std::uint32_t RotateFiles) -> bool
        {
            std::error_code Error;
            for (auto Index = RotateFiles + 1U; Index <= 64U; ++Index)
            {
                std::filesystem::remove(ModeArchivePath(Mode, Index), Error);
                if (Error)
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] auto RemoveExcessRotations(
            const std::uint32_t RotateFiles) -> bool
        {
            std::error_code Error;
            for (auto Index = RotateFiles + 1U; Index <= 64U; ++Index)
            {
                std::filesystem::remove(RotationPath(Index), Error);
                if (Error)
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] auto RemoveOldest(const std::uint32_t RotateFiles) -> bool
        {
            std::error_code Error;
            const auto Removed = std::filesystem::remove(RotationPath(RotateFiles), Error);
            (void)Removed;
            return !Error;
        }

        [[nodiscard]] auto ShiftRotated(const std::uint32_t RotateFiles) -> bool
        {
            std::error_code Error;
            for (auto Index = RotateFiles; Index > 1U; --Index)
            {
                const auto Source = RotationPath(Index - 1U);
                if (!std::filesystem::exists(Source, Error))
                {
                    if (Error)
                    {
                        return false;
                    }
                    continue;
                }
                std::filesystem::rename(Source, RotationPath(Index), Error);
                if (Error)
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] auto MoveCurrent() -> bool
        {
            std::error_code Error;
            std::filesystem::rename(Path_, RotationPath(1U), Error);
            return !Error;
        }

        auto ReopenAppend() noexcept -> void
        {
            File_.clear();
            File_.open(Path_, std::ios::binary | std::ios::out | std::ios::app);
        }

        [[nodiscard]] static auto SameMode(const RenderMode Left, const RenderMode Right) noexcept -> bool
        {
            return Left == Right;
        }

        [[nodiscard]] auto MarkFailed() noexcept -> bool
        {
            if (!FileFailed_)
            {
                FileFailed_ = true;
                CloseSucceeded_ = false;
                ErrorCount_.fetch_add(1U, std::memory_order_relaxed);
            }
            return false;
        }
        [[nodiscard]] auto RotationPath(const std::uint32_t Index) const
            -> std::filesystem::path
        {
            return Path_.parent_path() /
                (Path_.stem().string() + "." + std::to_string(Index) + Path_.extension().string());
        }

        [[nodiscard]] auto ModeArchivePath(const RenderMode Mode, const std::uint32_t Index) const
            -> std::filesystem::path
        {
            const auto Suffix = Mode == RenderMode::Structured ? ".structured."
                : Mode == RenderMode::HumanWithFields ? ".human-fields."
                : ".compact-human.";
            return Path_.parent_path() /
                (Path_.stem().string() + Suffix + std::to_string(Index) + Path_.extension().string());
        }

        std::filesystem::path Path_;
        std::ofstream File_;
        std::optional<RenderMode> Mode_{};
        std::uint64_t Size_{0U};
        std::vector<std::filesystem::path> CreatedDirectories_{};
        bool CreatedForPrepare_{true};
        bool FileOpened_{false};
        bool EverWritten_{false};
        bool FileFailed_{false};
        bool NeedsLegacyArchive_{false};
        std::atomic<std::uint64_t> ErrorCount_{0U};
        bool Closed_{false};
        bool CloseSucceeded_{true};
    };
}
