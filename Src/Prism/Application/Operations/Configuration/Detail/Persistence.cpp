/** @file Persistence.cpp @brief Reload 配置文件原子替换事务实现。 */
#include <Prism/Application/Operations/Configuration/Detail/Persistence.hpp>

#include <fstream>
#include <iterator>
#include <system_error>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace Prism::Application::OperationsConfigurationPersistence
{
    FileTransaction::FileTransaction(FileTransaction &&Other) noexcept
        : Path_(std::move(Other.Path_)), Temporary_(std::move(Other.Temporary_)),
          Original_(std::move(Other.Original_)), HadOriginal_(Other.HadOriginal_),
          Active_(std::exchange(Other.Active_, false))
    {
    }

    auto FileTransaction::operator=(FileTransaction &&Other) noexcept -> FileTransaction &
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

    FileTransaction::~FileTransaction() noexcept
    {
        (void)Rollback();
        Wipe(Original_);
    }

    auto FileTransaction::Replace(
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

    auto FileTransaction::Commit() noexcept -> void
    {
        Active_ = false;
        Wipe(Original_);
    }

    auto FileTransaction::Rollback() noexcept -> std::expected<void, Failure>
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

    auto FileTransaction::Write(
        const std::filesystem::path &Path, const std::string_view Text) noexcept -> bool
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

    auto FileTransaction::Remove(const std::filesystem::path &Path) noexcept -> bool
    {
        std::error_code Error;
        (void)std::filesystem::remove(Path, Error);
        if (Error) return false;
        return !std::filesystem::exists(Path, Error) && !Error;
    }

    auto FileTransaction::ReplacePath(
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

    auto FileTransaction::Wipe(std::string &Value) noexcept -> void
    {
        volatile char *Bytes = Value.data();
        for (std::size_t Index = 0; Index < Value.size(); ++Index) Bytes[Index] = 0;
        Value.clear();
    }
}
