/** @file OperationsConfigurationPersistence.hpp @brief Reload 配置文件事务的 Src 私有契约。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Application::OperationsConfigurationPersistence
{
    using Failure = Prism::Fault::Failure;

    /** @brief Reload 应用前替换配置；发布失败时用内存副本回滚原文件。 */
    class FileTransaction final
    {
    public:
        FileTransaction() = default;
        FileTransaction(const FileTransaction &) = delete;
        auto operator=(const FileTransaction &) -> FileTransaction & = delete;
        FileTransaction(FileTransaction &&Other) noexcept;
        auto operator=(FileTransaction &&Other) noexcept -> FileTransaction &;
        ~FileTransaction() noexcept;

        [[nodiscard]] static auto Replace(
            const std::filesystem::path &Path, const std::string_view Json,
            const std::uint64_t Operation) -> std::expected<FileTransaction, Failure>;

        /** @brief Reload 发布成功后放弃内存副本；临时文件已随原子替换消失。 */
        auto Commit() noexcept -> void;

        /** @brief 原子恢复原始配置；失败时保留副本供析构重试。 */
        [[nodiscard]] auto Rollback() noexcept -> std::expected<void, Failure>;

    private:
        [[nodiscard]] static auto Write(
            const std::filesystem::path &Path, const std::string_view Text) noexcept -> bool;
        [[nodiscard]] static auto Remove(const std::filesystem::path &Path) noexcept -> bool;
        [[nodiscard]] static auto ReplacePath(
            const std::filesystem::path &Source, const std::filesystem::path &Destination) noexcept -> bool;
        static auto Wipe(std::string &Value) noexcept -> void;

        std::filesystem::path Path_;
        std::filesystem::path Temporary_;
        std::string Original_;
        bool HadOriginal_{false};
        bool Active_{false};
    };
}
