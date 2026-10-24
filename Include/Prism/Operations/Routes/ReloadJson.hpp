/**
 * @file ReloadJson.hpp
 * @brief 受限 Reload JSON envelope 的值类型与解析接口。
 */
#pragma once

#include <Prism/Operations/Models.hpp>

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace Prism::Operations
{
    struct ReloadDocument final
    {
        ReloadMode Mode{ReloadMode::ValidateOnly};
        Prism::GenerationId BaseGeneration{};
        std::string ConfigurationJson;
    };

    enum class ReloadDocumentError : std::uint8_t
    {
        Malformed,
        Oversized,
    };

    /** @brief 解析 mode/base_generation/configuration；重复或未知顶层键一律拒绝。 */
    [[nodiscard]] auto ParseReloadDocument(const std::string_view Json)
        -> std::expected<ReloadDocument, ReloadDocumentError>;
} // namespace Prism::Operations
