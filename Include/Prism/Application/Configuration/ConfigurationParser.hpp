/**
 * @file ConfigurationParser.hpp
 * @brief Prism 配置的严格 glaze 解析入口。
 */
#pragma once

#include <Prism/Application/Configuration/ConfigurationError.hpp>
#include <Prism/Application/Configuration/PrismConfiguration.hpp>
#include <Prism/Application/Configuration/PreparedConfiguration.hpp>
#include <Prism/Application/Configuration/Validation/ValidationTypes.hpp>

#include <expected>
#include <filesystem>
#include <string>
#include <string_view>

namespace Prism::Application::Configuration
{

    /** @brief 严格解析请求。 */
    struct ParseRequest
    {
        std::string_view Json;
        ValidationOptions Options{};
    };

    /** @brief 文件解析请求。 */
    struct LoadRequest
    {
        std::filesystem::path Path;
        ValidationOptions Options{};
    };

    class ConfigurationParser final
    {
    public:
        using Result = std::expected<PrismConfiguration, ConfigurationError>;
        using PreparedResult = std::expected<PreparedConfiguration, ConfigurationError>;
        using SerializationResult = std::expected<std::string, ConfigurationError>;

        [[nodiscard]] static auto ParseJson(std::string_view Json) -> Result;

        /**
         * @brief 将完整配置值序列化为独立拥有的 JSON 文本。
         * @details 调用方负责先按其运行环境校验候选配置，并由应用层完成临时文件写入与原子替换。
         */
        [[nodiscard]] static auto SerializeJson(const PrismConfiguration &Configuration)
            -> SerializationResult;

        /** @brief 校验借用 JSON 缓冲；调用方仍拥有并负责该缓冲的清理。 */
        [[nodiscard]] static auto Parse(ParseRequest Request) -> Result;

        /** @brief 管理 reload 只接受 secret references；值必须来自当前 owning generation。 */
        [[nodiscard]] static auto ParseForOperationsReload(std::string_view Json) -> Result;

        [[nodiscard]] static auto PrepareFile(LoadRequest Request) -> PreparedResult;

        [[nodiscard]] static auto LoadFile(LoadRequest Request) -> Result;
    };

} // namespace Prism::Application::Configuration
