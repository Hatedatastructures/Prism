/**
 * @file Loader.hpp
 * @brief 后台资源清单加载接口与 Glaze schema。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Operations/Web/Catalog.hpp>

#include <glaze/glaze.hpp>

#include <expected>
#include <filesystem>
#include <memory>

namespace glz
{
    template <>
    struct meta<Prism::Operations::Web::ResourceDescriptor>
    {
        using T = Prism::Operations::Web::ResourceDescriptor;
        static constexpr auto value = object("path", &T::Path, "content_type", &T::ContentType, "sha256",
            &T::Sha256, "size", &T::Size, "immutable", &T::Immutable);
    };

    template <>
    struct meta<Prism::Operations::Web::ResourceManifest>
    {
        using T = Prism::Operations::Web::ResourceManifest;
        static constexpr auto value = object("version", &T::Version, "assets", &T::Assets);
    };
} // namespace glz

namespace Prism::Operations::Web
{
    /**
     * @brief 启动时只读取固定 catalog.json 及其明确列出的资源并验证全部内容。
     * @param Directory 由启动装配确定的资源根；不接受请求 URL 或客户端文件路径。
     * @return 成功为不可变 catalog，失败为同一次验证的完整 Failure。
     * @note 未捕获的异常（包括分配失败）保持原类型传播，由启动 fatal boundary 处理。
     * @details 同步文件读取仅在启动冷路径执行；所有输入句柄在返回前关闭，无异步取消和半关闭。
     */
    [[nodiscard]] auto LoadCatalog(const std::filesystem::path& Directory)
        -> std::expected<std::shared_ptr<const Catalog>, Prism::Fault::Failure>;
} // namespace Prism::Operations::Web
