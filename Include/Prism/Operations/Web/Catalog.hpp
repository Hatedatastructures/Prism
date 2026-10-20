/** @file Catalog.hpp @brief 后台资源固定清单及精确同源页面查询。 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace Prism::Operations::Web
{
    inline constexpr std::size_t MaxResources = 512;
    inline constexpr std::size_t MaxResourceBytes = 4 * 1024 * 1024;
    inline constexpr std::size_t MaxCatalogBytes = 1024 * 1024;
    inline constexpr std::size_t MaxTotalBytes = 64 * 1024 * 1024;

    /** @brief 构建生成的清单项；启动时核对路径、类型、大小与内容哈希。 */
    struct ResourceDescriptor final
    {
        std::string Path;
        std::string ContentType;
        std::string Sha256;
        std::uint64_t Size{0};
        bool Immutable{false};
    };

    struct ResourceManifest final
    {
        std::uint32_t Version{0};
        std::vector<ResourceDescriptor> Assets;
    };

    /** @brief 拥有完整正文；发布后只读，热路径不访问文件系统。 */
    struct Resource final
    {
        std::string Path;
        std::string ContentType;
        std::string Sha256;
        std::string Body;
        bool Immutable{false};
    };

    /** @brief 字段只允许可直接用于 HTTP 的构建路径，不把请求转换为文件路径。 */
    [[nodiscard]] auto IsResourcePath(std::string_view Value) noexcept -> bool;

    /** @brief 由文件后缀确定唯一媒体类型；拒绝可注入响应头的清单值。 */
    [[nodiscard]] auto ContentTypeFor(std::string_view Value) noexcept -> std::string_view;

    /** @brief 仅正式页面路径可以返回 index；未知资源与 API 保持各自错误。 */
    [[nodiscard]] auto IsPage(std::string_view Value) noexcept -> bool;

    /**
     * @brief 拥有不可变清单和正文，所有网络请求只查询本对象。
     * @details 构造是启动冷路径；Lookup 输入只在同步调用期间借用，返回指针随 catalog 存活。
     *          本对象没有 executor、取消、半关闭或文件句柄；最终释放者是管理 listener 的进程 owner。
     */
    class Catalog final
    {
    public:
        explicit Catalog(std::vector<Resource> Assets);

        [[nodiscard]] auto Lookup(std::string_view Target) const noexcept -> const Resource*;

        [[nodiscard]] auto Size() const noexcept -> std::size_t;

    private:
        std::vector<Resource> Assets_;
    };
} // namespace Prism::Operations::Web
