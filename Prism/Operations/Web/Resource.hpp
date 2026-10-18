/** @file Resource.hpp @brief 本机后台不可变资源值与固定容量。 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
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
} // namespace Prism::Operations::Web
