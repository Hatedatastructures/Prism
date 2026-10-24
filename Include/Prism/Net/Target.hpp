/** @file Target.hpp @brief 唯一正式网络目标：拥有型主机、数值端口及路由意图。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Host.hpp>

#include <cstdint>
#include <expected>
#include <string_view>
namespace Prism::Network
{
    enum class RouteKind { Reverse, Forward };
    /**
     * @brief 完整拥有地址，无 allocator、executor、取消或关闭责任。
     * @details 默认空主机和零端口用于无目标 root；实际 TCP/UDP 出站入口验证非空和非零。
     */
    struct Target final
    {
        Prism::Network::Host Host;
        std::uint16_t Port{0};
        RouteKind Route{RouteKind::Reverse};
        auto operator==(const Target&) const -> bool = default;
    };
    /** @brief 冷配置端口只转换一次；空、零、溢出及尾随字符返回领域失败。 */
    [[nodiscard]] auto ParsePort(std::string_view Text) noexcept
        -> std::expected<std::uint16_t, Prism::Fault::Failure>;
}
