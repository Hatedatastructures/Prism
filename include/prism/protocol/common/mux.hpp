/**
 * @file mux.hpp
 * @brief 多路复用目标检测
 * @details 提供检测目标地址是否为多路复用标记地址的工具函数。
 * 用于在协议管道中判断是否需要使用多路复用路径处理连接。
 */
#pragma once

#include <string_view>

namespace psm::protocol
{

    /**
     * @brief 检测是否为 mux 多路复用标记地址
     * @param host 目标主机名
     * @param mux_enabled 是否启用多路复用
     * @return 若目标地址为 mux 标记地址且 mux 已启用则返回 true
     * @details 检测目标主机名是否以 ".mux.sing-box.arpa" 结尾，
     * 这是 Mihomo/sing-box 兼容的 mux 多路复用标记地址。
     */
    [[nodiscard]] inline auto is_mux_target(std::string_view host, bool mux_enabled) noexcept
        -> bool
    {
        constexpr std::string_view suffix = ".mux.sing-box.arpa";
        return mux_enabled && host.size() >= suffix.size() && host.substr(host.size() - suffix.size()) == suffix;
    }

} // namespace psm::protocol
