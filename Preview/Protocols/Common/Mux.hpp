/**
 * @file Mux.hpp
 * @brief 多路复用目标检测
 * @details 提供检测目标地址是否为多路复用标记地址的工具函数。
 * 用于在协议管道中判断是否需要使用多路复用路径处理连接。
 */
#pragma once

#include <cstdint>
#include <string_view>

namespace Preview::Protocol
{

    /**
     * @brief 多路复用开关
     * @details 控制多路复用功能是否启用。
     */
    enum class MuxSwitch : std::uint8_t
    {
        Off = 0, ///< 禁用多路复用
        On = 1 ///< 启用多路复用
    };

    /**
     * @brief 检测是否为 mux 多路复用标记地址
     * @param Host 目标主机名
     * @param Switch 多路复用开关
     * @return 若目标地址为 mux 标记地址且开关已启用则返回 true
     * @details 检测目标主机名是否以 ".mux.sing-box.arpa" 结尾，
     * 这是 Mihomo/sing-box 兼容的 mux 多路复用标记地址。
     */
    [[nodiscard]] inline auto IsMuxTarget(
        std::string_view Host,
        MuxSwitch Switch) noexcept -> bool
    {
        if (Switch != MuxSwitch::On)
        {
            return false;
        }
        constexpr std::string_view Suffix = ".mux.sing-box.arpa";
        if (Host.size() < Suffix.size())
        {
            return false;
        }
        const auto SuffixStart = Host.size() - Suffix.size();
        return Host.substr(SuffixStart) == Suffix;
    }

} // namespace Preview::Protocol
