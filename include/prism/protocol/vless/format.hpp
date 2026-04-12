/**
 * @file format.hpp
 * @brief VLESS 协议格式编解码声明
 * @details 提供 VLESS 协议报文的底层解析函数声明，包括请求解析和响应序列化。
 * 函数实现位于 format.cpp 中。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <prism/protocol/vless/message.hpp>

namespace psm::protocol::vless::format
{
    /**
     * @brief 解析 VLESS 请求
     * @param buffer 包含完整 VLESS 请求头的缓冲区
     * @return std::optional<request> 解析成功返回请求结构，失败返回 std::nullopt
     * @details 从 wire buffer 解析 VLESS 请求头。格式为：
     * [Version 1B][UUID 16B][AddnlInfoLen 1B][AddnlInfo var][Cmd 1B][Port 2B BE][Atyp 1B][Addr var]
     * 仅支持 plain VLESS（AddnlInfoLen = 0）。
     */
    auto parse_request(std::span<const std::uint8_t> buffer) -> std::optional<request>;

    /**
     * @brief 获取 VLESS 响应字节数组
     * @return 包含 [Version 0x00][Addons Length 0x00] 的 2 字节数组
     * @note 客户端 (mihomo/Xray/sing-box) 期望读取 2 字节响应：
     *       [Version 1B][Addons Length 1B]，仅发送 1 字节会导致客户端
     *       将后续 smux ACK 数据误读为 Addons Length，造成流偏移
     */
    [[nodiscard]] constexpr auto make_response() -> std::array<std::byte, 2>
    {
        return {static_cast<std::byte>(version), std::byte{0x00}};
    }
}
