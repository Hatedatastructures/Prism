/**
 * @file format.hpp
 * @brief VLESS 协议格式编解码声明
 * @details 提供 VLESS 协议报文的底层解析函数声明，包括请求解析和响应序列化。
 * 函数实现位于 format.cpp 中
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <prism/fault/code.hpp>
#include <prism/protocol/vless/message.hpp>
#include <prism/memory/container.hpp>

namespace psm::protocol::vless::format
{
    /**
     * @brief 解析 VLESS 请求
     * @details 从 wire buffer 解析 VLESS 请求头。格式为
     * [Version 1B][UUID 16B][AddnlInfoLen 1B][AddnlInfo var]
     * [Cmd 1B][Port 2B BE][Atyp 1B][Addr var]。
     * 仅支持 plain VLESS（AddnlInfoLen = 0）
     * @param buffer 包含完整 VLESS 请求头的缓冲区
     * @return 解析成功返回请求结构，失败返回 std::nullopt
     */
    auto parse_request(std::span<const std::uint8_t> buffer) -> std::optional<request>;

    /**
     * @brief 获取 VLESS 响应字节数组
     * @details 返回 [Version 0x00][Addons Length 0x00] 的 2 字节数组。
     * 客户端（mihomo/Xray/sing-box）期望读取 2 字节响应，
     * 仅发送 1 字节会导致客户端将后续 smux ACK 数据误读为
     * Addons Length，造成流偏移
     * @return 2 字节响应数组
     * @note 必须发送 2 字节，不能只发送 1 字节
     */
    [[nodiscard]] constexpr auto make_response() -> std::array<std::byte, 2>
    {
        return {static_cast<std::byte>(version), std::byte{0x00}};
    }

    /**
     * @struct udp_frame
     * @brief VLESS UDP 帧信息
     * @details 描述一个 VLESS UDP 数据包的目标地址和端口，
     * 用于构建 UDP 响应帧
     */
    struct udp_frame
    {
        address destination_address;    // 目标地址
        std::uint16_t destination_port; // 目标端口
    };

    /**
     * @struct udp_parse_result
     * @brief VLESS UDP 数据包解析结果
     * @details 包含从 TLS 流中读取的 UDP 数据包解析出的目标地址、
     * 端口以及 payload 在原始缓冲区中的偏移和大小
     */
    struct udp_parse_result
    {
        address destination_address;      // 目标地址
        std::uint16_t destination_port{}; // 目标端口
        std::size_t payload_offset{};     // payload 在缓冲区中的偏移
        std::size_t payload_size{};       // payload 大小
    };

    /**
     * @brief 构建 VLESS UDP 数据包
     * @details 格式为 [ATYP(1)][ADDR(var)][PORT(2)][Payload]，
     * 与 Trojan 不同，不含 Length 和 CRLF 字段。ATYP 值与
     * VLESS 请求头一致：IPv4=0x01, Domain=0x02, IPv6=0x03
     * @param frame UDP 帧信息，包含目标地址和端口
     * @param payload 用户数据
     * @param out 输出缓冲区
     * @return fault::code 编码结果
     */
    auto build_udp_packet(const udp_frame &frame, std::span<const std::byte> payload,
                          memory::vector<std::byte> &out) -> fault::code;

    /**
     * @brief 解析 VLESS UDP 数据包
     * @details 从 TLS 流中读取的 UDP 数据包中解析出目标地址、端口和 payload。
     * 最小有效帧长度为 7 字节（ATYP + IPv4 + PORT）
     * @param buffer UDP 数据包缓冲区
     * @return 错误码和解析结果
     */
    auto parse_udp_packet(std::span<const std::byte> buffer)
        -> std::pair<fault::code, udp_parse_result>;
}
