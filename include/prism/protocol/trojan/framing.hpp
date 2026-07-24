/**
 * @file framing.hpp
 * @brief Trojan 协议格式编解码声明
 * @details 提供 Trojan 协议报文的底层解析函数声明，包括凭据解码、
 * CRLF 验证、命令和地址类型解析、地址解析、端口解码以及
 * UDP 帧编解码。函数实现位于 format.cpp 中
 */
#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/common/framing.hpp>
#include <prism/protocol/trojan/packet.hpp>

#include <array>
#include <cstdint>
#include <span>


namespace psm::protocol::trojan::format
{

    // 委托到共享地址解析函数
    using common::framing::parse_ipv4;
    using common::framing::parse_ipv6;
    using common::framing::parse_domain;
    using common::framing::parse_port;

    /**
     * @struct header_parse
     * @brief 协议头部解析结果
     * @details 存储从协议头部解析出的命令和地址类型
     */
    struct header_parse
    {
        command cmd;       // 命令类型
        address_type atyp; // 地址类型
    };

    /**
     * @brief 解析用户凭据
     * @param buffer 包含凭据的缓冲区，至少 56 字节
     * @return 错误码和凭据数组
     */
    [[nodiscard]] auto parse_credential(std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, std::array<char, 56>>;

    /**
     * @brief 验证 CRLF 分隔符
     * @param buffer 包含 CRLF 的缓冲区，至少 2 字节
     * @return 验证结果错误码
     */
    [[nodiscard]] auto parse_crlf(std::span<const std::uint8_t> buffer)
        -> fault::code;

    /**
     * @brief 解析命令和地址类型
     * @param buffer 包含命令和地址类型的缓冲区，至少 2 字节
     * @return 错误码和解析结果
     */
    [[nodiscard]] auto parse_cmd_atyp(std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, header_parse>;

    /**
     * @struct udp_frame
     * @brief Trojan UDP 帧信息
     * @details 描述一个 Trojan UDP 数据包的目标地址和端口
     */
    struct udp_routed
    {
        address destination_address;    // 目标地址
        std::uint16_t destination_port; // 目标端口
    };

    /**
     * @struct udp_parse_result
     * @brief Trojan UDP 数据包解析结果
     * @details 包含解析出的目标地址、端口以及 payload 偏移和大小
     */
    struct udp_parse_result
    {
        address destination_address;      // 目标地址
        std::uint16_t destination_port{}; // 目标端口
        std::size_t payload_offset{};     // payload 在缓冲区中的偏移
        std::size_t payload_size{};       // payload 大小
    };

    /**
     * @brief 构建 Trojan UDP 数据包（mihomo 兼容格式）
     * @param frame UDP 帧信息
     * @param payload 用户数据
     * @param out 输出缓冲区
     * @return 编码结果错误码
     */
    [[nodiscard]] auto build_udp_pkt(const udp_routed &frame, std::span<const std::byte> payload, memory::vector<std::byte> &out)
        -> fault::code;

    /**
     * @brief 解析 Trojan UDP 数据包（mihomo 兼容格式）
     * @param buffer UDP 数据包缓冲区
     * @return 错误码和解析结果
     */
    [[nodiscard]] auto parse_udp_pkt(std::span<const std::byte> buffer)
        -> std::pair<fault::code, udp_parse_result>;

} // namespace psm::protocol::trojan::format