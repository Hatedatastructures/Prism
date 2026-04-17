/**
 * @file format.hpp
 * @brief Trojan 协议格式编解码声明
 * @details 提供 Trojan 协议报文的底层解析函数声明，包括凭据解码、
 * CRLF 验证、命令和地址类型解析、地址解析、端口解码以及
 * UDP 帧编解码。函数实现位于 format.cpp 中
 */
#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <prism/fault/code.hpp>
#include <prism/protocol/trojan/message.hpp>
#include <prism/memory/container.hpp>

namespace psm::protocol::trojan::format
{
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
    auto parse_credential(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, std::array<char, 56>>;

    /**
     * @brief 验证 CRLF 分隔符
     * @param buffer 包含 CRLF 的缓冲区，至少 2 字节
     * @return 验证结果错误码
     */
    auto parse_crlf(const std::span<const std::uint8_t> buffer)
        -> fault::code;

    /**
     * @brief 解析命令和地址类型
     * @param buffer 包含命令和地址类型的缓冲区，至少 2 字节
     * @return 错误码和解析结果
     */
    auto parse_cmd_atyp(std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, header_parse>;

    /**
     * @brief 解析 IPv4 地址
     * @param buffer 包含 IPv4 地址的缓冲区，至少 4 字节
     * @return 错误码和地址结构
     */
    auto parse_ipv4(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, ipv4_address>;

    /**
     * @brief 解析 IPv6 地址
     * @param buffer 包含 IPv6 地址的缓冲区，至少 16 字节
     * @return 错误码和地址结构
     */
    auto parse_ipv6(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, ipv6_address>;

    /**
     * @brief 解析域名地址
     * @param buffer 包含域名地址的缓冲区，格式为长度字节加域名内容
     * @return 错误码和地址结构
     */
    auto parse_domain(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, domain_address>;

    /**
     * @brief 解析端口号
     * @param buffer 包含端口号的缓冲区，至少 2 字节
     * @return 错误码和端口号
     */
    auto parse_port(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, uint16_t>;

    /**
     * @struct udp_frame
     * @brief Trojan UDP 帧信息
     * @details 描述一个 Trojan UDP 数据包的目标地址和端口
     */
    struct udp_frame
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
    auto build_udp_packet(const udp_frame &frame, std::span<const std::byte> payload,
                          memory::vector<std::byte> &out)
        -> fault::code;

    /**
     * @brief 解析 Trojan UDP 数据包（mihomo 兼容格式）
     * @param buffer UDP 数据包缓冲区
     * @return 错误码和解析结果
     */
    auto parse_udp_packet(std::span<const std::byte> buffer)
        -> std::pair<fault::code, udp_parse_result>;

} // namespace psm::protocol::trojan::format