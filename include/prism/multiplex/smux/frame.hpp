/**
 * @file frame.hpp
 * @brief smux 帧协议定义（兼容 Mihomo/xtaci/smux v1）
 * @details 定义 smux 多路复用协议的帧格式、命令类型和编解码函数。
 * smux 是一种简单的多路复用协议，用于在单个 TCP 连接上承载多个
 * 独立的双向字节流。协议采用定长 8 字节帧头，包含版本、命令、
 * 长度和流 ID 四个部分。Length 和 StreamID 采用小端字节序。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include <prism/memory/container.hpp>

namespace psm::multiplex::smux
{

    /**
     * @enum command
     * @brief smux 帧命令类型
     * @details 命令值对齐 Mihomo 使用的 xtaci/smux 协议。
     * SYN 新建流，FIN 半关闭流，PSH 数据推送，NOP 心跳（不回复）。
     */
    enum class command : std::uint8_t
    {
        syn = 0,  // 新建流
        fin = 1,  // 半关闭流
        push = 2, // 数据推送
        nop = 3,  // 心跳（不回复）
    };

    /// 协议版本号
    constexpr std::uint8_t protocol_version = 0x01;

    /// 帧头大小（字节）：Version(1) + Cmd(1) + Length(2) + StreamID(4) = 8
    constexpr std::size_t frame_header_size = 8;

    /// 最大帧数据大小（64KB）
    constexpr std::size_t max_frame_length = 65535;

    /**
     * @struct frame_header
     * @brief smux 帧头结构，8 字节定长
     */
    struct frame_header
    {
        /// 协议版本号
        std::uint8_t version = protocol_version;

        /// 命令类型
        command cmd = command::push;

        /// 负载长度，小端序
        std::uint16_t length = 0;

        /// 流标识符，小端序，0 表示会话级帧
        std::uint32_t stream_id = 0;
    };

    /**
     * @struct parsed_address
     * @brief 从 mux 首个 PSH 帧解析出的目标地址
     * @details sing-mux StreamRequest 格式：
     * [Flags 2B][ATYP 1B][Addr(var)][Port 2B]。Flags bit0 标识 UDP 流，
     * bit1 标识 PacketAddr 模式（每帧携带目标地址）。
     * 支持 IPv4 (ATYP=0x01)、域名 (ATYP=0x03)、IPv6 (ATYP=0x04)。
     * offset 指向地址之后的第一个数据字节，用于转发剩余负载。
     */
    struct parsed_address
    {
        memory::string host;    // 目标主机（IPv4/IPv6/域名）
        std::uint16_t port = 0; // 目标端口
        std::size_t offset = 0; // 地址结束位置，相对于原始 buffer
        bool is_udp = false;    // 是否为 UDP 流（Flags bit0）
        bool packet_addr = false; // 是否为 PacketAddr 模式（Flags bit1）
    };

    /**
     * @struct udp_datagram
     * @brief UDP 数据报解析结果
     * @details 格式：[ATYP 1B][Addr(var)][Port 2B][Data]
     */
    struct udp_datagram
    {
        memory::string host;                // 目标主机
        std::uint16_t port = 0;             // 目标端口
        std::span<const std::byte> payload; // 数据部分（不含 UDP 头部）
        std::size_t consumed = 0;           // 解析消耗的总字节数
    };

    /**
     * @struct udp_length_prefixed
     * @brief Length-prefixed UDP 数据报解析结果
     * @details sing-mux 无 PacketAddr 模式格式：[Length 2B BE][Payload]
     * 目标地址在 SYN 时已确定，不包含在数据帧中。
     */
    struct udp_length_prefixed
    {
        std::span<const std::byte> payload; // 数据部分
        std::size_t consumed = 0;           // 解析消耗的总字节数
    };

    /**
     * @brief 解析 UDP 数据报（SOCKS5 地址格式）
     * @param data 包含 [ATYP 1B][Addr][Port 2B][Data] 的字节序列
     * @param mr 内存资源
     * @return 解析结果，nullopt 表示数据不足或格式错误
     */
    [[nodiscard]] auto parse_udp_datagram(std::span<const std::byte> data, memory::resource_pointer mr)
        -> std::optional<udp_datagram>;

    /**
     * @brief 解析 length-prefixed UDP 数据报
     * @param data 包含 [Length 2B BE][Payload] 的字节序列
     * @return 解析结果，nullopt 表示数据不足或格式错误
     */
    [[nodiscard]] auto parse_udp_length_prefixed(std::span<const std::byte> data)
        -> std::optional<udp_length_prefixed>;

    /**
     * @brief 构建 UDP 数据报
     * @param host 目标主机
     * @param port 目标端口
     * @param payload 数据负载
     * @param mr 内存资源
     * @return 编码后的完整 UDP 数据报
     */
    [[nodiscard]] auto build_udp_datagram(std::string_view host, std::uint16_t port,
                                          std::span<const std::byte> payload, memory::resource_pointer mr)
        -> memory::vector<std::byte>;

    /**
     * @brief 构建 length-prefixed UDP 数据报（响应格式）
     * @param payload 数据负载
     * @param mr 内存资源
     * @return 编码后的 [Length 2B BE][Payload]
     */
    [[nodiscard]] auto build_udp_length_prefixed(std::span<const std::byte> payload, memory::resource_pointer mr)
        -> memory::vector<std::byte>;

    /**
     * @brief 解析 mux 首个 PSH 中的 Flags+地址
     * @param data 包含 [Flags 2B][ATYP 1B][Addr][Port 2B] 的字节序列
     * @param mr 内存资源
     * @return 解析结果，nullopt 表示数据不足或格式错误
     */
    [[nodiscard]] auto parse_mux_address(std::span<const std::byte> data, memory::resource_pointer mr)
        -> std::optional<parsed_address>;

    /**
     * @brief 解析帧头
     * @param data 包含帧头的字节序列（至少 8 字节）
     * @return 解析成功的帧头，或 nullopt（校验失败）
     */
    [[nodiscard]] auto deserialization(std::span<const std::byte> data)
        -> std::optional<frame_header>;

} // namespace psm::multiplex::smux