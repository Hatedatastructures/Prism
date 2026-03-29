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

#include <forward-engine/memory/container.hpp>

namespace ngx::channel::smux
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
     * [Flags 2B][ATYP 1B][Addr(var)][Port 2B]。Flags bit0 标识 UDP 流。
     * 支持 IPv4 (ATYP=0x01)、域名 (ATYP=0x03)、IPv6 (ATYP=0x04)。
     * offset 指向地址之后的第一个数据字节，用于转发剩余负载。
     */
    struct parsed_address
    {
        memory::string host;          // 目标主机（IPv4/IPv6/域名）
        std::uint16_t port = 0;       // 目标端口
        std::size_t offset = 0;       // 地址结束位置，相对于原始 buffer
        bool is_udp = false;          // 是否为 UDP 流（Flags bit0）
    };

    /**
     * @struct udp_datagram
     * @brief UDP 数据报解析结果
     * @details 格式：[ATYP 1B][Addr(var)][Port 2B][Data]
     */
    struct udp_datagram
    {
        memory::string host;          // 目标主机
        std::uint16_t port = 0;       // 目标端口
        std::span<const std::byte> payload; // 数据部分（不含 UDP 头部）
    };

    /**
     * @brief 解析 UDP 数据报
     * @param data 包含 [ATYP 1B][Addr][Port 2B][Data] 的字节序列
     * @param mr 内存资源
     * @return 解析结果，nullopt 表示数据不足或格式错误
     */
    [[nodiscard]] auto parse_udp_datagram(std::span<const std::byte> data, memory::resource_pointer mr)
        -> std::optional<udp_datagram>;

    /**
     * @brief 构建 UDP 数据报
     * @param host 目标主机
     * @param port 目标端口
     * @param payload 数据负载
     * @param mr 内存资源
     * @return 编码后的完整 UDP 数据报
     */
    [[nodiscard]] auto build_udp_datagram(std::string_view host, std::uint16_t port,
                                          std::span<const std::byte> payload,
                                          memory::resource_pointer mr)
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
     * @brief 序列化帧
     * @param hdr 帧头结构
     * @param payload 数据负载（可以为空）
     * @param mr 内存资源
     * @return 序列化后的字节向量（8 字节帧头 + 负载）
     */
    [[nodiscard]] auto serialize(const frame_header &hdr, std::span<const std::byte> payload,
                                 memory::resource_pointer mr)
        -> memory::vector<std::byte>;

    /**
     * @brief 解析帧头
     * @param data 包含帧头的字节序列（至少 8 字节）
     * @return 解析成功的帧头，或 nullopt（校验失败）
     */
    [[nodiscard]] auto deserialization(std::span<const std::byte> data)
        -> std::optional<frame_header>;

    /**
     * @brief 创建 PSH（数据推送）帧
     */
    [[nodiscard]] inline auto make_push_frame(const std::uint32_t stream_id, const std::span<const std::byte> payload,
                                              const memory::resource_pointer mr)
        -> memory::vector<std::byte>
    {
        frame_header hdr{};
        hdr.version = protocol_version;
        hdr.cmd = command::push;
        hdr.stream_id = stream_id;
        hdr.length = static_cast<std::uint16_t>(payload.size());
        return serialize(hdr, payload, mr);
    }

    /**
     * @brief 创建 SYN 帧
     */
    [[nodiscard]] inline auto make_syn_frame(const std::uint32_t stream_id, const memory::resource_pointer mr)
        -> memory::vector<std::byte>
    {
        frame_header hdr{};
        hdr.version = protocol_version;
        hdr.cmd = command::syn;
        hdr.stream_id = stream_id;
        hdr.length = 0;
        return serialize(hdr, {}, mr);
    }

    /**
     * @brief 创建 FIN 帧
     */
    [[nodiscard]] inline auto make_fin_frame(const std::uint32_t stream_id, const memory::resource_pointer mr)
        -> memory::vector<std::byte>
    {
        frame_header hdr{};
        hdr.version = protocol_version;
        hdr.cmd = command::fin;
        hdr.stream_id = stream_id;
        hdr.length = 0;
        return serialize(hdr, {}, mr);
    }

} // namespace ngx::channel::smux
