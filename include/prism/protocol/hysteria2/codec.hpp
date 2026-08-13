/**
 * @file codec.hpp
 * @brief Hysteria2 协议帧编解码
 * @details TCP 请求（QUIC 双向流首包）：
 *   FrameType(0x401, QUIC varint) AddrLen(varint) Addr PaddingLen(varint) Padding
 * TCP 响应（同一流首包）：
 *   Status(1B, 0=OK) MsgLen(varint) Message PaddingLen(varint) Padding
 * UDP 消息（QUIC datagram）：
 *   SessionID(u32 BE) PacketID(u16 BE) FragID(u8) FragCount(u8)
 *   AddrLen(varint) Addr Data
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/protocol/common/address.hpp>

#include <cstdint>
#include <span>

namespace psm::protocol::hysteria2
{

    /// TCP 请求帧类型
    inline constexpr std::uint64_t frame_type_tcp = 0x401;

    /// UDP 最大消息长度
    inline constexpr std::size_t max_udp_message = 4096;

    /// 地址最大长度
    inline constexpr std::size_t max_address_length = 2048;

    /**
     * @struct tcp_request
     * @brief TCP 请求帧
     */
    struct tcp_request
    {
        memory::string address; ///< socksaddr 字符串（host:port）
    };

    /**
     * @struct udp_message
     * @brief UDP 消息（分片元数据 + 地址 + 数据）
     */
    struct udp_message
    {
        std::uint32_t session_id{0}; ///< 会话 ID
        std::uint16_t packet_id{0};  ///< 包 ID（分片聚合键）
        std::uint8_t frag_id{0};     ///< 分片序号
        std::uint8_t frag_count{1};  ///< 分片总数
        memory::string address;      ///< 目标地址（socksaddr）
        std::size_t data_offset{0};  ///< 数据偏移（输入中）
        std::size_t data_len{0};     ///< 数据长度
    };

    /**
     * @brief QUIC varint 编码
     * @param value 待编码值
     * @param out 输出缓冲
     * @return 编码字节数
     */
    [[nodiscard]] auto encode_varint(std::uint64_t value, std::span<std::uint8_t> out) -> std::size_t;

    /**
     * @brief QUIC varint 解码
     * @param in 输入缓冲
     * @param value 解码结果输出
     * @return 解码字节数
     */
    [[nodiscard]] auto decode_varint(std::span<const std::uint8_t> in, std::uint64_t &value) -> std::size_t;

    /**
     * @brief 解析 TCP 请求帧
     * @param in 输入
     * @param out 输出
     * @param payload_offset 输出载荷偏移（帧头长度，供剥帧头转发）
     * @return 是否成功
     */
    [[nodiscard]] auto parse_tcp_request(std::span<const std::uint8_t> in, tcp_request &out,
                                         std::size_t &payload_offset) -> bool;

    /**
     * @brief 解析 UDP 消息
     * @param in 输入
     * @param out 输出
     * @return 是否成功
     */
    [[nodiscard]] auto parse_udp_message(std::span<const std::uint8_t> in, udp_message &out) -> bool;

} // namespace psm::protocol::hysteria2
