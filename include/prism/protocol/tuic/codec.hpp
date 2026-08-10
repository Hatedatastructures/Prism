/**
 * @file codec.hpp
 * @brief TUIC v5 协议帧编解码
 * @details 命令帧格式（全部大端）：
 *   Authenticate: VER(0x05) TYPE(0x00) UUID[16] TOKEN[32]
 *   Connect:      VER TYPE ATYP[ADDR] PORT(2B BE)
 *   Packet:       VER TYPE ASSOC_ID(u16) PKT_ID(u16) FRAG_TOTAL(u8)
 *                 FRAG_ID(u8) SIZE(u16) ATYP[ADDR] PORT(2B BE) DATA
 *   Dissociate:   VER TYPE ASSOC_ID(u16)
 *   Heartbeat:    VER TYPE
 *   ATYP: 0=domain(1B len) 1=IPv4 2=IPv6 0xFF=None
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/protocol/common/address.hpp>

#include <array>
#include <cstdint>
#include <span>

namespace psm::protocol::tuic
{

    /// 协议版本
    inline constexpr std::uint8_t version = 0x05;

    /// 命令类型
    enum class command : std::uint8_t
    {
        authenticate = 0x00,
        connect = 0x01,
        packet = 0x02,
        dissociate = 0x03,
        heartbeat = 0x04,
    };

    /// 地址类型
    enum class address_type : std::uint8_t
    {
        domain = 0x00,
        ipv4 = 0x01,
        ipv6 = 0x02,
        none = 0xFF,
    };

    /// TOKEN 长度（TLS exporter 32 字节）
    inline constexpr std::size_t token_len = 32;

    /**
     * @struct authenticate_frame
     * @brief 认证帧
     */
    struct authenticate_frame
    {
        std::array<std::uint8_t, 16> uuid{};  ///< 用户 UUID
        std::array<std::uint8_t, 32> token{}; ///< 认证令牌
    };

    /**
     * @struct connect_frame
     * @brief CONNECT 帧
     */
    struct connect_frame
    {
        psm::protocol::common::address destination{};
        std::uint16_t port{0};
    };

    /**
     * @struct packet_frame
     * @brief UDP 数据帧
     */
    struct packet_frame
    {
        std::uint16_t assoc_id{0};  ///< 关联会话 ID
        std::uint16_t pkt_id{0};    ///< 包 ID
        std::uint8_t frag_total{1}; ///< 分片总数
        std::uint8_t frag_id{0};    ///< 分片序号
        psm::protocol::common::address destination{};
        std::uint16_t port{0};
        std::size_t data_offset{0}; ///< 数据在缓冲区中的偏移
        std::size_t data_len{0};    ///< 数据长度
    };

    /**
     * @brief 编码 varint（LEB128）
     * @param value 数值
     * @param out 输出
     * @return 写入字节数
     */
    [[nodiscard]] auto encode_varint(std::uint32_t value, std::span<std::uint8_t> out) -> std::size_t;

    /**
     * @brief 解码 varint
     * @param in 输入
     * @param value 输出
     * @return 消耗字节数（0 失败）
     */
    [[nodiscard]] auto decode_varint(std::span<const std::uint8_t> in, std::uint32_t &value) -> std::size_t;

    /**
     * @brief 解析 Authenticate 帧
     * @param in 输入（≥ 2 + 16 + 32）
     * @param out 输出
     * @return 是否成功
     */
    [[nodiscard]] auto parse_authenticate(std::span<const std::uint8_t> in, authenticate_frame &out) -> bool;

    /**
     * @brief 解析 Connect 帧
     * @param in 输入
     * @param out 输出
     * @param frame_len 输出帧头长度（供剥帧头转发）
     * @return 是否成功（数据不足返回 false）
     */
    [[nodiscard]] auto parse_connect(std::span<const std::uint8_t> in, connect_frame &out,
                                     std::size_t &frame_len) -> bool;

    /**
     * @brief 解析 Packet 帧
     * @param in 输入
     * @param out 输出（data_offset/data_len 指向输入中的载荷）
     * @return 是否成功
     */
    [[nodiscard]] auto parse_packet(std::span<const std::uint8_t> in, packet_frame &out) -> bool;

    /**
     * @brief 解析 Dissociate 帧
     * @param in 输入
     * @param assoc_id 输出关联 ID
     * @return 是否成功
     */
    [[nodiscard]] auto parse_dissociate(std::span<const std::uint8_t> in, std::uint16_t &assoc_id) -> bool;

    /**
     * @brief 解析 Heartbeat 帧
     * @param in 输入
     * @return 是否成功
     */
    [[nodiscard]] auto parse_heartbeat(std::span<const std::uint8_t> in) -> bool;

} // namespace psm::protocol::tuic
