/**
 * @file singmux.hpp
 * @brief sing-mux StreamRequest 解析
 * @details sing-mux 会话内每个 HTTP/2 stream 的首个 DATA 帧载荷为
 *          StreamRequest（二进制，非 JSON）：
 *            [flags 2B BE]：bit0=UDP，bit1=PacketAddr
 *            [addrType 1B][addr][port 2B BE]（地址在前，端口在后）
 *          addrType：0x01=IPv4(4B) / 0x03=域名(1B len+域名) / 0x04=IPv6(16B)
 *          PacketAddr 模式可省略地址（空目标），由每包携带地址。
 */

#pragma once

#include <prism/foundation/memory/container.hpp>

#include <cstdint>
#include <optional>
#include <span>

namespace psm::multiplex::h2mux
{

    /// StreamRequest flags 位定义
    enum class sing_flag : std::uint16_t
    {
        udp = 0x0001,         ///< UDP 流
        packet_addr = 0x0002, ///< 每包携带目标地址
    };

    /**
     * @struct sing_request
     * @brief 解析后的 StreamRequest
     */
    struct sing_request
    {
        bool udp{false};             ///< UDP 标志
        bool packet_addr{false};      ///< PacketAddr 标志
        memory::string host;          ///< 目标主机（空表示无目标，PacketAddr 模式）
        std::uint16_t port{0};        ///< 目标端口
        std::size_t consumed{0};      ///< 解析消耗的字节数
    };

    /**
     * @brief 解析 sing-mux StreamRequest
     * @param data 首 DATA 帧载荷（可含 StreamRequest 之后的用户数据）
     * @param mr 内存资源（host 分配用）
     * @return 解析结果；数据不足返回 nullopt（调用方累积后重试）
     * @details 最小长度 4 字节（flags + addrType + port），数据不足时
     *          返回 nullopt。地址类型非法返回 consumed=0 的空结果。
     */
    [[nodiscard]] auto parse_sing_request(std::span<const std::byte> data,
                                          memory::resource_pointer mr = memory::current_resource())
        -> std::optional<sing_request>;

} // namespace psm::multiplex::h2mux
