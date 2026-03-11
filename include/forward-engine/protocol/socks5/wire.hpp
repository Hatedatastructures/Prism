/**
 * @file wire.hpp
 * @brief SOCKS5 协议线级解析
 * @details 提供 SOCKS5 协议报文的底层解析函数，包括头部、IPv4、IPv6、域名、端口和 UDP 数据报的编解码。
 */

#pragma once

#include <cstring>
#include <utility>
#include <span>
#include <vector>

#include <forward-engine/gist.hpp>
#include <forward-engine/protocol/socks5/constants.hpp>
#include <forward-engine/protocol/socks5/message.hpp>
#include <forward-engine/memory/container.hpp>

namespace ngx::protocol::socks5::wire
{
    struct header_parse
    {
        std::uint8_t version; // 协议版本
        command cmd;          // 命令
        std::uint8_t rsv;     // 保留字段
        address_type atyp;    // 地址类型
    };

    /**
     * @brief 解析 SOCKS5 协议报文头部
     * @param buffer 包含 socks5 协议信息的字节数组
     * @return std::pair<gist::code, header_parse> 包含解析之后的错误码和解析后的 socks5 协议头部类
     */
    inline auto parse_header(std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, header_parse>
    {
        if (buffer.size() < 4)
        { // 参数长度过小 无法满足协议长度要求
            return {gist::code::bad_message, {}};
        }

        if (buffer[0] != 0x05)
        { // 协议版本错误，不是socks5协议
            return {gist::code::protocol_error, {}};
        }

        return {gist::code::success, {buffer[0], static_cast<command>(buffer[1]), buffer[2], static_cast<address_type>(buffer[3])}};
    }

    /**
     * @brief 解析 IPv4 地址
     * @param buffer 包含 IPv4 地址的字节数组
     * @return std::pair<gist::code, ipv4_address> 包含解析之后的错误码和解析后的 IPv4 地址类
     */
    inline auto parse_ipv4(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, ipv4_address>
    {
        if (buffer.size() < 4)
        {
            return {gist::code::bad_message, {}};
        }
        ipv4_address addr{};
        std::memcpy(addr.bytes.data(), buffer.data(), 4);
        return {gist::code::success, addr};
    }

    /**
     * @brief 解析 IPv6 地址
     * @param buffer 包含 IPv6 地址的字节数组
     * @return std::pair<gist::code, ipv6_address> 包含解析之后的错误码和解析后的 IPv6 地址类
     */
    inline auto parse_ipv6(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, ipv6_address>
    {
        if (buffer.size() < 16)
        {
            return {gist::code::bad_message, {}};
        }
        ipv6_address addr{};
        std::memcpy(addr.bytes.data(), buffer.data(), 16);
        return {gist::code::success, addr};
    }

    /**
     * @brief 解析域名地址
     * @param buffer 包含域名地址的字节数组
     * @return std::pair<gist::code, domain_address> 包含解析之后的错误码和解析后的域名地址类
     */
    inline auto parse_domain(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, domain_address>
    {
        if (buffer.empty())
        {
            return {gist::code::bad_message, {}};
        }
        const std::uint8_t len = buffer[0];
        if (buffer.size() < static_cast<size_t>(1 + len))
        {
            return {gist::code::bad_message, {}};
        }
        domain_address addr{};
        if (len > addr.value.size())
        {
            return {gist::code::bad_message, {}};
        }
        addr.length = len;
        std::memcpy(addr.value.data(), buffer.data() + 1, len);
        return {gist::code::success, addr};
    }

    /**
     * @brief 解析端口
     * @param buffer 包含端口的字节数组
     * @return std::pair<gist::code, uint16_t> 包含解析之后的错误码和解析后的端口值
     */
    inline auto decode_port(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, uint16_t>
    {
        if (buffer.size() < 2)
        {
            return {gist::code::bad_message, 0};
        }
        uint16_t port = (static_cast<uint16_t>(buffer[0]) << 8) | static_cast<uint16_t>(buffer[1]);
        return {gist::code::success, port};
    }

    /**
     * @brief SOCKS5 UDP 数据报头部
     * @details SOCKS5 UDP 数据报格式 (RFC 1928 Section 7)
     * ```
     * +----+------+------+----------+----------+----------+
     * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +----+------+------+----------+----------+----------+
     * | 2  |  1   |  1   | Variable |    2     | Variable |
     * +----+------+------+----------+----------+----------+
     * ```
     *
     * 字段说明：
     * - RSV: 保留字段，必须为 0x0000
     * - FRAG: 分片序号，0 表示独立数据报（本项目仅支持 0）
     * - ATYP: 地址类型 (0x01=IPv4, 0x03=域名, 0x04=IPv6)
     * - DST.ADDR: 目标地址
     * - DST.PORT: 目标端口（大端序）
     * - DATA: 用户数据
     *
     * @warning FRAG != 0 的数据包将被丢弃
     */
    struct udp_header
    {
        address destination_address;      // 目标地址
        std::uint16_t destination_port{}; // 目标端口
        std::uint8_t frag{};              // 分片序号
    };

    /**
     * @brief UDP 报头解析结果
     */
    struct udp_header_parse
    {
        udp_header header;
        std::size_t header_size{};
    };

    /**
     * @brief 编码 SOCKS5 UDP 报头
     * @param header UDP 报头信息
     * @param out 输出缓冲区
     * @return gist::code 编码结果
     * @details 将 UDP 报头编码为 SOCKS5 格式，不包含 DATA 部分
     */
    inline auto encode_udp_header(const udp_header &header, memory::vector<std::uint8_t> &out)
        -> gist::code
    {   // TODO udp未详细处理其逻辑
        // RSV (2 bytes) + FRAG (1 byte) + ATYP (1 byte)
        out.push_back(0x00);
        out.push_back(0x00);
        out.push_back(header.frag);

        auto encode_address = [&out]<typename Address>(const Address &addr)
        {
            if constexpr (std::is_same_v<Address, ipv4_address>)
            {
                out.push_back(0x01);
                out.insert(out.end(), addr.bytes.begin(), addr.bytes.end());
            }
            else if constexpr (std::is_same_v<Address, ipv6_address>)
            {
                out.push_back(0x04);
                out.insert(out.end(), addr.bytes.begin(), addr.bytes.end());
            }
            else if constexpr (std::is_same_v<Address, domain_address>)
            {
                out.push_back(0x03);
                out.push_back(addr.length);
                out.insert(out.end(), addr.value.begin(), addr.value.begin() + addr.length);
            }
        };

        std::visit(encode_address, header.destination_address);

        out.push_back(static_cast<std::uint8_t>((header.destination_port >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(header.destination_port & 0xFF));

        return gist::code::success;
    }

    /**
     * @brief 解码 SOCKS5 UDP 报头
     * @param buffer UDP 数据报缓冲区
     * @return std::pair<gist::code, udp_header_parse> 解码结果
     * @details 解析 UDP 报头，返回报头信息和 DATA 起始偏移
     *
     * FRAG 处理策略：
     * - FRAG = 0：正常处理
     * - FRAG != 0：返回 not_supported 错误（SOCKS5 规范要求）
     */
    inline auto decode_udp_header(std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, udp_header_parse>
    {
        // 最小长度：RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2) = 10
        if (buffer.size() < 10)
        {
            return {gist::code::bad_message, {}};
        }

        // 验证 RSV
        if (buffer[0] != 0x00 || buffer[1] != 0x00)
        {
            return {gist::code::protocol_error, {}};
        }

        std::uint8_t frag = buffer[2];
        // FRAG != 0 时拒绝（SOCKS5 规范要求）
        if (frag != 0)
        {
            return {gist::code::not_supported, {}};
        }

        const auto atyp = static_cast<address_type>(buffer[3]);
        std::size_t offset = 4;
        address dest_addr;
        std::size_t addr_size = 0;

        switch (atyp)
        {
        case address_type::ipv4:
        {
            if (buffer.size() < offset + 4 + 2)
            {
                return {gist::code::bad_message, {}};
            }
            auto [ec, addr] = parse_ipv4(buffer.subspan(offset, 4));
            if (gist::failed(ec))
            {
                return {ec, {}};
            }
            dest_addr = addr;
            addr_size = 4;
            break;
        }
        case address_type::ipv6:
        {
            if (buffer.size() < offset + 16 + 2)
            {
                return {gist::code::bad_message, {}};
            }
            auto [ec, addr] = parse_ipv6(buffer.subspan(offset, 16));
            if (gist::failed(ec))
            {
                return {ec, {}};
            }
            dest_addr = addr;
            addr_size = 16;
            break;
        }
        case address_type::domain:
        {
            if (buffer.size() < offset + 1)
            {
                return {gist::code::bad_message, {}};
            }
            std::uint8_t domain_len = buffer[offset];
            if (buffer.size() < offset + 1 + domain_len + 2)
            {
                return {gist::code::bad_message, {}};
            }
            auto [ec, addr] = parse_domain(buffer.subspan(offset, 1 + domain_len));
            if (gist::failed(ec))
            {
                return {ec, {}};
            }
            dest_addr = addr;
            addr_size = 1 + domain_len;
            break;
        }
        default:
            return {gist::code::unsupported_address, {}};
        }

        offset += addr_size;
        auto [port_ec, port] = decode_port(buffer.subspan(offset, 2));
        if (gist::failed(port_ec))
        {
            return {port_ec, {}};
        }

        udp_header_parse result;
        result.header.destination_address = dest_addr;
        result.header.destination_port = port;
        result.header.frag = frag;
        result.header_size = offset + 2;

        return {gist::code::success, result};
    }

    /**
     * @brief 编码完整的 SOCKS5 UDP 数据报
     * @param header UDP 报头
     * @param data 用户数据
     * @param out 输出缓冲区
     * @return gist::code 编码结果
     */
    inline auto encode_udp_datagram(const udp_header &header, std::span<const std::uint8_t> data, memory::vector<std::uint8_t> &out)
        -> gist::code
    {
        if (gist::failed(encode_udp_header(header, out)))
        {
            return gist::code::bad_message;
        }
        out.insert(out.end(), data.begin(), data.end());
        return gist::code::success;
    }
}
