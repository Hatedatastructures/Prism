/**
 * @file wire.hpp
 * @brief SOCKS5 协议线级解析
 * @details 提供 SOCKS5 协议报文的底层解析函数，包括头部、IPv4、IPv6、
 * 域名、端口和 UDP 数据报的编解码。所有函数设计为零拷贝友好，直接
 * 操作字节缓冲区，避免不必要的内存分配。解析结果通过结构体返回，
 * 调用者负责管理缓冲区生命周期。函数返回值使用 gist::code 错误码
 * 系统，便于错误追踪和处理。
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
    /**
     * @struct header_parse
     * @brief SOCKS5 请求头部解析结果
     * @details 存储解析后的请求头部字段，包括协议版本、命令类型、
     * 保留字段和地址类型。头部格式为 4 字节固定长度，解析后可直接
     * 用于后续地址读取和命令处理。
     */
    struct header_parse
    {
        // 协议版本，SOCKS5 固定为 0x05
        std::uint8_t version;

        // 命令类型
        command cmd;

        // 保留字段，必须为 0x00
        std::uint8_t rsv;

        // 地址类型
        address_type atyp;
    };

    /**
     * @brief 解析 SOCKS5 协议报文头部
     * @param buffer 包含 SOCKS5 协议信息的字节数组
     * @return std::pair<gist::code, header_parse> 包含解析之后的错误码
     * 和解析后的 SOCKS5 协议头部类
     * @details 解析 4 字节的请求头部，验证协议版本是否为 SOCKS5。
     * 头部格式为 VER(1) + CMD(1) + RSV(1) + ATYP(1)。缓冲区长度
     * 不足或版本错误时返回相应错误码。
     */
    inline auto parse_header(std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, header_parse>
    {
        if (buffer.size() < 4)
        {
            return {gist::code::bad_message, {}};
        }

        if (buffer[0] != 0x05)
        {
            return {gist::code::protocol_error, {}};
        }

        return {gist::code::success, {buffer[0], static_cast<command>(buffer[1]), buffer[2], static_cast<address_type>(buffer[3])}};
    }

    /**
     * @brief 解析 IPv4 地址
     * @param buffer 包含 IPv4 地址的字节数组
     * @return std::pair<gist::code, ipv4_address> 包含解析之后的错误码
     * 和解析后的 IPv4 地址类
     * @details 从缓冲区读取 4 字节的 IPv4 地址数据，直接拷贝到返回
     * 结构中。地址采用网络字节序存储，无需转换。
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
     * @return std::pair<gist::code, ipv6_address> 包含解析之后的错误码
     * 和解析后的 IPv6 地址类
     * @details 从缓冲区读取 16 字节的 IPv6 地址数据，直接拷贝到返回
     * 结构中。地址采用网络字节序存储，无需转换。
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
     * @return std::pair<gist::code, domain_address> 包含解析之后的错误码
     * 和解析后的域名地址类
     * @details 解析 SOCKS5 域名格式，第一个字节为长度，后续为域名
     * 内容。域名最大长度为 255 字节。缓冲区格式为 LEN(1) + DOMAIN(n)。
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
     * @return std::pair<gist::code, uint16_t> 包含解析之后的错误码和
     * 解析后的端口值
     * @details 从缓冲区读取 2 字节的大端序端口值，转换为主机字节序
     * 返回。端口格式为高字节在前、低字节在后。
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
     * @struct udp_header
     * @brief SOCKS5 UDP 数据报头部
     * @details 定义 SOCKS5 UDP 数据报的头部结构，遵循 RFC 1928 Section 7
     * 规范。UDP 数据报格式为 RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(变长)
     * + DST.PORT(2) + DATA(变长)。RSV 保留字段必须为 0x0000，FRAG
     * 分片序号为 0 表示独立数据报。本项目仅支持 FRAG=0 的完整数据报。
     * @warning FRAG != 0 的数据包将被丢弃
     */
    struct udp_header
    {
        // 目标地址
        address destination_address;

        // 目标端口（主机字节序）
        std::uint16_t destination_port{};

        // 分片序号，0 表示独立数据报
        std::uint8_t frag{};
    };

    /**
     * @struct udp_header_parse
     * @brief UDP 报头解析结果
     * @details 存储解析后的 UDP 报头信息和头部大小。头部大小用于
     * 计算数据载荷的起始偏移，便于后续数据处理。
     */
    struct udp_header_parse
    {
        // UDP 报头信息
        udp_header header;

        // 头部字节数，用于定位 DATA 起始位置
        std::size_t header_size{};
    };

    /**
     * @brief 编码 SOCKS5 UDP 报头
     * @param header UDP 报头信息
     * @param out 输出缓冲区
     * @return gist::code 编码结果
     * @details 将 UDP 报头编码为 SOCKS5 格式，不包含 DATA 部分。
     * 编码格式为 RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(变长) +
     * DST.PORT(2)。地址根据类型写入不同格式的数据。
     */
    inline auto encode_udp_header(const udp_header &header, memory::vector<std::uint8_t> &out)
        -> gist::code
    {
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
     * @details 解析 UDP 报头，返回报头信息和 DATA 起始偏移。首先
     * 验证 RSV 字段是否为 0x0000，然后检查 FRAG 字段是否为 0。
     * FRAG != 0 时返回 not_supported 错误，符合 SOCKS5 规范要求。
     * 地址解析支持 IPv4、IPv6 和域名三种类型。
     */
    inline auto decode_udp_header(std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, udp_header_parse>
    {
        if (buffer.size() < 10)
        {
            return {gist::code::bad_message, {}};
        }

        if (buffer[0] != 0x00 || buffer[1] != 0x00)
        {
            return {gist::code::protocol_error, {}};
        }

        std::uint8_t frag = buffer[2];
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
     * @details 将 UDP 报头和用户数据编码为完整的 SOCKS5 UDP 数据报。
     * 首先调用 encode_udp_header 编码头部，然后追加用户数据。
     * 输出缓冲区将包含完整的可发送数据报。
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
