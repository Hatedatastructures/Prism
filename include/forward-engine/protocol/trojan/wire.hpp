/**
 * @file wire.hpp
 * @brief Trojan 协议线级解析
 * @details 提供 Trojan 协议报文的底层解析函数，包括凭据解码、CRLF 验证、
 * 命令和地址类型解析、地址解析、端口解码以及 UDP 帧编解码。所有函数
 * 设计为零拷贝友好，直接操作缓冲区视图，避免不必要的内存分配。
 */

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <forward-engine/gist.hpp>
#include <cctype>
#include <forward-engine/protocol/trojan/message.hpp>
#include <forward-engine/memory/container.hpp>

/**
 * @namespace ngx::protocol::trojan::wire
 * @brief Trojan 协议线级解析函数
 * @details 提供 Trojan 协议报文的底层编解码函数。所有函数使用 std::span
 * 作为输入参数，支持零拷贝操作。函数返回 gist::code 错误码和解析结果。
 */
namespace ngx::protocol::trojan::wire
{
    /**
     * @struct header_parse
     * @brief 协议头部解析结果
     * @details 存储从协议头部解析出的命令和地址类型。
     */
    struct header_parse
    {
        // 命令类型
        command cmd;
        // 地址类型
        address_type atyp;
    };

    /**
     * @brief 解码用户凭据
     * @param buffer 包含凭据的缓冲区，至少 56 字节
     * @return std::pair<gist::code, std::array<char, 56>> 错误码和凭据数组
     * @details 从缓冲区提取 56 字节的十六进制凭据字符串。验证每个字节
     * 都是有效的十六进制字符（0-9、a-f、A-F）。凭据通常是密码的 SHA224
     * 哈希值的十六进制表示。
     */
    inline auto decode_credential(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, std::array<char, 56>>
    {
        if (buffer.size() < 56)
        {
            return {gist::code::bad_message, {}};
        }

        std::array<char, 56> credential{};
        for (size_t i = 0; i < 56; ++i)
        {
            if (!std::isxdigit(buffer[i]))
            {
                return {gist::code::protocol_error, {}};
            }
            credential[i] = static_cast<char>(buffer[i]);
        }
        return {gist::code::success, credential};
    }

    /**
     * @brief 验证 CRLF 分隔符
     * @param buffer 包含 CRLF 的缓冲区，至少 2 字节
     * @return gist::code 验证结果
     * @details 检查缓冲区前两个字节是否为回车换行符（\r\n）。
     * Trojan 协议使用 CRLF 作为字段分隔符。
     */
    inline auto decode_crlf(const std::span<const std::uint8_t> buffer)
        -> gist::code
    {
        if (buffer.size() < 2)
        {
            return gist::code::bad_message;
        }
        if (buffer[0] != '\r' || buffer[1] != '\n')
        {
            return gist::code::protocol_error;
        }
        return gist::code::success;
    }

    /**
     * @brief 解码命令和地址类型
     * @param buffer 包含命令和地址类型的缓冲区，至少 2 字节
     * @return std::pair<gist::code, header_parse> 错误码和解析结果
     * @details 从缓冲区提取命令字节和地址类型字节。第一个字节为命令，
     * 第二个字节为地址类型。不验证值的有效性，由调用者负责检查。
     */
    inline auto decode_cmd_atyp(std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, header_parse>
    {
        if (buffer.size() < 2)
        {
            return {gist::code::bad_message, {}};
        }
        return {gist::code::success, {static_cast<command>(buffer[0]), static_cast<address_type>(buffer[1])}};
    }

    /**
     * @brief 解析 IPv4 地址
     * @param buffer 包含 IPv4 地址的缓冲区，至少 4 字节
     * @return std::pair<gist::code, ipv4_address> 错误码和地址结构
     * @details 从缓冲区复制 4 字节的 IPv4 地址到地址结构。
     * 地址采用网络字节序（大端序）。
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
     * @param buffer 包含 IPv6 地址的缓冲区，至少 16 字节
     * @return std::pair<gist::code, ipv6_address> 错误码和地址结构
     * @details 从缓冲区复制 16 字节的 IPv6 地址到地址结构。
     * 地址采用网络字节序（大端序）。
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
     * @param buffer 包含域名地址的缓冲区，格式为长度字节加域名内容
     * @return std::pair<gist::code, domain_address> 错误码和地址结构
     * @details 从缓冲区解析域名地址。第一个字节为域名长度，后续为域名内容。
     * 域名最大长度为 255 字节。验证缓冲区长度是否足够。
     */
    inline auto parse_domain(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, domain_address>
    {
        if (buffer.empty())
        {
            return {gist::code::bad_message, {}};
        }
        std::uint8_t len = buffer[0];
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
     * @brief 解码端口号
     * @param buffer 包含端口号的缓冲区，至少 2 字节
     * @return std::pair<gist::code, uint16_t> 错误码和端口号
     * @details 从缓冲区读取 2 字节的端口号，采用大端序编码。
     * 第一个字节为高位，第二个字节为低位。
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
     * @struct udp_frame
     * @brief Trojan UDP 帧信息
     * @details 存储 UDP 帧的目标地址和端口。Trojan UDP 帧格式为：
     * ATYP(1) + LEN(2) + DST.ADDR(变长) + DST.PORT(2) + DATA(变长)。
     * 其中 LEN 字段表示地址、端口和数据的总长度。
     */
    struct udp_frame
    {
        // 目标地址
        address destination_address;
        // 目标端口
        std::uint16_t destination_port;
    };

    /**
     * @struct udp_frame_parse
     * @brief UDP 帧解析结果
     * @details 存储 UDP 帧解析后的目标地址、端口以及负载数据的位置信息。
     */
    struct udp_frame_parse
    {
        // 目标地址
        address destination_address;
        // 目标端口
        std::uint16_t destination_port;
        // 负载数据在原始缓冲区中的偏移量
        std::size_t payload_offset;
        // 负载数据的长度
        std::size_t payload_size;
    };

    /**
     * @brief 编码 Trojan UDP 帧
     * @param frame UDP 帧信息
     * @param payload 用户数据
     * @param out 输出缓冲区
     * @return gist::code 编码结果
     * @details 将 UDP 帧信息和用户数据编码为 Trojan UDP 帧格式。
     * 输出格式为：ATYP(1) + LEN(2) + DST.ADDR + DST.PORT(2) + DATA。
     * LEN 字段为大端序，表示地址、端口和数据的总长度。
     */
    inline auto encode_udp_frame(const udp_frame &frame, std::span<const std::byte> payload,
                                 memory::vector<std::byte> &out)
        -> gist::code
    {
        std::size_t addr_len = 0;
        std::visit([&addr_len]<typename Address>(const Address &addr)
                   {
            if constexpr (std::is_same_v<Address, ipv4_address>)
            {
                addr_len = 4;
            }
            else if constexpr (std::is_same_v<Address, ipv6_address>)
            {
                addr_len = 16;
            }
            else if constexpr (std::is_same_v<Address, domain_address>)
            {
                addr_len = 1 + addr.length;
            } }, frame.destination_address);

        std::uint16_t len = static_cast<std::uint16_t>(addr_len + 2 + payload.size());

        std::visit([&out]<typename Address>(const Address &addr)
                   {
            if constexpr (std::is_same_v<Address, ipv4_address>)
            {
                out.push_back(static_cast<std::byte>(0x01));
            }
            else if constexpr (std::is_same_v<Address, ipv6_address>)
            {
                out.push_back(static_cast<std::byte>(0x04));
            }
            else if constexpr (std::is_same_v<Address, domain_address>)
            {
                out.push_back(static_cast<std::byte>(0x03));
            } }, frame.destination_address);

        out.push_back(static_cast<std::byte>((len >> 8) & 0xFF));
        out.push_back(static_cast<std::byte>(len & 0xFF));

        std::visit([&out]<typename Address>(const Address &addr)
                   {
            if constexpr (std::is_same_v<Address, ipv4_address>)
            {
                out.insert(out.end(),
                    reinterpret_cast<const std::byte*>(addr.bytes.data()),
                    reinterpret_cast<const std::byte*>(addr.bytes.data()) + 4);
            }
            else if constexpr (std::is_same_v<Address, ipv6_address>)
            {
                out.insert(out.end(),
                    reinterpret_cast<const std::byte*>(addr.bytes.data()),
                    reinterpret_cast<const std::byte*>(addr.bytes.data()) + 16);
            }
            else if constexpr (std::is_same_v<Address, domain_address>)
            {
                out.push_back(static_cast<std::byte>(addr.length));
                out.insert(out.end(),
                    reinterpret_cast<const std::byte*>(addr.value.data()),
                    reinterpret_cast<const std::byte*>(addr.value.data()) + addr.length);
            } }, frame.destination_address);

        out.push_back(static_cast<std::byte>((frame.destination_port >> 8) & 0xFF));
        out.push_back(static_cast<std::byte>(frame.destination_port & 0xFF));

        out.insert(out.end(), payload.begin(), payload.end());

        return gist::code::success;
    }

    /**
     * @brief 解码 Trojan UDP 帧
     * @param buffer UDP 帧缓冲区
     * @return std::pair<gist::code, udp_frame_parse> 错误码和解析结果
     * @details 解析 Trojan UDP 帧，提取目标地址、端口和负载数据位置。
     * 帧格式为：ATYP(1) + LEN(2) + DST.ADDR + DST.PORT(2) + DATA。
     * 最小帧长度为 9 字节（ATYP + LEN + IPv4 + PORT）。
     */
    inline auto decode_udp_frame(std::span<const std::byte> buffer)
        -> std::pair<gist::code, udp_frame_parse>
    {
        if (buffer.size() < 9)
        {
            return {gist::code::bad_message, {}};
        }

        address_type atyp = static_cast<address_type>(static_cast<std::uint8_t>(buffer[0]));
        std::uint16_t len = (static_cast<std::uint16_t>(buffer[1]) << 8) |
                            static_cast<std::uint16_t>(buffer[2]);

        if (buffer.size() < static_cast<std::size_t>(3 + len))
        {
            return {gist::code::bad_message, {}};
        }

        std::size_t offset = 3;
        address dest_addr;
        std::size_t addr_size = 0;

        switch (atyp)
        {
        case address_type::ipv4:
        {
            if (len < 4 + 2)
            {
                return {gist::code::bad_message, {}};
            }
            auto addr_span = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(buffer.data() + offset), 4);
            auto [ec, addr] = parse_ipv4(addr_span);
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
            if (len < 16 + 2)
            {
                return {gist::code::bad_message, {}};
            }
            auto addr_span = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(buffer.data() + offset), 16);
            auto [ec, addr] = parse_ipv6(addr_span);
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
            if (len < 1)
            {
                return {gist::code::bad_message, {}};
            }
            std::uint8_t domain_len = static_cast<std::uint8_t>(buffer[offset]);
            if (len < 1 + domain_len + 2)
            {
                return {gist::code::bad_message, {}};
            }
            auto domain_span = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(buffer.data() + offset), 1 + domain_len);
            auto [ec, addr] = parse_domain(domain_span);
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
        auto port_span = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(buffer.data() + offset), 2);
        auto [port_ec, port] = decode_port(port_span);
        if (gist::failed(port_ec))
        {
            return {port_ec, {}};
        }

        offset += 2;
        std::size_t payload_size = len - addr_size - 2;

        udp_frame_parse result;
        result.destination_address = dest_addr;
        result.destination_port = port;
        result.payload_offset = offset;
        result.payload_size = payload_size;

        return {gist::code::success, result};
    }
}
