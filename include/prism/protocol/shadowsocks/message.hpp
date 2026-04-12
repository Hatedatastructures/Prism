/**
 * @file message.hpp
 * @brief SS2022 消息结构定义
 * @details 定义 SS2022 协议中使用的地址结构和请求消息结构。
 * 地址格式与 SOCKS5 兼容，支持 IPv4、IPv6 和域名。
 */

#pragma once

#include <array>
#include <variant>
#include <cstdint>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/memory/container.hpp>

namespace psm::protocol::shadowsocks
{
    /// IPv4 地址（4 字节，网络字节序）
    struct ipv4_address
    {
        std::array<std::uint8_t, 4> bytes;
    };

    /// IPv6 地址（16 字节，网络字节序）
    struct ipv6_address
    {
        std::array<std::uint8_t, 16> bytes;
    };

    /// 域名地址（1 字节长度 + 最多 255 字节域名）
    struct domain_address
    {
        std::uint8_t length;
        std::array<char, 255> value;

        [[nodiscard]] auto to_string(const memory::resource_pointer mr = memory::current_resource()) const
            -> memory::string
        {
            return memory::string(value.data(), length, mr);
        }
    };

    /// 地址变体类型
    using address = std::variant<ipv4_address, ipv6_address, domain_address>;

    /// SS2022 请求结构（由 handshake 填充）
    struct request
    {
        /// 加密算法
        cipher_method method;

        /// 目标端口
        std::uint16_t port{0};

        /// 目标地址
        address destination_address;

        /// 握手中的初始 payload（可能为空）
        memory::vector<std::byte> initial_payload;
    };

    /**
     * @brief 获取地址的字符串表示
     * @param addr 地址变体
     * @param mr 内存资源指针
     * @return 地址字符串
     */
    inline auto to_string(const address &addr, const memory::resource_pointer mr = memory::current_resource())
        -> memory::string
    {
        auto translate = [mr]<typename A>(const A &arg) -> memory::string
        {
            using type = std::decay_t<A>;
            if constexpr (std::is_same_v<type, ipv4_address>)
            {
                std::array<char, INET_ADDRSTRLEN> buf{};
                const char *r = inet_ntop(AF_INET, arg.bytes.data(), buf.data(), buf.size());
                return r ? memory::string(r, mr) : memory::string(mr);
            }
            else if constexpr (std::is_same_v<type, ipv6_address>)
            {
                std::array<char, INET6_ADDRSTRLEN> buf{};
                const char *r = inet_ntop(AF_INET6, arg.bytes.data(), buf.data(), buf.size());
                return r ? memory::string(r, mr) : memory::string(mr);
            }
            else if constexpr (std::is_same_v<type, domain_address>)
            {
                return arg.to_string(mr);
            }
            return {};
        };
        return std::visit(translate, addr);
    }
} // namespace psm::protocol::shadowsocks
