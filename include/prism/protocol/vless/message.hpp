/**
 * @file message.hpp
 * @brief VLESS 消息结构定义
 * @details 定义 VLESS 协议中使用的地址结构和请求消息结构。
 * 地址结构支持 IPv4、IPv6 和域名三种格式，请求结构包含命令、
 * 端口、目标地址和用户 UUID。所有结构设计为零拷贝友好。
 */

#pragma once

#include <array>
#include <variant>
#include <string>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <prism/protocol/vless/constants.hpp>
#include <prism/protocol/common/form.hpp>
#include <prism/memory/container.hpp>

namespace psm::protocol::vless
{
    /**
     * @struct ipv4_address
     * @brief IPv4 地址结构
     * @details 存储 4 字节的 IPv4 地址数据，采用网络字节序。
     */
    struct ipv4_address
    {
        std::array<uint8_t, 4> bytes;
    };

    /**
     * @struct ipv6_address
     * @brief IPv6 地址结构
     * @details 存储 16 字节的 IPv6 地址数据，采用网络字节序。
     */
    struct ipv6_address
    {
        std::array<uint8_t, 16> bytes;
    };

    /**
     * @struct domain_address
     * @brief 域名地址结构
     * @details 存储域名长度和域名内容。域名长度最大为 255 字节。
     */
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

    /// VLESS 地址变体类型
    using address = std::variant<ipv4_address, ipv6_address, domain_address>;

    /**
     * @struct request
     * @brief VLESS 请求结构
     * @details 包含完整的 VLESS 协议请求信息，包括用户 UUID、
     * 命令类型、目标端口、目标地址和传输形式。
     */
    struct request
    {
        // 用户 UUID（16 字节原始数据）
        std::array<uint8_t, 16> uuid;

        // 命令类型
        command cmd;

        // 目标端口，主机字节序
        uint16_t port;

        // 目标地址
        address destination_address;

        // 传输形式，由命令类型决定
        psm::protocol::form form = psm::protocol::form::stream;
    };

    /**
     * @brief 获取地址的字符串表示
     * @param addr 地址变体
     * @param mr 内存资源指针
     * @return memory::string 地址字符串
     */
    inline auto to_string(const address &addr, memory::resource_pointer mr = memory::current_resource())
        -> memory::string
    {
        auto translate_address = [mr]<typename Address>(const Address &arg) -> memory::string
        {
            using type = std::decay_t<Address>;
            if constexpr (std::is_same_v<type, ipv4_address>)
            {
                std::array<char, INET_ADDRSTRLEN> buffer;
                const char *result = inet_ntop(AF_INET, arg.bytes.data(), buffer.data(), buffer.size());
                if (result == nullptr)
                {
                    return memory::string(mr);
                }
                return memory::string(buffer.data(), mr);
            }
            else if constexpr (std::is_same_v<type, ipv6_address>)
            {
                std::array<char, INET6_ADDRSTRLEN> buffer;
                const char *result = inet_ntop(AF_INET6, arg.bytes.data(), buffer.data(), buffer.size());
                if (result == nullptr)
                {
                    return memory::string(mr);
                }
                return memory::string(buffer.data(), mr);
            }
            else if constexpr (std::is_same_v<type, domain_address>)
            {
                return arg.to_string(mr);
            }
            return {};
        };
        return std::visit(translate_address, addr);
    }
}
