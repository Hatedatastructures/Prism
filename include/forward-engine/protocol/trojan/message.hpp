/**
 * @file message.hpp
 * @brief Trojan 消息结构
 * @details 定义了 Trojan 协议中使用的地址结构（IPv4, IPv6, Domain）和请求消息结构。
 */
#pragma once
#include <array>
#include <variant>
#include <string>
#include <boost/asio/ip/address.hpp>
#include <forward-engine/protocol/trojan/constants.hpp>
#include <forward-engine/transport/form.hpp>
#include <forward-engine/memory/container.hpp>

/**
 * @namespace ngx::protocol::trojan
 * @brief Trojan 协议实现
 * @details 实现了 Trojan 协议 (Trojan-GFW) 的数据结构和处理逻辑。
 * 包含地址解析、密码哈希验证和流量转发封装。
 */
namespace ngx::protocol::trojan
{
    /**
     * @brief IPv4 地址结构
     * @details 包含 4 字节的 IPv4 地址数据。
     */
    struct ipv4_address
    {
        /**
         * @brief 地址字节数组
         */
        std::array<uint8_t, 4> bytes;
    };

    /**
     * @brief IPv6 地址结构
     * @details 包含 16 字节的 IPv6 地址数据。
     */
    struct ipv6_address
    {
        /**
         * @brief 地址字节数组
         */
        std::array<uint8_t, 16> bytes;
    };

    /**
     * @brief 域名地址结构
     * @details 包含域名长度和内容。
     * @note Trojan 域名最大长度为 255 (1 字节长度)。
     */
    struct domain_address
    {
        /**
         * @brief 域名长度
         */
        std::uint8_t length;

        /**
         * @brief 域名内容缓冲区
         */
        std::array<char, 255> value;

        /**
         * @brief 转换为字符串
         * @param mr 内存资源指针
         * @return memory::string 域名字符串
         */
        [[nodiscard]] auto to_string(const memory::resource_pointer mr = memory::current_resource()) const
            -> memory::string
        {
            return memory::string(value.data(), length, mr);
        }
    };

    /**
     * @brief Trojan 地址变体
     * @details 可以是 IPv4、IPv6 或域名地址。
     */
    using address = std::variant<ipv4_address, ipv6_address, domain_address>;

    /**
     * @brief Trojan 请求结构
     * @details 包含命令类型、端口、目标地址和用户凭据。
     */
    struct request
    {
        command cmd;

        uint16_t port;

        address destination_address;

        std::array<char, 56> credential;

        transport::form form = transport::form::stream;
    };

    /**
     * @brief 获取地址的字符串表示
     * @param addr 地址变体
     * @param mr 内存资源指针 (默认为全局资源)
     * @return ngx::memory::string 地址字符串
     */
    inline auto to_string(const address &addr, memory::resource_pointer mr = memory::current_resource())
        -> memory::string
    {
        auto translate_address = [mr]<typename Address>(const Address& arg)-> memory::string
        {
            using type = std::decay_t<Address>;
            if constexpr (std::is_same_v<type, ipv4_address>)
            {
                std::string str = boost::asio::ip::make_address_v4(arg.bytes).to_string();
                return memory::string(str.begin(), str.end(), mr);
            }
            else if constexpr (std::is_same_v<type, ipv6_address>)
            {
                std::string str = boost::asio::ip::make_address_v6(arg.bytes).to_string();
                return memory::string(str.begin(), str.end(), mr);
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
