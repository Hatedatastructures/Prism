/**
 * @file message.hpp
 * @brief SOCKS5 消息结构
 * @details 定义了 SOCKS5 协议中使用的地址结构（IPv4, IPv6, Domain）和请求消息结构。
 */
#pragma once
#include <array>
#include <variant>
#include <string>
#include <boost/asio/ip/address.hpp>
#include <forward-engine/protocol/socks5/constants.hpp>
#include <forward-engine/transport/form.hpp>
#include <forward-engine/memory/container.hpp>

namespace ngx::protocol::socks5
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
        std::array<std::uint8_t, 4> bytes;
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
        std::array<std::uint8_t, 16> bytes;
    };

    /**
     * @brief 域名地址结构
     * @details 包含域名长度和内容。
     * @note SOCKS5 域名最大长度为 255。
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
     * @brief SOCKS5 地址变体
     * @details 可以是 IPv4、IPv6 或域名地址。
     */
    using address = std::variant<ipv4_address, ipv6_address, domain_address>;

    /**
     * @brief SOCKS5 请求结构
     * @details 包含命令类型、目标端口和目标地址。
     */
    struct request
    {
        command cmd;

        uint16_t destination_port;

        address destination_address;

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
        {   // 通过预编译确定类型，避免运行时判断
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
            else
            {
                return {};
            }
        };
        return std::visit(translate_address, addr);
    }
}
