#pragma once
#include <array>
#include <variant>
#include <string>
#include <boost/asio/ip/address.hpp>
#include <forward-engine/protocol/trojan/constants.hpp>
#include <forward-engine/memory/container.hpp>

namespace ngx::protocol::trojan
{
    /**
     * @brief IPv4 地址结构
     */
    struct ipv4_address
    {
        std::array<uint8_t, 4> bytes;
    };

    /**
     * @brief IPv6 地址结构
     */
    struct ipv6_address
    {
        std::array<uint8_t, 16> bytes;
    };

    /**
     * @brief 域名地址结构
     * @note Trojan 域名最大长度为 255 (1 字节长度)
     */
    struct domain_address
    {
        std::uint8_t length;
        std::array<char, 255> value;

        [[nodiscard]] memory::string to_string(const memory::resource_pointer mr = memory::current_resource()) const
        {
            return memory::string(value.data(), length, mr);
        }
    };

    /**
     * @brief Trojan 地址变体
     */
    using address = std::variant<ipv4_address, ipv6_address, domain_address>;

    /**
     * @brief Trojan 请求结构
     */
    struct request
    {
        command cmd;
        uint16_t port;
        address destination_address;
        std::array<char, 56> password_hash;
    };

    /**
     * @brief 获取地址的字符串表示
     * @param addr 地址变体
     * @param mr 内存资源指针 (默认为全局资源)
     * @return ngx::memory::string 地址字符串
     */
    inline memory::string to_string(const address &addr, memory::resource_pointer mr = memory::current_resource())
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
