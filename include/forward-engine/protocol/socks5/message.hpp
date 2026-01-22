#pragma once
#include <array>
#include <variant>
#include <string>
#include <boost/asio/ip/address.hpp>
#include <forward-engine/protocol/socks5/constants.hpp>
#include <forward-engine/memory/container.hpp>

namespace ngx::protocol::socks5
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
     * @note SOCKS5 域名最大长度为 255
     */
    struct domain_address
    {
        uint8_t length;
        std::array<char, 255> value;

        [[nodiscard]] ngx::memory::string to_string(ngx::memory::resource_pointer mr = ngx::memory::current_resource()) const
        {
            return ngx::memory::string(value.data(), length, mr);
        }
    };

    /**
     * @brief SOCKS5 地址变体
     */
    using address = std::variant<ipv4_address, ipv6_address, domain_address>;

    /**
     * @brief SOCKS5 请求结构
     */
    struct request
    {
        command cmd;
        uint16_t destination_port;
        address destination_address;
    };

    /**
     * @brief 获取地址的字符串表示
     * @param addr 地址变体
     * @param mr 内存资源指针 (默认为全局资源)
     * @return ngx::memory::string 地址字符串
     */
    inline ngx::memory::string to_string(const address &addr, ngx::memory::resource_pointer mr = ngx::memory::current_resource())
    {
        auto translate_address = [mr](const auto& arg)-> memory::string
        {   // 通过预编译确定类型，避免运行时判断
            using Type = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<Type, ipv4_address>)
            {
                std::string str = boost::asio::ip::make_address_v4(arg.bytes).to_string();
                return memory::string(str.begin(), str.end(), mr);
            }
            else if constexpr (std::is_same_v<Type, ipv6_address>)
            {
                std::string str = boost::asio::ip::make_address_v6(arg.bytes).to_string();
                return memory::string(str.begin(), str.end(), mr);
            }
            else if constexpr (std::is_same_v<Type, domain_address>)
            {
                return arg.to_string(mr);
            }
        };
        return std::visit(translate_address, addr);
    }
}
