/**
 * @file message.hpp
 * @brief Trojan 消息结构定义
 * @details 定义 Trojan 协议中使用的地址结构和请求消息结构。
 * 地址结构支持 IPv4、IPv6 和域名三种格式，请求结构包含命令、
 * 端口、目标地址和用户凭据。所有结构设计为零拷贝友好，避免
 * 不必要的内存分配。
 */

#pragma once

#include <array>
#include <variant>
#include <string>
#include <boost/asio/ip/address.hpp>
#include <prism/protocol/trojan/constants.hpp>
#include <prism/protocol/common/form.hpp>
#include <prism/memory/container.hpp>

/**
 * @namespace psm::protocol::trojan
 * @brief Trojan 协议实现
 * @details 实现 Trojan 协议的数据结构和处理逻辑，包含地址解析、
 * 密码哈希验证和流量转发封装。遵循 Trojan 协议规范。
 */
namespace psm::protocol::trojan
{
    /**
     * @struct ipv4_address
     * @brief IPv4 地址结构
     * @details 存储 4 字节的 IPv4 地址数据，采用网络字节序。
     * 该结构用于协议解析时直接映射到缓冲区，避免内存拷贝。
     */
    struct ipv4_address
    {
        // IPv4 地址字节，网络字节序
        std::array<uint8_t, 4> bytes;
    };

    /**
     * @struct ipv6_address
     * @brief IPv6 地址结构
     * @details 存储 16 字节的 IPv6 地址数据，采用网络字节序。
     * 该结构用于协议解析时直接映射到缓冲区，避免内存拷贝。
     */
    struct ipv6_address
    {
        // IPv6 地址字节，网络字节序
        std::array<uint8_t, 16> bytes;
    };

    /**
     * @struct domain_address
     * @brief 域名地址结构
     * @details 存储域名长度和域名内容。域名长度最大为 255 字节，
     * 由协议规范限制。提供 to_string 方法用于获取域名字符串。
     *
     * @note Trojan 域名最大长度为 255 字节（1 字节长度字段限制）
     */
    struct domain_address
    {
        // 域名长度，最大 255
        std::uint8_t length;

        // 域名内容缓冲区
        std::array<char, 255> value;

        /**
         * @brief 转换为字符串
         * @param mr 内存资源指针，用于分配返回字符串
         * @return memory::string 域名字符串
         */
        [[nodiscard]] auto to_string(const memory::resource_pointer mr = memory::current_resource()) const
            -> memory::string
        {
            return memory::string(value.data(), length, mr);
        }
    };

    /**
     * @brief Trojan 地址变体类型
     * @details 使用 std::variant 统一表示 IPv4、IPv6 或域名地址。
     * 变体类型允许在编译期确定类型安全，同时支持运行时多态访问。
     */
    using address = std::variant<ipv4_address, ipv6_address, domain_address>;

    /**
     * @struct request
     * @brief Trojan 请求结构
     * @details 包含完整的 Trojan 协议请求信息，包括命令类型、
     * 目标端口、目标地址、用户凭据和传输形式。该结构由握手
         * 过程填充，后续用于路由和转发决策。
     *
     * @note 凭据长度固定为 56 字节，通常为密码的 SHA224 哈希
     */
    struct request
    {
        // 命令类型
        command cmd;

        // 目标端口，网络字节序
        uint16_t port;

        // 目标地址
        address destination_address;

        // 用户凭据，56 字节 SHA224 哈希
        std::array<char, 56> credential;

        // 传输形式，由命令类型决定
        psm::protocol::form form = psm::protocol::form::stream;
    };

    /**
     * @brief 获取地址的字符串表示
     * @param addr 地址变体
     * @param mr 内存资源指针，默认为全局资源
     * @return memory::string 地址字符串
     * @details 将 IPv4、IPv6 或域名地址转换为可读的字符串格式。
     * IPv4 和 IPv6 地址使用 Boost.Asio 进行格式化，域名地址直接
     * 返回其内容。返回的字符串使用指定的内存资源分配。
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
