/**
 * @file message.hpp
 * @brief SOCKS5 消息结构定义
 * @details 定义 SOCKS5 协议中使用的地址结构和请求消息结构。地址
 * 结构支持 IPv4、IPv6 和域名三种类型，使用 std::variant 实现类型
 * 安全的多态。所有结构设计为零拷贝友好，避免不必要的内存分配，
 * 适用于高性能协议处理场景。
 */

#pragma once

#include <array>
#include <variant>
#include <string>

#include <boost/asio/ip/address.hpp>

#include <prism/protocol/socks5/constants.hpp>
#include <prism/protocol/common/form.hpp>
#include <prism/memory/container.hpp>

namespace psm::protocol::socks5
{
    /**
     * @struct ipv4_address
     * @brief IPv4 地址结构
     * @details 包含 4 字节的 IPv4 地址数据，采用网络字节序存储。
     * 结构设计为 POD 类型，可直接从协议缓冲区拷贝填充，无需
     * 额外转换。适用于协议解析和地址比较场景。
     */
    struct ipv4_address
    {
        // 地址字节数组（网络字节序）
        std::array<std::uint8_t, 4> bytes;
    };

    /**
     * @struct ipv6_address
     * @brief IPv6 地址结构
     * @details 包含 16 字节的 IPv6 地址数据，采用网络字节序存储。
     * 结构设计为 POD 类型，可直接从协议缓冲区拷贝填充，无需
     * 额外转换。适用于协议解析和地址比较场景。
     */
    struct ipv6_address
    {
        // 地址字节数组（网络字节序）
        std::array<std::uint8_t, 16> bytes;
    };

    /**
     * @struct domain_address
     * @brief 域名地址结构
     * @details 包含域名长度和内容，遵循 SOCKS5 协议的域名编码格式。
     * 域名最大长度为 255 字节，由协议规范限定。提供 to_string
     * 方法用于获取可读的域名字符串表示。
     * @note SOCKS5 域名最大长度为 255
     */
    struct domain_address
    {
        // 域名长度（1-255）
        std::uint8_t length;

        // 域名内容缓冲区
        std::array<char, 255> value;

        /**
         * @brief 转换为字符串
         * @param mr 内存资源指针
         * @return memory::string 域名字符串
         * @details 根据指定的内存资源创建域名字符串，支持自定义
         * 内存分配器。返回的字符串包含有效的域名内容，不包含
         * 长度前缀。
         */
        [[nodiscard]] auto to_string(const memory::resource_pointer mr = memory::current_resource()) const
            -> memory::string
        {
            return memory::string(value.data(), length, mr);
        }
    };

    /**
     * @brief SOCKS5 地址变体类型
     * @details 使用 std::variant 封装三种地址类型，提供类型安全的
     * 多态访问。访问者模式配合 std::visit 可实现编译期类型分发，
     * 避免运行时虚函数开销。适用于请求解析和响应构建场景。
     */
    using address = std::variant<ipv4_address, ipv6_address, domain_address>;

    /**
     * @struct request
     * @brief SOCKS5 请求结构
     * @details 封装客户端请求的完整信息，包括命令类型、目标端口、
     * 目标地址和传输形式。请求结构由 handshake 方法解析填充，
     * 传递给上层业务逻辑进行路由决策和连接建立。
     */
    struct request
    {
        // 命令类型
        command cmd;

        // 目标端口（主机字节序）
        uint16_t destination_port;

        // 目标地址
        address destination_address;

        // 传输形式（stream 或 datagram）
        form form = form::stream;
    };

    /**
     * @brief 获取地址的字符串表示
     * @param addr 地址变体
     * @param mr 内存资源指针
     * @return memory::string 地址字符串
     * @details 将地址变体转换为可读的字符串表示。IPv4 和 IPv6 地址
     * 使用 Boost.Asio 进行格式化，域名直接返回原始内容。支持
     * 自定义内存分配器，适用于日志记录和调试输出场景。
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
            else
            {
                return {};
            }
        };
        return std::visit(translate_address, addr);
    }
}
