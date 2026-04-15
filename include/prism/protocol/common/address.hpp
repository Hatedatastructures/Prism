/**
 * @file address.hpp
 * @brief 共享地址类型定义
 * @details 定义跨协议通用的地址结构，包括 IPv4、IPv6 和域名三种类型。
 * 各协议 (SOCKS5/Trojan/VLESS/Shadowsocks) 通过 using 声明引用这些
 * 共享类型，消除四个 message.hpp 中的重复定义。地址使用 std::variant
 * 实现类型安全的多态，所有结构设计为零拷贝友好，可直接从协议缓冲区
 * 填充。提供 address_to_string 工具函数用于调试和日志输出。
 */

#pragma once

#include <array>
#include <variant>

#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif

#include <prism/memory/container.hpp>

namespace psm::protocol::common
{
    /**
     * @struct ipv4_address
     * @brief IPv4 地址结构
     * @details 包含 4 字节的 IPv4 地址数据，采用网络字节序存储。
     * 结构设计为 POD 类型，可直接从协议缓冲区拷贝填充。
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
     * 结构设计为 POD 类型，可直接从协议缓冲区拷贝填充。
     */
    struct ipv6_address
    {
        // 地址字节数组（网络字节序）
        std::array<std::uint8_t, 16> bytes;
    };

    /**
     * @struct domain_address
     * @brief 域名地址结构
     * @details 包含域名长度和内容，遵循代理协议的域名编码格式。
     * 域名最大长度为 255 字节，由协议规范限定。提供 to_string
     * 方法用于获取可读的域名字符串表示。
     * @note 域名最大长度为 255（1 字节长度字段限制）
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
         * 内存分配器。返回的字符串包含有效的域名内容。
         */
        [[nodiscard]] auto to_string(const memory::resource_pointer mr = memory::current_resource()) const
            -> memory::string
        {
            return memory::string(value.data(), length, mr);
        }
    };

    /**
     * @brief 通用地址变体类型
     * @details 使用 std::variant 封装三种地址类型，提供类型安全的
     * 多态访问。访问者模式配合 std::visit 可实现编译期类型分发。
     */
    using address = std::variant<ipv4_address, ipv6_address, domain_address>;

    /**
     * @brief 获取地址的字符串表示
     * @param addr 地址变体
     * @param mr 内存资源指针
     * @return memory::string 地址字符串
     * @details 将地址变体转换为可读的字符串表示。IPv4 和 IPv6 地址
     * 使用 inet_ntop 进行格式化，域名直接返回原始内容。支持
     * 自定义内存分配器，适用于日志记录和调试输出场景。
     */
    [[nodiscard]] inline auto address_to_string(const address &addr,
                                                 memory::resource_pointer mr = memory::current_resource())
        -> memory::string
    {
        auto translate = [mr]<typename A>(const A &arg) -> memory::string
        {
            using type = std::decay_t<A>;
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
            else
            {
                return {};
            }
        };
        return std::visit(translate, addr);
    }
} // namespace psm::protocol::common
