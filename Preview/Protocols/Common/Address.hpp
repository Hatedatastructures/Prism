/**
 * @file Address.hpp
 * @brief 共享地址类型与编解码实现
 * @details 定义跨协议通用的地址结构，包括 IPv4、IPv6 和域名三种类型。
 * 各协议 (SOCKS5/Trojan/VLESS/Shadowsocks) 通过 using 声明引用这些
 * 共享类型，消除四个 Message.hpp 中的重复定义。地址使用 std::variant
 * 实现类型安全的多态，所有结构设计为零拷贝友好，可直接从协议缓冲区
 * 填充。提供 AddrToStr 工具函数用于调试和日志输出。
 * 另提供模板化 EncodeAddress / ReadAddressBody：各协议地址结构
 * （Type/host/port 字段）与 AddressType 枚举值可直接复用，消除
 * 6+ 份重复实现（协议内同名函数保留签名作转发层，行为零变化）。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <span>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include <Preview/Foundation/Utility/Diagnose/Log.hpp>
#include <Preview/Foundation/Error.hpp>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <Preview/Foundation/Memory/Container.hpp>

namespace Preview::Protocol::Common
{

    namespace Net = boost::asio;
    /**
     * @struct Ipv4Address
     * @brief IPv4 地址结构
     * @details 包含 4 字节的 IPv4 地址数据，采用网络字节序存储。
     * 结构设计为 POD 类型，可直接从协议缓冲区拷贝填充。
     */
    struct Ipv4Address
    {
        // 地址字节数组（网络字节序）
        std::array<std::uint8_t, 4> Bytes;
    };

    /**
     * @struct Ipv6Address
     * @brief IPv6 地址结构
     * @details 包含 16 字节的 IPv6 地址数据，采用网络字节序存储。
     * 结构设计为 POD 类型，可直接从协议缓冲区拷贝填充。
     */
    struct Ipv6Address
    {
        // 地址字节数组（网络字节序）
        std::array<std::uint8_t, 16> Bytes;
    };

    /**
     * @struct DomainAddress
     * @brief 域名地址结构
     * @details 包含域名长度和内容，遵循代理协议的域名编码格式。
     * 域名最大长度为 255 字节，由协议规范限定。提供 ToString
     * 方法用于获取可读的域名字符串表示。
     * @note 域名最大长度为 255（1 字节长度字段限制）
     */
    struct DomainAddress
    {
        // 域名长度（1-255）
        std::uint8_t length;

        // 域名内容缓冲区
        std::array<char, 255> value;

        /**
         * @brief 转换为字符串
         * @param MemoryResource 内存资源指针
         * @return std::string 域名字符串
         * @details 根据指定的内存资源创建域名字符串，支持自定义
         * 内存分配器。返回的字符串包含有效的域名内容。
         */
        [[nodiscard]] auto ToString(
            Preview::Memory::ResourcePointer MemoryResource = Preview::Memory::CurrentResource()) const
            -> Preview::Memory::String
        {
            return Preview::Memory::String(value.data(), length, MemoryResource);
        }
    };

    /**
     * @brief 通用地址变体类型
     * @details 使用 std::variant 封装三种地址类型，提供类型安全的
     * 多态访问。访问者模式配合 std::visit 可实现编译期类型分发。
     */
    using Address = std::variant<Ipv4Address, Ipv6Address, DomainAddress>;

    /**
     * @brief 获取地址的字符串表示
     * @param AddressValue 地址变体
     * @param MemoryResource 内存资源指针
     * @return std::string 地址字符串
     * @details 将地址变体转换为可读的字符串表示。IPv4 和 IPv6 地址
     * 使用 inet_ntop 进行格式化，域名直接返回原始内容。支持
     * 自定义内存分配器，适用于日志记录和调试输出场景。
     */
    [[nodiscard]] inline auto AddrToStr(
        const Address &AddressValue,
        Preview::Memory::ResourcePointer MemoryResource = Preview::Memory::CurrentResource())
        -> Preview::Memory::String
    {
        auto Translate = [MemoryResource]<typename A>(const A &Argument) -> Preview::Memory::String
        {
            using Type = std::decay_t<A>;
            if constexpr (std::is_same_v<Type, Ipv4Address>)
            {
                std::array<char, INET_ADDRSTRLEN> Buffer;
                const char *Result = inet_ntop(AF_INET, Argument.Bytes.data(), Buffer.data(), Buffer.size());
                if (Result == nullptr)
                {
                    return Preview::Memory::String(MemoryResource);
                }
                return Preview::Memory::String(Buffer.data(), MemoryResource);
            }
            else if constexpr (std::is_same_v<Type, Ipv6Address>)
            {
                std::array<char, INET6_ADDRSTRLEN> Buffer;
                const char *Result = inet_ntop(AF_INET6, Argument.Bytes.data(), Buffer.data(), Buffer.size());
                if (Result == nullptr)
                {
                    return Preview::Memory::String(MemoryResource);
                }
                return Preview::Memory::String(Buffer.data(), MemoryResource);
            }
            else if constexpr (std::is_same_v<Type, DomainAddress>)
            {
                return Argument.ToString(MemoryResource);
            }
            else
            {
                return {};
            }
        };
        return std::visit(Translate, AddressValue);
    }

    /**
     * @brief 解析点分十进制 IPv4 文本为 4 字节（严格校验）
     * @param Text 待解析文本
     * @param Output 输出字节（非法输入时置全零）
     * @return true = 合法 IPv4 文本
     */
    [[nodiscard]] inline auto ParseIpv4Text(
        std::string_view Text,
        std::array<std::uint8_t, 4> &Output) -> bool
    {
        Output.fill(0);
        std::size_t Segment = 0;
        std::size_t Value = 0;
        bool HasDigit = false;
        for (const char Character : Text)
        {
            if (Character == '.')
            {
                if (!HasDigit || Segment >= 3)
                {
                    Output.fill(0);
                    return false;
                }
                Output[Segment++] = static_cast<std::uint8_t>(Value);
                Value = 0;
                HasDigit = false;
            }
            else if (Character >= '0' && Character <= '9')
            {
                const auto Digit = static_cast<std::size_t>(Character - '0');
                if (Value > (255 - Digit) / 10)
                {
                    Output.fill(0);
                    return false;
                }
                Value = Value * 10 + Digit;
                HasDigit = true;
            }
            else
            {
                Output.fill(0);
                return false;
            }
        }
        if (Segment != 3 || !HasDigit)
        {
            Output.fill(0);
            return false;
        }
        Output[3] = static_cast<std::uint8_t>(Value);
        return true;
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @tparam Addr 协议地址结构（须含 Type/host/port 字段与嵌套 AddressType 枚举）
     * @tparam Alloc 输出缓冲分配器
     * @param AddressValue 目标地址
     * @param Output 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     * @details 各协议共享实现：IPv4 点分十进制校验解析；IPv6 文本解析为
     *          16 字节二进制（长度为 16 的输入视为已编码二进制）；域名长度前缀。
     *          非法输入不会追加部分 wire，返回 false。
     *          ATYP 字节取 addr.Type 枚举值（各协议枚举值即 wire 值）。
     */
    template <typename Addr, typename Alloc>
    inline auto EncodeAddress(
        const Addr &AddressValue,
        std::vector<std::uint8_t, Alloc> &Output) -> bool
    {
        using EnumT = std::decay_t<decltype(AddressValue.Type)>;
        if (AddressValue.Type == EnumT::Ipv4)
        {
            std::array<std::uint8_t, 4> Ipv4Bytes{};
            if (!ParseIpv4Text(AddressValue.Host, Ipv4Bytes))
            {
                return false;
            }
            Output.push_back(static_cast<std::uint8_t>(AddressValue.Type));
            Output.insert(Output.end(), Ipv4Bytes.begin(), Ipv4Bytes.end());
        }
        else if (AddressValue.Type == EnumT::Ipv6)
        {
            std::array<std::uint8_t, 16> Bytes{};
            boost::system::error_code ErrorCode;
            const auto Ipv6 = Net::ip::make_address_v6(AddressValue.Host, ErrorCode);
            if (!ErrorCode)
            {
                Bytes = Ipv6.to_bytes();
            }
            else if (AddressValue.Host.size() == Bytes.size())
            {
                std::memcpy(Bytes.data(), AddressValue.Host.data(), Bytes.size());
            }
            else
            {
                return false;
            }
            Output.push_back(static_cast<std::uint8_t>(AddressValue.Type));
            Output.insert(Output.end(), Bytes.begin(), Bytes.end());
        }
        else if (AddressValue.Type == EnumT::Domain)
        {
            if (AddressValue.Host.empty() || AddressValue.Host.size() > 0xFF)
            {
                return false;
            }
            Output.push_back(static_cast<std::uint8_t>(AddressValue.Type));
            Output.push_back(static_cast<std::uint8_t>(AddressValue.Host.size()));
            Output.insert(Output.end(), AddressValue.Host.begin(), AddressValue.Host.end());
        }
        else
        {
            return false;
        }
        Output.push_back(static_cast<std::uint8_t>((AddressValue.Port >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(AddressValue.Port & 0xFF));
        return true;
    }

    /**
     * @brief 读取地址体（ADDR 部分，ATYP 已由调用方解析；不含 PORT）
     * @tparam Addr 协议地址结构（须含 Type/host 字段与嵌套 AddressType 枚举）
     * @tparam ReadExact 精确读取调用器（span → awaitable<bool>，true = 失败）
     * @param AddressValue 输出地址（Type 预置，host 填充）
     * @param ReadFunction 读取辅助（协议各自包装 ReadExact/ReadExactImpl）
     * @return 错误码；io_error = 读取失败，bad_message = 非法 ATYP
     * @details 各协议 Conn/Dgram 类内 ReadAddressBody 的统一实现：
     *          IPv4 读 4 字节格式化为点分十进制文本；IPv6 与域名原样拷贝。
     * @note ReadExact 按值传递：协程形参仅非引用类型会拷贝进协程帧，
     *          引用形参在调用表达式结束后悬垂（协程挂起恢复后 UB）。
     */
    template <typename Addr, typename ReadExact>
    [[nodiscard]] inline auto ReadAddressBody(
        Addr &AddressValue,
        ReadExact ReadFunction) -> Net::awaitable<Preview::Error>
    {
        using EnumT = std::decay_t<decltype(AddressValue.Type)>;
        if (AddressValue.Type == EnumT::Ipv4)
        {
            std::array<std::uint8_t, 4> Ipv4Bytes{};
            if (co_await ReadFunction(std::span<std::uint8_t>(Ipv4Bytes)))
            {
                co_return Preview::Error::IoError;
            }
            std::array<char, 16> Buffer{};
            std::snprintf(
                Buffer.data(),
                Buffer.size(),
                "%u.%u.%u.%u",
                Ipv4Bytes[0],
                Ipv4Bytes[1],
                Ipv4Bytes[2],
                Ipv4Bytes[3]);
            AddressValue.Host = Buffer.data();
        }
        else if (AddressValue.Type == EnumT::Ipv6)
        {
            std::array<std::uint8_t, 16> Ipv6Bytes{};
            if (co_await ReadFunction(std::span<std::uint8_t>(Ipv6Bytes)))
            {
                co_return Preview::Error::IoError;
            }
            AddressValue.Host.assign(reinterpret_cast<const char *>(Ipv6Bytes.data()), Ipv6Bytes.size());
        }
        else if (AddressValue.Type == EnumT::Domain)
        {
            std::array<std::uint8_t, 1> Length{};
            if (co_await ReadFunction(std::span<std::uint8_t>(Length)))
            {
                co_return Preview::Error::IoError;
            }
            std::vector<std::uint8_t> Host(Length[0]);
            if (co_await ReadFunction(Host))
            {
                co_return Preview::Error::IoError;
            }
            AddressValue.Host.assign(reinterpret_cast<const char *>(Host.data()), Host.size());
        }
        else
        {
            co_return Preview::Error::BadMessage;
        }
        co_return Preview::Error::None;
    }
} // namespace Preview::Protocol::Common
