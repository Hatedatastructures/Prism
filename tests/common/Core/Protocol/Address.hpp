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
#include <span>
#include <string_view>
#include <variant>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include <common/Core/Diagnose/Log.hpp>
#include <common/Core/Error.hpp>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <common/Core/Memory/Container.hpp>

namespace Preview::Protocol::Common
{

    namespace net = boost::asio;
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
         * @param mr 内存资源指针
         * @return std::string 域名字符串
         * @details 根据指定的内存资源创建域名字符串，支持自定义
         * 内存分配器。返回的字符串包含有效的域名内容。
         */
        [[nodiscard]] auto ToString(Preview::Memory::ResourcePointer mr = Preview::Memory::CurrentResource()) const
            -> Preview::Memory::String
        {
            return Preview::Memory::String(value.data(), length, mr);
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
     * @param addr 地址变体
     * @param mr 内存资源指针
     * @return std::string 地址字符串
     * @details 将地址变体转换为可读的字符串表示。IPv4 和 IPv6 地址
     * 使用 inet_ntop 进行格式化，域名直接返回原始内容。支持
     * 自定义内存分配器，适用于日志记录和调试输出场景。
     */
    [[nodiscard]] inline auto AddrToStr(const Address &addr, Preview::Memory::ResourcePointer mr = Preview::Memory::CurrentResource())
        -> Preview::Memory::String
    {
        auto Translate = [mr]<typename A>(const A &arg) -> Preview::Memory::String
        {
            using Type = std::decay_t<A>;
            if constexpr (std::is_same_v<Type, Ipv4Address>)
            {
                std::array<char, INET_ADDRSTRLEN> Buffer;
                const char *Result = inet_ntop(AF_INET, arg.Bytes.data(), Buffer.data(), Buffer.size());
                if (Result == nullptr)
                {
                    return Preview::Memory::String(mr);
                }
                return Preview::Memory::String(Buffer.data(), mr);
            }
            else if constexpr (std::is_same_v<Type, Ipv6Address>)
            {
                std::array<char, INET6_ADDRSTRLEN> Buffer;
                const char *Result = inet_ntop(AF_INET6, arg.Bytes.data(), Buffer.data(), Buffer.size());
                if (Result == nullptr)
                {
                    return Preview::Memory::String(mr);
                }
                return Preview::Memory::String(Buffer.data(), mr);
            }
            else if constexpr (std::is_same_v<Type, DomainAddress>)
            {
                return arg.ToString(mr);
            }
            else
            {
                return {};
            }
        };
        return std::visit(Translate, addr);
    }

    /**
     * @brief 解析点分十进制 IPv4 文本为 4 字节（严格校验）
     * @param text 待解析文本
     * @param out 输出字节（非法输入时置全零）
     * @return true = 合法 IPv4 文本
     */
    [[nodiscard]] inline auto ParseIpv4Text(std::string_view text, std::array<std::uint8_t, 4> &out)
        -> bool
    {
        out.fill(0);
        std::size_t Seg = 0, val = 0;
        for (const char ch : text)
        {
            if (ch == '.')
            {
                if (Seg >= 3 || val > 255)
                {
                    out.fill(0);
                    return false;
                }
                out[Seg++] = static_cast<std::uint8_t>(val);
                val = 0;
            }
            else if (ch >= '0' && ch <= '9')
            {
                val = val * 10 + static_cast<std::size_t>(ch - '0');
                if (val > 255)
                {
                    out.fill(0);
                    return false;
                }
            }
            else
            {
                out.fill(0);
                return false;
            }
        }
        if (Seg != 3 || val > 255)
        {
            out.fill(0);
            return false;
        }
        out[3] = static_cast<std::uint8_t>(val);
        return true;
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @tparam Addr 协议地址结构（须含 Type/host/port 字段与嵌套 AddressType 枚举）
     * @tparam Alloc 输出缓冲分配器
     * @param addr 目标地址
     * @param out 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     * @details 各协议共享实现：IPv4 点分十进制校验解析（非法输入输出
     *          0.0.0.0，保证 wire 格式合法）；IPv6 文本解析为 16 字节二进制
     *          （非法文本或已是二进制的输入原样拷贝）；域名长度前缀。
     *          ATYP 字节取 addr.Type 枚举值（各协议枚举值即 wire 值）。
     */
    template <typename Addr, typename Alloc>
    inline auto EncodeAddress(const Addr &addr, std::vector<std::uint8_t, Alloc> &out) -> void
    {
        using EnumT = std::decay_t<decltype(addr.Type)>;
        out.push_back(static_cast<std::uint8_t>(addr.Type));
        if (addr.Type == EnumT::Ipv4)
        {
            std::array<std::uint8_t, 4> ip{};
            static_cast<void>(ParseIpv4Text(addr.Host, ip));
            // 非法 IPv4（段数/段值/字符不符）保持全零 0.0.0.0，保证 wire 格式合法
            out.insert(out.end(), ip.begin(), ip.end());
        }
        else if (addr.Type == EnumT::Ipv6)
        {
            // 文本形式（如 "::1"）解析为 16 字节二进制（线缆约定）；
            // 非法文本或已为 16 字节二进制的输入解析失败，原样拷贝（与既有测试断言一致）
            boost::system::error_code ec;
            const auto V6 = net::ip::make_address_v6(addr.Host, ec);
            if (!ec)
            {
                const auto Bytes = V6.to_bytes();
                out.insert(out.end(), Bytes.begin(), Bytes.end());
            }
            else
            {
                out.insert(out.end(), addr.Host.begin(), addr.Host.end());
            }
        }
        else
        {
            if (addr.Host.size() > 0xFF)
            {
                // 超长域名无法用单字节长度表达：编码为空域名（接收方解析失败），
                // 禁止静默回绕——回绕会把后续 PORT 字节当长度字节，整帧错位静默损坏
                Preview::Diagnose::Error("EncodeAddress: domain too long ({} Bytes)", addr.Host.size());
                out.push_back(0x00);
            }
            else
            {
                out.push_back(static_cast<std::uint8_t>(addr.Host.size()));
                out.insert(out.end(), addr.Host.begin(), addr.Host.end());
            }
        }
        out.push_back(static_cast<std::uint8_t>((addr.Port >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(addr.Port & 0xFF));
    }

    /**
     * @brief 读取地址体（ADDR 部分，ATYP 已由调用方解析；不含 PORT）
     * @tparam Addr 协议地址结构（须含 Type/host 字段与嵌套 AddressType 枚举）
     * @tparam ReadExact 精确读取调用器（span → awaitable<bool>，true = 失败）
     * @param addr 输出地址（Type 预置，host 填充）
     * @param ReadFn 读取辅助（协议各自包装 ReadExact/ReadExactImpl）
     * @return 错误码；io_error = 读取失败，bad_message = 非法 ATYP
     * @details 各协议 Conn/Dgram 类内 ReadAddressBody 的统一实现：
     *          IPv4 读 4 字节格式化为点分十进制文本；IPv6 与域名原样拷贝。
     * @note ReadExact 按值传递：协程形参仅非引用类型会拷贝进协程帧，
     *          引用形参在调用表达式结束后悬垂（协程挂起恢复后 UB）。
     */
    template <typename Addr, typename ReadExact>
    [[nodiscard]] inline auto ReadAddressBody(Addr &addr, ReadExact ReadFn)
        -> net::awaitable<Preview::Error>
    {
        using EnumT = std::decay_t<decltype(addr.Type)>;
        if (addr.Type == EnumT::Ipv4)
        {
            std::array<std::uint8_t, 4> ip{};
            if (co_await ReadFn(std::span<std::uint8_t>(ip)))
            {
                co_return Preview::Error::IoError;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
            addr.Host = buf.data();
        }
        else if (addr.Type == EnumT::Ipv6)
        {
            std::array<std::uint8_t, 16> ip{};
            if (co_await ReadFn(std::span<std::uint8_t>(ip)))
            {
                co_return Preview::Error::IoError;
            }
            addr.Host.assign(reinterpret_cast<const char *>(ip.data()), 16);
        }
        else if (addr.Type == EnumT::Domain)
        {
            std::array<std::uint8_t, 1> len{};
            if (co_await ReadFn(std::span<std::uint8_t>(len)))
            {
                co_return Preview::Error::IoError;
            }
            std::vector<std::uint8_t> host(len[0]);
            if (co_await ReadFn(host))
            {
                co_return Preview::Error::IoError;
            }
            addr.Host.assign(reinterpret_cast<const char *>(host.data()), host.size());
        }
        else
        {
            co_return Preview::Error::BadMessage;
        }
        co_return Preview::Error::None;
    }
} // namespace Preview::Protocol::Common
