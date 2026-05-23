/**
 * @file protocol_type.hpp
 * @brief 协议类型枚举定义
 * @details 定义代理系统支持的所有应用层协议类型枚举，以及将枚举值转换
 * 为可读字符串的工具函数。该模块是协议系统的核心类型定义，被协议识别、
 * 分发、管道等模块广泛引用。使用 enum class 提供类型安全，避免隐式转换。
 * 协议探测失败时返回 unknown。路由决策根据协议类型选择不同的处理管道。
 * @note 所有函数都是线程安全的，可并发调用。
 * @warning 不要依赖枚举值的具体数值，仅使用符号名称。
 */
#pragma once

#include <cstdint>
#include <string_view>

namespace psm::protocol {

/**
 * @enum protocol_type
 * @brief 协议类型枚举
 * @details 标识当前连接所使用的应用层协议类型，用于协议探测和路由
 * 决策。该枚举涵盖了代理系统支持的所有主要协议类型。使用 enum class
 * 提供类型安全，避免隐式转换。值顺序固定，可用于 switch 语句优化。
 * 预留扩展空间，未来可添加新协议类型。协议探测失败时返回 unknown。
 * 路由决策根据协议类型选择不同的处理管道。日志输出使用 to_string_view
 * 转换为可读字符串。
 * @note TLS 协议是一个通用类别，包含多种基于 TLS 的代理协议。
 * @warning 不要依赖枚举值的具体数值，仅使用符号名称。
 */
enum class protocol_type : std::uint8_t {
    /** @brief 未知协议 */
    unknown,
    /** @brief HTTP 协议 */
    http,
    /** @brief SOCKS5 协议 */
    socks5,
    /** @brief Trojan 协议 */
    trojan,
    /** @brief VLESS 协议 */
    vless,
    /** @brief Shadowsocks 2022 协议 */
    shadowsocks,
    /** @brief TLS 协议 */
    tls
};

/**
 * @brief 将协议类型转换为字符串视图
 * @details 将 protocol_type 枚举值转换为可读的字符串表示，用于日志
 * 输出、调试和监控。该函数提供编译时已知的字符串字面量，无运行时
 * 分配开销。映射关系为 unknown 对应 "unknown"，http 对应 "http"，
 * socks5 对应 "socks5"，tls 对应 "tls"，其他值安全回退到 "unknown"。
 * 函数设计为 inline 建议编译器内联展开，消除函数调用开销。无异常，
 * 适合所有上下文使用。纯函数，无状态，可并发调用。使用 switch 语句
 * 实现高效跳转表，返回编译时常量字符串字面量，无拷贝开销。
 * @param type 协议类型枚举值
 * @return std::string_view 协议类型的字符串表示，指向编译时常量
 * @note 返回的字符串视图指向静态存储期的字符串字面量，生命周期与
 * 程序相同。
 * @warning 不要修改返回的字符串视图内容，它是只读的。
 */
[[nodiscard]] inline auto to_string_view(const protocol_type type)
    -> std::string_view
{
    switch (type)
    {
    case protocol_type::unknown:
        return "unknown";
    case protocol_type::http:
        return "http";
    case protocol_type::socks5:
        return "socks5";
    case protocol_type::trojan:
        return "trojan";
    case protocol_type::vless:
        return "vless";
    case protocol_type::shadowsocks:
        return "shadowsocks";
    case protocol_type::tls:
        return "tls";
    default:
        return "unknown";
    }
}

} // namespace psm::protocol
