/**
 * @file MessageCodec.hpp
 * @brief SOCKS5 Greeting、请求、响应和 UDP 数据报的 wire 编解码
 * @details 该头只拥有无状态消息转换；地址字段由 AddressCodec 拥有，
 *          RFC 1929 用户名/密码由 AuthCodec 拥有。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Socks5/AddressCodec.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>

namespace Prism::Socks5
{

    /**
     * @brief 编码 Greeting 并覆盖写入复用缓冲
     * @details 方法列表超过 255 项时输出为空。
     */
    template <typename Alloc>
    inline auto BuildGreeting(
        const Greeting &GreetingValue,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        if (GreetingValue.Methods.size() > 0xFF)
        {
            return;
        }
        Output.reserve(2 + GreetingValue.Methods.size());
        Output.push_back(GreetingValue.Ver);
        Output.push_back(static_cast<std::uint8_t>(GreetingValue.Methods.size()));
        Output.insert(Output.end(), GreetingValue.Methods.begin(), GreetingValue.Methods.end());
    }

    /**
     * @brief 编码 Greeting
     */
    [[nodiscard]] auto BuildGreeting(const Greeting &GreetingValue)
        -> std::vector<std::uint8_t>;

    /**
     * @brief 增量解析 Greeting
     */
    [[nodiscard]] auto ParseGreeting(
        std::span<const std::uint8_t> Data,
        Greeting &Output,
        std::size_t &Consumed) -> Error;

    /**
     * @brief 编码方法选择回复
     */
    [[nodiscard]] auto BuildMethodReply(const MethodReply &MethodReplyValue)
        -> std::array<std::uint8_t, 2>;

    /**
     * @brief 解析方法选择回复
     */
    [[nodiscard]] auto ParseMethodReply(
        std::span<const std::uint8_t> Data,
        MethodReply &Output) -> Error;

    /**
     * @brief 编码请求并覆盖写入复用缓冲
     * @details 头部写入后直接续写地址，避免中间地址缓冲。
     */
    template <typename Alloc>
    inline auto BuildRequest(
        const Request &RequestValue,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        Output.reserve(3 + RequestValue.Target.Host.size() + 8);
        Output.push_back(RequestValue.Ver);
        Output.push_back(static_cast<std::uint8_t>(RequestValue.Cmd));
        Output.push_back(RequestValue.Rsv);
        if (!EncodeAddress(RequestValue.Target, Output))
        {
            Output.clear();
        }
    }

    /**
     * @brief 编码请求
     */
    [[nodiscard]] auto BuildRequest(const Request &RequestValue)
        -> std::vector<std::uint8_t>;

    /**
     * @brief 增量解析请求
     */
    [[nodiscard]] auto ParseRequest(
        std::span<const std::uint8_t> Data,
        Request &Output,
        std::size_t &Consumed) -> Error;

    /**
     * @brief 编码响应并覆盖写入复用缓冲
     */
    template <typename Alloc>
    inline auto BuildReply(
        const Reply &ReplyValue,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        Output.reserve(3 + ReplyValue.Bind.Host.size() + 8);
        Output.push_back(ReplyValue.Ver);
        Output.push_back(static_cast<std::uint8_t>(ReplyValue.Code));
        Output.push_back(ReplyValue.Rsv);
        if (!EncodeAddress(ReplyValue.Bind, Output))
        {
            Output.clear();
        }
    }

    /**
     * @brief 编码响应
     */
    [[nodiscard]] auto BuildReply(const Reply &ReplyValue)
        -> std::vector<std::uint8_t>;

    /**
     * @brief 增量解析响应
     */
    [[nodiscard]] auto ParseReply(
        std::span<const std::uint8_t> Data,
        Reply &Output,
        std::size_t &Consumed) -> Error;

    /**
     * @brief 编码 SOCKS5 UDP 数据报并覆盖写入复用缓冲
     * @details RSV 两字节和 FRAG 字节固定为 0，载荷边界由底层 datagram
     *          读取决定。
     */
    template <typename Alloc>
    inline auto BuildUdpDatagram(
        const Address &Target,
        std::span<const std::uint8_t> Payload,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        Output.reserve(3 + Target.Host.size() + 8 + Payload.size());
        Output.push_back(0x00);
        Output.push_back(0x00);
        Output.push_back(0x00);
        if (!EncodeAddress(Target, Output))
        {
            Output.clear();
            return;
        }
        Output.insert(Output.end(), Payload.begin(), Payload.end());
    }

    /**
     * @brief 编码 SOCKS5 UDP 数据报
     */
    [[nodiscard]] auto BuildUdpDatagram(
        const Address &Target,
        std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>;

    /**
     * @brief 解析 SOCKS5 UDP 数据报
     * @param Data 输入 datagram
     * @param Target 输出目标地址
     * @param Payload 输出载荷视图，指向 Data
     */
    [[nodiscard]] auto ParseUdpDatagram(
        std::span<const std::uint8_t> Data,
        Address &Target,
        std::span<const std::uint8_t> &Payload) -> Error;

} // namespace Prism::Socks5
