/**
 * @file AddressCodec.hpp
 * @brief SOCKS5 地址字段的 wire 编解码
 * @details 仅拥有 ATYP、地址内容与端口的编码和增量解析；不依赖
 *          握手状态或传输对象。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>

namespace Prism::Socks5
{

    namespace Detail
    {
        /**
         * @brief 将四字节 IPv4 地址格式化为点分十进制文本
         */
        [[nodiscard]] inline auto FormatIpv4(const std::uint8_t *Bytes, std::string &Host) -> bool
        {
            std::array<char, 16> Buffer{};
            auto *Cursor = Buffer.data();
            for (std::size_t Index = 0; Index < 4; ++Index)
            {
                if (Index != 0)
                {
                    *Cursor++ = '.';
                }
                const auto [End, ErrorCode] = std::to_chars(
                    Cursor, Buffer.data() + Buffer.size(), static_cast<unsigned int>(Bytes[Index]));
                if (ErrorCode != std::errc{})
                {
                    return false;
                }
                Cursor = End;
            }
            Host.assign(Buffer.data(), Cursor);
            return true;
        }
    } // namespace Detail

    /**
     * @brief 编码地址并追加到调用方持有的缓冲
     * @param AddressValue 目标地址
     * @param Output 输出缓冲
     * @return 地址合法且追加成功返回 true
     * @details IPv4 与域名沿用公共编码；IPv6 接受协议地址中的 16 字节网络序值。
     */
    template <typename Alloc>
    inline auto EncodeAddress(
        const Address &AddressValue,
        std::vector<std::uint8_t, Alloc> &Output) -> bool
    {
        return Prism::Protocol::Common::EncodeAddress(AddressValue, Output);
    }

    /**
     * @brief 编码地址
     * @param AddressValue 目标地址
     * @return ATYP、地址内容和大端端口；非法地址返回空缓冲
     */
    [[nodiscard]] inline auto EncodeAddress(const Address &AddressValue)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        if (!EncodeAddress(AddressValue, Output))
        {
            return {};
        }
        return Output;
    }

    /**
     * @brief 增量解析地址
     * @param Data 输入 wire
     * @param Output 输出地址
     * @param Consumed 输出已消费字节数
     * @return 错误码；数据不完整时返回 NeedMore
     * @details IPv6 Host 保留线上的 16 个网络序字节，IPv4 Host 使用点分文本。
     */
    [[nodiscard]] inline auto ParseAddress(
        std::span<const std::uint8_t> Data,
        Address &Output,
        std::size_t &Consumed) -> Error
    {
        if (Data.empty())
        {
            return Error::NeedMore;
        }
        Output.Type = static_cast<AddressType>(Data[0]);
        std::size_t Off = 1;
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < Off + 4 + 2)
            {
                return Error::NeedMore;
            }
            if (!Detail::FormatIpv4(Data.data() + Off, Output.Host))
            {
                return Error::BadMessage;
            }
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < Off + 16 + 2)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain: {
            if (Off >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Len = Data[Off++];
            if (Len == 0)
            {
                return Error::BadMessage;
            }
            if (Data.size() < Off + Len + 2)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Len);
            Off += Len;
            break;
        }
        default:
            return Error::BadMessage;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Consumed = Off + 2;
        return Error::None;
    }

    /**
     * @brief 按 SOCKS5 wire 表示读取 ATYP 后的地址体。
     * @param Output 已设置 Type 的输出地址
     * @param ReadExact 精确读取回调，true 表示底层读取失败
     * @return 地址体读取结果；截断返回 IoError，非法域名长度返回 BadMessage
     * @details IPv6 保留 16 个网络序字节，使解析结果可直接往返编码或转换为 Network::Target。
     */
    template <typename ReadExact>
    [[nodiscard]] inline auto ReadAddressBody(Address &Output, ReadExact Read)
        -> boost::asio::awaitable<Error>
    {
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            std::array<std::uint8_t, 4> Bytes{};
            if (co_await Read(std::span<std::uint8_t>(Bytes)))
            {
                co_return Error::IoError;
            }
            if (!Detail::FormatIpv4(Bytes.data(), Output.Host))
            {
                co_return Error::BadMessage;
            }
            break;
        }
        case AddressType::Ipv6: {
            std::array<std::uint8_t, 16> Bytes{};
            if (co_await Read(std::span<std::uint8_t>(Bytes)))
            {
                co_return Error::IoError;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Bytes.data()), Bytes.size());
            break;
        }
        case AddressType::Domain: {
            std::array<std::uint8_t, 1> Length{};
            if (co_await Read(std::span<std::uint8_t>(Length)))
            {
                co_return Error::IoError;
            }
            if (Length[0] == 0)
            {
                co_return Error::BadMessage;
            }
            std::array<std::uint8_t, 255> Bytes{};
            const auto Host = std::span<std::uint8_t>(Bytes.data(), Length[0]);
            if (co_await Read(Host))
            {
                co_return Error::IoError;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Bytes.data()), Length[0]);
            break;
        }
        default:
            co_return Error::BadMessage;
        }
        co_return Error::None;
    }

} // namespace Prism::Socks5
