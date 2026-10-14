/**
 * @file AddressCodec.hpp
 * @brief Trojan 地址字段的 wire 编解码
 * @details 只拥有 ATYP、地址内容与端口的编码和增量解析；不依赖
 *          请求状态或传输对象。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Protocols/Trojan/Types.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <vector>

namespace Preview::Trojan
{

    namespace Detail
    {
        /** @brief 将 IPv4 wire bytes 格式化为 Address 的点分文本表示。 */
        [[nodiscard]] inline auto FormatIpv4(const std::uint8_t *Bytes, std::string &Host)
            -> bool
        {
            std::array<char, 16> Buffer{};
            const auto Length = std::snprintf(
                Buffer.data(), Buffer.size(), "%u.%u.%u.%u",
                static_cast<unsigned int>(Bytes[0]), static_cast<unsigned int>(Bytes[1]),
                static_cast<unsigned int>(Bytes[2]), static_cast<unsigned int>(Bytes[3]));
            if (Length < 0 || static_cast<std::size_t>(Length) >= Buffer.size())
            {
                return false;
            }
            Host.assign(Buffer.data(), static_cast<std::size_t>(Length));
            return true;
        }
    } // namespace Detail

    /**
     * @brief 编码地址并追加到调用方持有的缓冲
     * @param AddressValue 目标地址
     * @param Output 输出缓冲
     * @return 地址合法且追加成功返回 true
     * @details 转发到协议公共地址编码，保留 Trojan 的地址字段签名。
     */
    template <typename Alloc>
    inline auto EncodeAddress(const Address& AddressValue, std::vector<std::uint8_t, Alloc>& Output) -> bool
    {
        return Preview::Protocol::Common::EncodeAddress(AddressValue, Output);
    }

    /**
     * @brief 编码地址
     * @param AddressValue 目标地址
     * @return ATYP、地址内容和大端端口；非法地址返回空缓冲
     */
    [[nodiscard]] inline auto EncodeAddress(const Address& AddressValue) -> std::vector<std::uint8_t>
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
     */
    [[nodiscard]] inline auto ParseAddress(std::span<const std::uint8_t> Data, Address& Output,
        std::size_t& Consumed) -> Error
    {
        if (Data.empty())
        {
            return Error::NeedMore;
        }
        Output.Type = static_cast<AddressType>(Data[0]);
        std::size_t Offset = 1;
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Offset < 4 + 2)
            {
                return Error::NeedMore;
            }
            if (!Detail::FormatIpv4(Data.data() + Offset, Output.Host))
            {
                return Error::BadMessage;
            }
            Offset += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() - Offset < 16 + 2)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char*>(Data.data() + Offset), 16);
            Offset += 16;
            break;
        }
        case AddressType::Domain: {
            if (Data.size() - Offset < 1)
            {
                return Error::NeedMore;
            }
            const auto Length = Data[Offset++];
            if (Length == 0)
            {
                return Error::BadMessage;
            }
            if (Data.size() - Offset < Length + 2)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char*>(Data.data() + Offset), Length);
            Offset += Length;
            break;
        }
        default:
            return Error::BadMessage;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Offset]) << 8 | Data[Offset + 1];
        Offset += 2;
        Consumed = Offset;
        return Error::None;
    }

    /**
     * @brief 按 Trojan wire 表示读取 ATYP 后的地址体。
     * @param Output 已设置 Type 的输出地址
     * @param ReadExact 精确读取回调，true 表示底层读取失败
     * @return 地址体读取结果；截断返回 IoError，非法域名长度返回 BadMessage
     * @details IPv6 保留 16 个网络序字节，与 ParseAddress 和 Network::Target 契约一致。
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

} // namespace Preview::Trojan
