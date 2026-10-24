/**
 * @file AddressCodec.hpp
 * @brief Trojan 地址字段的 wire 编解码
 * @details 只拥有 ATYP、地址内容与端口的编码和增量解析；不依赖
 *          请求状态或传输对象。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Trojan/Types.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>
#include <string>

namespace Prism::Trojan
{

    namespace Detail
    {
        /** @brief 将 IPv4 wire bytes 格式化为 Address 的点分文本表示。 */
        [[nodiscard]] auto FormatIpv4(const std::uint8_t *Bytes, std::string &Host)
            -> bool;
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
        return Prism::Protocol::Common::EncodeAddress(AddressValue, Output);
    }

    /**
     * @brief 编码地址
     * @param AddressValue 目标地址
     * @return ATYP、地址内容和大端端口；非法地址返回空缓冲
     */
    [[nodiscard]] auto EncodeAddress(const Address& AddressValue) -> std::vector<std::uint8_t>;

    /**
     * @brief 增量解析地址
     * @param Data 输入 wire
     * @param Output 输出地址
     * @param Consumed 输出已消费字节数
     * @return 错误码；数据不完整时返回 NeedMore
     */
    [[nodiscard]] auto ParseAddress(std::span<const std::uint8_t> Data, Address& Output,
        std::size_t& Consumed) -> Error;

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

} // namespace Prism::Trojan
