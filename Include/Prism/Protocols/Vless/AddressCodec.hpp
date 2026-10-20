/**
 * @file AddressCodec.hpp
 * @brief VLESS 地址字段的 wire 编解码
 * @details 仅拥有 ATYP、地址内容和端口的编码与增量解析。请求头的
 *          端口前置顺序由 RequestCodec 组合，UDP 帧使用本头提供的
 *          ATYP + 地址 + 端口顺序。
 */

#pragma once

#include <boost/asio/ip/address_v6.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Vless/Types.hpp>

namespace Prism::Vless
{

    namespace Net = boost::asio;

    namespace Detail
    {
        /**
         * @brief 编码不含端口的地址体
         * @param AddressValue 目标地址
         * @param Output 输出缓冲
         * @return 地址合法时返回 true
         * @details 输出格式为 [ATYP][ADDR]；失败时回滚到调用前长度。
         */
        template <typename Alloc>
        inline auto EncodeAddressBody(
            const Address &AddressValue,
            std::vector<std::uint8_t, Alloc> &Output) -> bool
        {
            const auto Begin = Output.size();
            const auto Reject = [&Output, Begin]
            {
                Output.resize(Begin);
            };
            Output.push_back(static_cast<std::uint8_t>(AddressValue.Type));
            switch (AddressValue.Type)
            {
            case AddressType::Ipv4: {
                std::array<std::uint8_t, 4> Bytes{};
                if (!Prism::Protocol::Common::ParseIpv4Text(AddressValue.Host, Bytes))
                {
                    Reject();
                    return false;
                }
                Output.insert(Output.end(), Bytes.begin(), Bytes.end());
                break;
            }
            case AddressType::Ipv6: {
                boost::system::error_code ErrorCode;
                const auto Parsed = Net::ip::make_address_v6(AddressValue.Host, ErrorCode);
                if (!ErrorCode)
                {
                    const auto Bytes = Parsed.to_bytes();
                    Output.insert(Output.end(), Bytes.begin(), Bytes.end());
                }
                else if (AddressValue.Host.size() == 16)
                {
                    Output.insert(Output.end(), AddressValue.Host.begin(), AddressValue.Host.end());
                }
                else
                {
                    Reject();
                    return false;
                }
                break;
            }
            case AddressType::Domain:
                if (AddressValue.Host.empty() || AddressValue.Host.size() > 0xFF)
                {
                    Reject();
                    return false;
                }
                Output.push_back(static_cast<std::uint8_t>(AddressValue.Host.size()));
                Output.insert(Output.end(), AddressValue.Host.begin(), AddressValue.Host.end());
                break;
            default:
                Reject();
                return false;
            }
            return true;
        }

        /**
         * @brief 增量解析不含端口的地址体
         * @param Data 输入 wire
         * @param Output 输出地址
         * @param Offset 输入起始偏移，成功时指向地址体末尾
         * @return 错误码；数据不完整时返回 NeedMore
         */
        [[nodiscard]] auto ParseAddressBody(
            std::span<const std::uint8_t> Data,
            Address &Output,
            std::size_t &Offset) -> Error;
    } // namespace Detail

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @param AddressValue 目标地址
     * @param Output 输出缓冲（追加到末尾；调用方持有复用）
     * @note VLESS 对地址字段执行严格校验；非法输入不会生成部分帧。
     */
    template <typename Alloc>
    inline auto EncodeAddress(
        const Address &AddressValue,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        if (!Detail::EncodeAddressBody(AddressValue, Output))
        {
            return;
        }
        Output.push_back(static_cast<std::uint8_t>((AddressValue.Port >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(AddressValue.Port & 0xFF));
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE）
     * @param AddressValue 目标地址
     * @return 字节序列；非法地址返回空缓冲
     */
    [[nodiscard]] auto EncodeAddress(const Address &AddressValue)
        -> std::vector<std::uint8_t>;

    /**
     * @brief 解析地址字节（ATYP + ADDR + PORT 2B BE，增量）
     * @param Data 输入数据
     * @param Output 输出地址
     * @param Offset 输入起始偏移，输出结束偏移
     * @return 错误码；数据不足时返回 NeedMore
     */
    [[nodiscard]] auto ParseAddress(
        std::span<const std::uint8_t> Data,
        Address &Output,
        std::size_t &Offset) -> Error;

} // namespace Prism::Vless
