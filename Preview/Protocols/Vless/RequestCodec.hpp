/**
 * @file RequestCodec.hpp
 * @brief VLESS 握手请求与响应 wire 编解码
 * @details 只拥有版本、UUID、附加字段、命令和目标地址组成的请求头。
 *          TCP/UDP 请求使用 [PORT][ATYP][ADDR] 顺序，Mux 请求在命令后结束。
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Vless/AddressCodec.hpp>
#include <Preview/Protocols/Vless/Types.hpp>

namespace Preview::Vless
{

    /**
     * @brief 构造 VLESS 请求头字节并覆盖写入复用缓冲
     * @param RequestValue 请求头
     * @param Output 输出缓冲（调用方持有复用）
     * @details 通用头为 [Version 1B][UUID 16B][AddnlLen 1B][Addnl var][Cmd 1B]；
     *          TCP/UDP 命令再附加 [Port 2B BE][Atyp 1B][Addr var]，Mux 命令则结束。
     */
    template <typename Alloc>
    inline auto BuildRequest(
        const RequestHeader &RequestValue,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        if (RequestValue.Version != ProtocolVersion || RequestValue.Addons.size() > 0xFF ||
            (RequestValue.Cmd != Command::Tcp && RequestValue.Cmd != Command::Udp &&
             RequestValue.Cmd != Command::Mux))
        {
            return;
        }
        const auto IsMux = RequestValue.Cmd == Command::Mux;
        Output.reserve((IsMux ? 19U : 22U) + RequestValue.Addons.size() +
                       (IsMux ? 0U : RequestValue.Target.Host.size()));
        Output.push_back(RequestValue.Version);
        Output.insert(Output.end(), RequestValue.Uuid.begin(), RequestValue.Uuid.end());
        Output.push_back(static_cast<std::uint8_t>(RequestValue.Addons.size()));
        Output.insert(Output.end(), RequestValue.Addons.begin(), RequestValue.Addons.end());
        Output.push_back(static_cast<std::uint8_t>(RequestValue.Cmd));
        if (IsMux)
        {
            return;
        }
        Output.push_back(static_cast<std::uint8_t>((RequestValue.Target.Port >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(RequestValue.Target.Port & 0xFF));
        if (!Detail::EncodeAddressBody(RequestValue.Target, Output))
        {
            Output.clear();
        }
    }

    /**
     * @brief 构造 VLESS 请求头字节
     * @param RequestValue 请求头
     * @return 请求头字节；非法输入返回空缓冲
     */
    [[nodiscard]] inline auto BuildRequest(const RequestHeader &RequestValue)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildRequest(RequestValue, Output);
        return Output;
    }

    /**
     * @brief 解析 VLESS 请求头（增量）
     * @param Data 输入数据
     * @param Output 输出请求头
     * @param Consumed 输出消耗字节数
     * @return 错误码；数据不足时返回 NeedMore
     */
    [[nodiscard]] inline auto ParseRequest(
        std::span<const std::uint8_t> Data,
        RequestHeader &Output,
        std::size_t &Consumed) -> Error
    {
        if (Data.size() < 18)
        {
            return Error::NeedMore;
        }
        Output.Version = Data[0];
        if (Output.Version != ProtocolVersion)
        {
            return Error::BadMagic;
        }
        std::copy_n(Data.begin() + 1, UuidLen, Output.Uuid.begin());
        const auto AddnlLen = Data[17];
        const auto CommandOffset = 18U + static_cast<std::size_t>(AddnlLen);
        if (Data.size() <= CommandOffset)
        {
            return Error::NeedMore;
        }
        Output.Addons.assign(Data.begin() + 18, Data.begin() + 18 + AddnlLen);
        std::size_t Offset = CommandOffset;
        Output.Cmd = static_cast<Command>(Data[Offset++]);
        if (Output.Cmd != Command::Tcp && Output.Cmd != Command::Udp && Output.Cmd != Command::Mux)
        {
            return Error::BadMessage;
        }
        if (Output.Cmd == Command::Mux)
        {
            Output.Target.Type = AddressType::Domain;
            Output.Target.Host = "v1.mux.cool";
            Output.Target.Port = 0;
            Consumed = Offset;
            return Error::None;
        }
        if (Data.size() - Offset < 3U)
        {
            return Error::NeedMore;
        }
        Output.Target.Port = static_cast<std::uint16_t>(Data[Offset]) << 8 | Data[Offset + 1];
        Offset += 2;
        const auto AddressError = Detail::ParseAddressBody(Data, Output.Target, Offset);
        if (AddressError != Error::None)
        {
            return AddressError;
        }
        if (Output.Target.Type == AddressType::Domain && Output.Target.Host.empty())
        {
            return Error::BadMessage;
        }
        Consumed = Offset;
        return Error::None;
    }

    /**
     * @brief 构造响应字节（固定 2 字节）
     * @return [Version 0x00][Addons Length 0x00]
     */
    [[nodiscard]] inline constexpr auto MakeResponse() -> std::array<std::uint8_t, 2>
    {
        return {ProtocolVersion, 0x00};
    }

} // namespace Preview::Vless
