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

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Vless/AddressCodec.hpp>
#include <Prism/Protocols/Vless/Types.hpp>

namespace Prism::Vless
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
    [[nodiscard]] auto BuildRequest(const RequestHeader &RequestValue)
        -> std::vector<std::uint8_t>;

    /**
     * @brief 解析 VLESS 请求头（增量）
     * @param Data 输入数据
     * @param Output 输出请求头
     * @param Consumed 输出消耗字节数
     * @return 错误码；数据不足时返回 NeedMore
     */
    [[nodiscard]] auto ParseRequest(
        std::span<const std::uint8_t> Data,
        RequestHeader &Output,
        std::size_t &Consumed) -> Error;

    /**
     * @brief 构造响应字节（固定 2 字节）
     * @return [Version 0x00][Addons Length 0x00]
     */
    [[nodiscard]] inline constexpr auto MakeResponse() -> std::array<std::uint8_t, 2>
    {
        return {ProtocolVersion, 0x00};
    }

} // namespace Prism::Vless
