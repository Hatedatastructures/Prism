/**
 * @file AuthCodec.hpp
 * @brief SOCKS5 RFC 1929 用户名/密码 wire 编解码
 * @details 仅处理认证子协商消息；认证策略和账户生命周期仍由 Conn
 *          与上层认证器拥有。
 */

#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Socks5/Types.hpp>

namespace Preview::Socks5
{

    /**
     * @brief 编码 RFC 1929 用户名/密码请求并追加到复用缓冲
     * @param User 用户名
     * @param Password 密码
     * @param Output 输出缓冲
     * @details 任一字段超过 255 字节时清空输出，不生成截断长度字段。
     */
    template <typename Alloc>
    inline auto BuildUserpass(
        std::string_view User,
        std::string_view Password,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        if (User.size() > 0xFF || Password.size() > 0xFF)
        {
            return;
        }
        Output.reserve(2 + User.size() + 1 + Password.size());
        Output.push_back(0x01);
        Output.push_back(static_cast<std::uint8_t>(User.size()));
        Output.insert(Output.end(), User.begin(), User.end());
        Output.push_back(static_cast<std::uint8_t>(Password.size()));
        Output.insert(Output.end(), Password.begin(), Password.end());
    }

    /**
     * @brief 编码 RFC 1929 用户名/密码请求
     */
    [[nodiscard]] inline auto BuildUserpass(std::string_view User, std::string_view Password)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildUserpass(User, Password, Output);
        return Output;
    }

    /**
     * @brief 解析 RFC 1929 用户名/密码响应
     * @param Data 响应 wire
     * @return 0x00 状态映射为 None，其余状态映射为 BadAuth
     */
    [[nodiscard]] inline auto ParseUserpassReply(std::span<const std::uint8_t> Data) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::NeedMore;
        }
        if (Data[0] != 0x01)
        {
            return Error::BadMagic;
        }
        if (Data[1] == 0x00)
        {
            return Error::None;
        }
        return Error::BadAuth;
    }

} // namespace Preview::Socks5
