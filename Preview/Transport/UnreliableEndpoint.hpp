/**
 * @file UnreliableEndpoint.hpp
 * @brief Unreliable UDP 传输的远端地址解析 owner。
 * @details 只负责 host:port 语法、IPv4/IPv6 数值地址和延迟解析域名的值模型；
 *          socket 生命周期与 peer 过滤仍由 Unreliable 持有。
 */

#pragma once

#include <boost/asio/ip/address.hpp>

#include <charconv>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>

namespace Preview::Transport::Detail
{

    namespace Net = boost::asio;

    /**
     * @brief host:port 语法解析的值结果，不拥有任何运行时资源。
     * @details 输入所有权：Host 是从输入 string_view 复制出的独占 std::string，Port 已限定在 1..65535；
     *          Address 有值表示数值 IPv4/IPv6 地址，无值表示仍需在异步操作中解析的域名。ParseRemote
     *          只借用输入视图至返回，返回后与输入无耦合。
     *          输出与错误：解析失败只以 std::nullopt 表达，不区分语法、端口越界与地址非法等类别，
     *          也不产出 Fault::Code；Unreliable::Connect 将无值映射为唯一 ControlResult 的
     *          InvalidArgument，socket 原生失败则由该操作另行保留。
     *          取消、半关闭、最终关闭者与 executor：本类型是同步纯值，不参与 I/O、不拥有描述符、
     *          不绑定执行域，这三类语义不适用；实际的 socket 生命周期、peer 过滤与最终关闭者仍由
     *          Unreliable 持有。
     * @note 未定义：细粒度失败类别（例如语法错误与端口非法的区分）在当前代码中没有可指出的事实，
     *       留待 M13 之后按实际调用者需要决定。
     */
    struct ParsedUnreliableRemote final
    {
        std::string Host;
        unsigned short Port{0};
        std::optional<Net::ip::address> Address;
    };

    [[nodiscard]] inline auto ParsePort(const std::string_view Text)
        -> std::optional<unsigned short>
    {
        if (Text.empty())
        {
            return std::nullopt;
        }
        unsigned long Value = 0;
        const auto Parsed = std::from_chars(Text.data(), Text.data() + Text.size(), Value, 10);
        if (Parsed.ec != std::errc{} || Parsed.ptr != Text.data() + Text.size() ||
            Value > 65535UL)
        {
            return std::nullopt;
        }
        return static_cast<unsigned short>(Value);
    }

    [[nodiscard]] inline auto IsValidDomain(const std::string_view Host) noexcept -> bool
    {
        if (Host.empty() || Host.front() == '.' || Host.front() == '-' ||
            Host.find_first_of("[]:/\\ \t\r\n") != std::string_view::npos)
        {
            return false;
        }
        bool LabelStart = true;
        char Previous = 0;
        for (const auto Character : Host)
        {
            if (Character == '.')
            {
                if (LabelStart || Previous == '-')
                {
                    return false;
                }
                LabelStart = true;
                Previous = Character;
                continue;
            }
            if (Character == '-' && LabelStart)
            {
                return false;
            }
            if (!std::isalnum(static_cast<unsigned char>(Character)) && Character != '-')
            {
                return false;
            }
            LabelStart = false;
            Previous = Character;
        }
        return !LabelStart && Previous != '-';
    }

    [[nodiscard]] inline auto ParseRemote(const std::string_view Remote)
        -> std::optional<ParsedUnreliableRemote>
    {
        if (Remote.empty())
        {
            return std::nullopt;
        }

        std::string_view Host;
        std::string_view PortText;
        std::optional<Net::ip::address> Address;
        if (Remote.front() == '[')
        {
            const auto Close = Remote.find(']');
            if (Close == std::string_view::npos || Close == 1 ||
                Close + 1 >= Remote.size() || Remote[Close + 1] != ':')
            {
                return std::nullopt;
            }
            Host = Remote.substr(1, Close - 1);
            PortText = Remote.substr(Close + 2);
            boost::system::error_code ErrorCode;
            const auto ParsedAddress = Net::ip::make_address_v6(Host, ErrorCode);
            if (ErrorCode)
            {
                return std::nullopt;
            }
            Address = ParsedAddress;
        }
        else
        {
            const auto FirstColon = Remote.find(':');
            const auto LastColon = Remote.rfind(':');
            if (FirstColon == std::string_view::npos || FirstColon != LastColon)
            {
                return std::nullopt;
            }
            Host = Remote.substr(0, FirstColon);
            PortText = Remote.substr(FirstColon + 1);
            if (Host.empty() || Host.find_first_of("[]") != std::string_view::npos)
            {
                return std::nullopt;
            }
            boost::system::error_code ErrorCode;
            const auto ParsedAddress = Net::ip::make_address(Host, ErrorCode);
            if (!ErrorCode)
            {
                Address = ParsedAddress;
            }
            else if (!IsValidDomain(Host))
            {
                return std::nullopt;
            }
        }

        const auto Port = ParsePort(PortText);
        if (!Port)
        {
            return std::nullopt;
        }
        return ParsedUnreliableRemote{std::string(Host), *Port, Address};
    }

} // namespace Preview::Transport::Detail

