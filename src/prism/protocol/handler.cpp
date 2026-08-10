/**
 * @file handler.cpp
 * @brief 协议处理器工厂实现
 */

#include <prism/protocol/handler.hpp>

#include <prism/protocol/http/handler/handler.hpp>
#include <prism/protocol/socks5/handler/handler.hpp>
#include <prism/protocol/trojan/handler/handler.hpp>
#include <prism/protocol/vless/handler/handler.hpp>
#include <prism/protocol/shadowsocks/handler/handler.hpp>
#include <prism/protocol/vmess/handler/handler.hpp>
#include <prism/protocol/hysteria2/handler.hpp>
#include <prism/protocol/tuic/handler.hpp>

#include <utility>

namespace psm::protocol
{

    [[nodiscard]] auto make_protocol_handler(protocol_type type, handler_params params) 
        -> std::unique_ptr<protocol_handler>
    {
        switch (type)
        {
        case protocol_type::http:
            return std::make_unique<http::handler>(std::move(params));
        case protocol_type::socks5:
            return std::make_unique<socks5::handler>(std::move(params));
        case protocol_type::trojan:
            return std::make_unique<trojan::handler>(std::move(params));
        case protocol_type::vless:
            return std::make_unique<vless::handler>(std::move(params));
        case protocol_type::shadowsocks:
            return std::make_unique<shadowsocks::handler>(std::move(params));
        case protocol_type::vmess:
            return std::make_unique<vmess::handler>(std::move(params));
        case protocol_type::hysteria2:
            return std::make_unique<hysteria2::handler>(std::move(params));
        case protocol_type::tuic:
            return std::make_unique<tuic::handler>(std::move(params));
        default:
            return nullptr;
        }
    }

} // namespace psm::protocol
