/**
 * @file handler.cpp
 * @brief 协议处理器工厂实现
 */

#include <prism/proto/protocol/handler.hpp>

#include <prism/proto/protocol/http/handler.hpp>
#include <prism/proto/protocol/socks5/handler.hpp>
#include <prism/proto/protocol/trojan/handler.hpp>
#include <prism/proto/protocol/vless/handler.hpp>
#include <prism/proto/protocol/shadowsocks/handler.hpp>

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
        default:
            return nullptr;
        }
    }

} // namespace psm::protocol
