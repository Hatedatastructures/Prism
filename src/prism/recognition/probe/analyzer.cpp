/**
 * @file analyzer.cpp
 * @brief 外层协议检测实现
 */

#include <prism/recognition/probe/analyzer.hpp>
#include <array>

namespace psm::recognition::probe
{
    namespace
    {
        constexpr std::array<std::string_view, 9> http_methods = {
            "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
            "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "};

        bool is_http_request(const std::string_view data) noexcept
        {
            for (const auto &method : http_methods)
            {
                if (data.size() >= method.size() && data.substr(0, method.size()) == method)
                    return true;
            }
            return false;
        }
    }

    auto detect(const std::string_view peek_data) -> protocol::protocol_type
    {
        if (peek_data.empty())
            return protocol::protocol_type::unknown;

        if (peek_data[0] == 0x05)
            return protocol::protocol_type::socks5;

        // TLS 须检查两字节 0x16 0x03，防止 SS2022 salt 首字节 0x16 误判
        if (peek_data.size() >= 2 && peek_data[0] == 0x16 && peek_data[1] == 0x03)
            return protocol::protocol_type::tls;

        if (is_http_request(peek_data))
            return protocol::protocol_type::http;

        // SS2022 fallback（排除法）
        return protocol::protocol_type::shadowsocks;
    }

} // namespace psm::recognition::probe
