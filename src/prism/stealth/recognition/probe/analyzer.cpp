#include <prism/stealth/recognition/probe/analyzer.hpp>

namespace psm::recognition::probe
{

    auto detect(const std::string_view peek_data)
        -> psm::connect::protocol_type
    {
        if (peek_data.empty())
            return psm::connect::protocol_type::unknown;

        if (peek_data[0] == 0x05)
            return psm::connect::protocol_type::socks5;

        // TLS 须检查两字节 0x16 0x03，防止 SS2022 salt 首字节 0x16 误判
        if (peek_data.size() >= 2 && peek_data[0] == 0x16 && peek_data[1] == 0x03)
            return psm::connect::protocol_type::tls;

        if (is_http_request(peek_data))
            return psm::connect::protocol_type::http;

        // SS2022 fallback（排除法）
        return psm::connect::protocol_type::shadowsocks;
    }

} // namespace psm::recognition::probe
