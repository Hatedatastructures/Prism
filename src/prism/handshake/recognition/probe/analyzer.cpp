#include <prism/handshake/recognition/probe/analyzer.hpp>

namespace psm::recognition::probe
{

    auto detect(const std::string_view peek_data)
        -> psm::connect::protocol_type
    {
        if (peek_data.empty())
            return psm::connect::protocol_type::unknown;

        // SOCKS5 须校验 NMETHODS（1-16）：SS2022 salt 首字节随机，单查 0x05 会 1/256 误判
        if (peek_data.size() >= 2 && peek_data[0] == 0x05 &&
            peek_data[1] >= 1 && peek_data[1] <= 16)
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
