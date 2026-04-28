/**
 * @file analyzer.cpp
 * @brief 协议分析器实现
 * @details 实现 detect() 和 detect_tls() 函数。
 */

#include <prism/recognition/probe/analyzer.hpp>
#include <array>

namespace psm::recognition::probe
{
    namespace
    {
        /// HTTP 方法列表（最短 4 字节 "GET "）
        constexpr std::array<std::string_view, 9> http_methods = {
            "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
            "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "};

        /**
         * @brief 检查数据是否以已知 HTTP 方法前缀开头
         */
        bool is_http_request(const std::string_view data) noexcept
        {
            for (const auto &method : http_methods)
            {
                if (data.size() >= method.size() && data.substr(0, method.size()) == method)
                {
                    return true;
                }
            }
            return false;
        }
    }

    auto detect(const std::string_view peek_data) -> protocol::protocol_type
    {
        if (peek_data.empty())
            return protocol::protocol_type::unknown;

        // 1. SOCKS5 (0x05)
        if (peek_data[0] == 0x05)
        {
            return protocol::protocol_type::socks5;
        }

        // 2. TLS (0x16 0x03)
        // 必须检查两字节，否则 SS2022 salt 约有 1/256 概率首字节为 0x16
        if (peek_data.size() >= 2 && peek_data[0] == 0x16 && peek_data[1] == 0x03)
        {
            return protocol::protocol_type::tls;
        }

        // 3. HTTP
        if (is_http_request(peek_data))
        {
            return protocol::protocol_type::http;
        }

        // 4. SS2022 fallback（排除法）
        return protocol::protocol_type::shadowsocks;
    }

    auto detect_tls(std::string_view peek_data) -> protocol::protocol_type
    {
        // 阶段 1：HTTP 检测（最少 4 字节）
        if (peek_data.size() >= 4 && is_http_request(peek_data))
        {
            return protocol::protocol_type::http;
        }

        // 阶段 2：VLESS 检测（最少 22 字节）
        // byte[0] = 0x00 (version), byte[17] = 0x00 (no additional info)
        // byte[18] in {0x01, 0x02, 0x7F} (valid command)
        // byte[21] in {0x01, 0x02, 0x03} (valid address type)
        if (peek_data.size() >= 22)
        {
            const auto b0 = static_cast<unsigned char>(peek_data[0]);
            const auto b17 = static_cast<unsigned char>(peek_data[17]);
            const auto b18 = static_cast<unsigned char>(peek_data[18]);
            const auto b21 = static_cast<unsigned char>(peek_data[21]);

            if (b0 == 0x00 && b17 == 0x00 && (b18 == 0x01 || b18 == 0x02 || b18 == 0x7F) &&
                (b21 == 0x01 || b21 == 0x02 || b21 == 0x03))
            {
                return protocol::protocol_type::vless;
            }
        }

        // 阶段 3：Trojan 检测（最少 60 字节）
        constexpr std::size_t trojan_min_length = 60;
        if (peek_data.size() >= trojan_min_length)
        {
            bool is_trojan = true;
            for (std::size_t i = 0; i < 56; ++i)
            {
                const auto c = static_cast<unsigned char>(peek_data[i]);
                const bool is_hex_digit = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                                          (c >= 'A' && c <= 'F');
                if (!is_hex_digit)
                {
                    is_trojan = false;
                    break;
                }
            }

            if (is_trojan && peek_data[56] == '\r' && peek_data[57] == '\n')
            {
                const auto cmd = static_cast<unsigned char>(peek_data[58]);
                if (cmd == 0x01 || cmd == 0x03 || cmd == 0x7F)
                {
                    const auto atyp = static_cast<unsigned char>(peek_data[59]);
                    if (atyp == 0x01 || atyp == 0x03 || atyp == 0x04)
                    {
                        return protocol::protocol_type::trojan;
                    }
                }
            }

            // 60+ 字节仍无法识别，排除法 fallback 到 SS2022
            return protocol::protocol_type::shadowsocks;
        }

        // 数据不足 60 字节且不匹配任何已知协议
        return protocol::protocol_type::unknown;
    }
} // namespace psm::recognition::probe