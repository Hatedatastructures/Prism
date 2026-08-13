/**
 * @file h3_auth.cpp
 * @brief Hysteria2 HTTP/3 认证辅助实现
 */

#include <prism/protocol/hysteria2/h3_auth.hpp>

#include <array>
#include <charconv>
#include <cstring>

namespace psm::protocol::hysteria2::h3
{

    namespace
    {
        /**
         * @brief 查找头字段
         * @param fields 头字段列表
         * @param name 目标字段名
         * @return 匹配的字段值，未找到返回空视图
         */
        [[nodiscard]] auto find_header(const memory::vector<qpack::header_field> &fields,
                                       const std::string_view name) -> std::string_view
        {
            for (const auto &f : fields)
            {
                if (f.name == name)
                {
                    return std::string_view(f.value.data(), f.value.size());
                }
            }
            return {};
        }
    } // namespace

    auto parse_auth_request(const std::span<const std::uint8_t> data, auth_request &out,
                            const memory::resource_pointer mr) -> bool
    {
        auto fields = qpack::decode_header_block(data, mr);

        out.method.assign(find_header(fields, ":method"));
        out.host.assign(find_header(fields, ":authority"));
        out.path.assign(find_header(fields, ":path"));
        out.auth.assign(find_header(fields, "hysteria-auth"));

        const auto rx_str = find_header(fields, "hysteria-cc-rx");
        out.rx = 0;
        if (!rx_str.empty())
        {
            std::from_chars(rx_str.data(), rx_str.data() + rx_str.size(), out.rx);
        }

        // 认证请求必须匹配 POST https://hysteria/auth
        return out.method == "POST" && out.path == "/auth" && !out.auth.empty();
    }

    auto encode_auth_response(const std::uint16_t status, const bool udp_enabled, const std::uint64_t rx,
                              const std::span<std::byte> out) -> std::size_t
    {
        // QPACK 块：前缀 + :status + Hysteria-UDP + Hysteria-CC-RX + Hysteria-Padding
        std::array<std::uint8_t, 512> block{};
        std::size_t offset = qpack::encode_prefix(block);

        // :status 字段（静态表无 233 条目，用字面量）
        char status_buf[4];
        const auto [se, sec] = std::to_chars(status_buf, status_buf + sizeof(status_buf), status);
        const auto status_str = std::string_view(status_buf, static_cast<std::size_t>(se - status_buf));
        offset += qpack::encode_literal(
            ":status", status_str, std::span<std::uint8_t>(block.data() + offset, block.size() - offset));

        // Hysteria-UDP: true
        offset +=
            qpack::encode_literal("hysteria-udp", udp_enabled ? "true" : "false",
                                  std::span<std::uint8_t>(block.data() + offset, block.size() - offset));

        // Hysteria-CC-RX: <rx>
        char rx_buf[24];
        const auto [re, rec] = std::to_chars(rx_buf, rx_buf + sizeof(rx_buf), rx);
        const auto rx_str = std::string_view(rx_buf, static_cast<std::size_t>(re - rx_buf));
        offset += qpack::encode_literal(
            "hysteria-cc-rx", rx_str, std::span<std::uint8_t>(block.data() + offset, block.size() - offset));

        // Hysteria-Padding: 0（客户端解析用，填 0 表示无 padding）
        offset += qpack::encode_literal(
            "hysteria-padding", "0", std::span<std::uint8_t>(block.data() + offset, block.size() - offset));

        // HTTP/3 帧头：type=HEADERS(1) + length
        std::size_t n = 0;
        if (out.size() < 2 + offset)
        {
            return 0;
        }
        out[n++] = static_cast<std::byte>(frame_headers); // varint 1
        // length varint（offset < 128 通常成立；超长用多字节编码）
        auto len_rest = offset;
        if (len_rest < 128)
        {
            out[n++] = static_cast<std::byte>(len_rest);
        }
        else
        {
            // 通用 varint 编码（保留前缀位 0x00）
            out[n++] = static_cast<std::byte>(static_cast<std::uint8_t>(len_rest & 0x7F) | 0x80);
            len_rest >>= 7;
            while (len_rest >= 128)
            {
                if (out.size() <= n)
                {
                    return 0;
                }
                out[n++] = static_cast<std::byte>(static_cast<std::uint8_t>((len_rest & 0x7F) | 0x80));
                len_rest >>= 7;
            }
            if (out.size() <= n)
            {
                return 0;
            }
            out[n++] = static_cast<std::byte>(len_rest);
        }
        if (out.size() < n + offset)
        {
            return 0;
        }
        std::memcpy(out.data() + n, block.data(), offset);
        return n + offset;
    }

} // namespace psm::protocol::hysteria2::h3
