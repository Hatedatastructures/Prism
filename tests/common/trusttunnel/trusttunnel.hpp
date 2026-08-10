/**
 * @file trusttunnel.hpp
 * @brief TrustTunnel 认证编解码（HTTP/2 CONNECT + Basic Auth）
 * @details 纯逻辑（无锁）：
 *          1. Authorization: Basic base64(user:pass)
 *          2. HTTP/2 CONNECT 请求头（HPACK 字面量编码，兼容 nghttp2）
 *          命名空间 psm_test::trusttunnel，参考 mihomo transport/trusttunnel。
 */

#pragma once

#include <common/common.hpp>

namespace psm_test::trusttunnel
{

    /// RFC 4648 Base64 编码
    [[nodiscard]] inline auto base64_encode(const view data) -> std::string
    {
        static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve((data.size() + 2) / 3 * 4);
        std::size_t i = 0;
        for (; i + 2 < data.size(); i += 3)
        {
            const auto n = static_cast<std::uint32_t>(data[i]) << 16
                | static_cast<std::uint32_t>(data[i + 1]) << 8 | data[i + 2];
            out.push_back(table[(n >> 18) & 0x3F]);
            out.push_back(table[(n >> 12) & 0x3F]);
            out.push_back(table[(n >> 6) & 0x3F]);
            out.push_back(table[n & 0x3F]);
        }
        if (i + 1 == data.size())
        {
            const auto n = static_cast<std::uint32_t>(data[i]) << 16;
            out.push_back(table[(n >> 18) & 0x3F]);
            out.push_back(table[(n >> 12) & 0x3F]);
            out.push_back('=');
            out.push_back('=');
        }
        else if (i + 2 == data.size())
        {
            const auto n = static_cast<std::uint32_t>(data[i]) << 16
                | static_cast<std::uint32_t>(data[i + 1]) << 8;
            out.push_back(table[(n >> 18) & 0x3F]);
            out.push_back(table[(n >> 12) & 0x3F]);
            out.push_back(table[(n >> 6) & 0x3F]);
            out.push_back('=');
        }
        return out;
    }

    /// Basic Auth 头值："Basic " + base64(user:pass)
    [[nodiscard]] inline auto basic_auth(const std::string_view user,
                                         const std::string_view password) -> std::string
    {
        byte_writer w;
        w.write_bytes(user);
        w.write_u8(':');
        w.write_bytes(password);
        return "Basic " + base64_encode(w.data());
    }

    namespace detail
    {

        /// HPACK 字面量字符串（无 huffman）：7 位长度前缀 + 字节
        inline auto write_hpack_string(byte_writer &w, const std::string_view s) -> void
        {
            w.write_u8(static_cast<std::uint8_t>(s.size()));
            w.write_bytes(s);
        }

    } // namespace detail

    /**
     * @brief 构造 HTTP/2 CONNECT 请求头（HPACK 编码，无 huffman）
     * @param host 目标主机
     * @param port 目标端口
     * @param auth Authorization 头值（如 "Basic xxx"）
     * @return HPACK 头块字节（nghttp2 可解码）
     */
    [[nodiscard]] inline auto h2_connect_headers(const std::string_view host,
                                                 const std::uint16_t port,
                                                 const std::string_view auth) -> buffer
    {
        byte_writer w;
        // :method CONNECT（静态表索引 7）
        w.write_u8(0x80 | 7);
        // :scheme https（静态表索引 23）
        w.write_u8(0x80 | 23);
        // :path /（静态表索引 4）
        w.write_u8(0x80 | 4);
        // :authority（字面量名称引用，不索引：0000 前缀 + 静态表索引 1）
        w.write_u8(0x01);
        const std::string authority = std::string(host) + ":" + std::to_string(port);
        detail::write_hpack_string(w, authority);
        // authorization（字面量名称引用，静态表索引 55）
        w.write_u8(0x40 | 55);
        detail::write_hpack_string(w, auth);
        return w.data();
    }

    /// 解析 HTTP/2 响应头（HPACK 解码，提取 :status）
    /// @param block HPACK 头块
    /// @param status 输出状态码（如 200）
    [[nodiscard]] inline auto parse_h2_status(const view block, std::uint16_t &status) -> bool
    {
        byte_reader r(block);
        std::string name, value;
        bool found = false;
        while (!r.empty())
        {
            std::uint8_t b = 0;
            if (!r.read_u8(b))
                return false;
            if ((b & 0x80) != 0)
            {
                // 索引字段（静态表）
                const auto idx = b & 0x7F;
                if (idx == 8) // :status 200
                {
                    status = 200;
                    found = true;
                }
                continue;
            }
            if ((b & 0x40) != 0)
            {
                // 增量索引：字面量，名称引用静态表（4 位索引）
                const auto idx = b & 0x0F;
                if (idx == 1)
                    name = ":authority";
                else if (idx == 55)
                    name = "authorization";
                else if (idx == 8)
                    name = ":status";
                else
                    name.clear();
            }
            else if ((b & 0x20) != 0)
            {
                // 字面量名称（5 位前缀）
                std::uint64_t name_len = b & 0x1F;
                if (name_len == 31)
                {
                    std::uint64_t shift = 0;
                    for (;;)
                    {
                        std::uint8_t nb = 0;
                        if (!r.read_u8(nb))
                            return false;
                        name_len += static_cast<std::uint64_t>(nb & 0x7F) << shift;
                        if ((nb & 0x80) == 0)
                            break;
                        shift += 7;
                    }
                }
                const auto nv = r.read(static_cast<std::size_t>(name_len));
                if (nv.size() != name_len)
                    return false;
                name.assign(reinterpret_cast<const char *>(nv.data()), nv.size());
            }
            else
            {
                // 不索引/永不索引：字面量，名称引用静态表（4 位索引）
                const auto idx = b & 0x0F;
                if (idx == 1)
                    name = ":authority";
                else if (idx == 55)
                    name = "authorization";
                else if (idx == 8)
                    name = ":status";
                else
                    name.clear();
            }
            // 值
            std::uint64_t vlen = 0;
            if (!r.read_hpack_varint(7, vlen))
                return false;
            const auto v = r.read(static_cast<std::size_t>(vlen));
            if (v.size() != vlen)
                return false;
            value.assign(reinterpret_cast<const char *>(v.data()), v.size());
            if (name == ":status")
            {
                status = static_cast<std::uint16_t>(std::atoi(value.c_str()));
                found = true;
            }
        }
        return found;
    }

} // namespace psm_test::trusttunnel
