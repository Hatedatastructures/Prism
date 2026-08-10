/**
 * @file hysteria2.hpp
 * @brief Hysteria2 协议帧编解码（客户端 + 服务端）
 * @details 纯逻辑（无锁）：
 *          TCP 帧 = [0x401 varint][地址 varint][载荷]
 *          UDP 帧 = [0x402 varint][sessionID 4B][packetID 2B][fragID 1B][fragCount 1B][地址 varint][载荷]
 *          认证请求 = HTTP/3 HEADERS 帧（QPACK 字面量编码，兼容 quic-go/nghttp3）
 *          命名空间 psm_test::hysteria2，参考 mihomo sing-quic/hysteria2。
 */

#pragma once

#include <common/common.hpp>

#include <common/socks5/socks5.hpp>

namespace psm_test::hysteria2
{

    inline constexpr std::uint64_t frame_tcp = 0x401;
    inline constexpr std::uint64_t frame_udp = 0x402;
    inline constexpr std::string_view auth_path = "/auth";
    inline constexpr std::string_view auth_host = "hysteria";

    using address = socks5::address;

    namespace detail
    {

        /// 读取 QPACK 字面量值（H 位 + 7 位长度）
        inline auto read_qpack_value(byte_reader &q, std::string &value) -> bool
        {
            std::uint64_t vlen = 0;
            if (!q.read_hpack_varint(7, vlen))
                return false;
            const auto v = q.read(static_cast<std::size_t>(vlen));
            if (v.size() != vlen)
                return false;
            value.assign(reinterpret_cast<const char *>(v.data()), v.size());
            return true;
        }

    } // namespace detail

    /**
     * @brief 构造 HTTP/3 HEADERS 帧（QPACK 字面量编码，H=0）
     * @param password 认证密码
     * @return 完整帧字节（[0x01 HEADERS][QUIC varint 长度][QPACK 块]）
     */
    [[nodiscard]] inline auto build_auth_request(const std::string_view password) -> buffer
    {
        byte_writer block;
        block.write_u8(0x00); // QPACK Required Insert Count = 0
        block.write_u8(0x00); // Delta Base = 0
        block.write_u8(0xD4); // 静态表索引 20：:method POST
        block.write_u8(0xD7); // 静态表索引 23：:scheme https
        // :authority（静态表索引 0，S 位=1 → 0x50）
        block.write_u8(0x50);
        block.write_u8(static_cast<std::uint8_t>(auth_host.size()));
        block.write_bytes(auth_host);
        // :path（静态表索引 1 → 0x51）
        block.write_u8(0x51);
        block.write_u8(static_cast<std::uint8_t>(auth_path.size()));
        block.write_bytes(auth_path);
        // hysteria-auth（字面量名称，13 字符）
        block.write_u8(0x27); // 名称长度前缀 7
        block.write_u8(static_cast<std::uint8_t>(13 - 7));
        block.write_bytes("hysteria-auth");
        block.write_u8(static_cast<std::uint8_t>(password.size()));
        block.write_bytes(password);
        // hysteria-cc-rx: 0（字面量名称，14 字符）
        block.write_u8(0x27);
        block.write_u8(static_cast<std::uint8_t>(14 - 7));
        block.write_bytes("hysteria-cc-rx");
        block.write_u8(1);
        block.write_u8('0');
        // hysteria-padding: 0（字面量名称，16 字符）
        block.write_u8(0x27);
        block.write_u8(static_cast<std::uint8_t>(16 - 7));
        block.write_bytes("hysteria-padding");
        block.write_u8(1);
        block.write_u8('0');

        byte_writer frame;
        frame.write_u8(0x01); // HEADERS 帧类型
        frame.write_quic_varint(block.size());
        frame.write_bytes(block.data());
        return frame.data();
    }

    /// 认证请求解析结果
    struct auth_request
    {
        std::string method;
        std::string path;
        std::string auth;
        bool valid{false};
    };

    /**
     * @brief 解析认证请求（HEADERS 帧 + QPACK 字面量/静态表）
     * @param frame 完整帧字节
     * @param out 输出解析结果
     * @return 是否解析成功（method/path/auth 有效）
     */
    [[nodiscard]] inline auto parse_auth_request(const view frame, auth_request &out) -> bool
    {
        auth_request req;
        byte_reader r(frame);
        std::uint8_t type = 0;
        if (!r.read_u8(type) || type != 0x01)
            return false;
        std::uint64_t block_len = 0;
        if (!r.read_quic_varint(block_len))
            return false;
        const auto block = r.read(static_cast<std::size_t>(block_len));
        if (block.size() != block_len)
            return false;

        byte_reader q(block);
        // QPACK 前缀
        std::uint64_t ricnt = 0, dbase = 0;
        if (!q.read_hpack_varint(8, ricnt) || !q.read_hpack_varint(7, dbase))
            return false;
        std::string name, value;
        while (!q.empty())
        {
            std::uint8_t b = 0;
            if (!q.read_u8(b))
                break;
            if ((b & 0xC0) == 0xC0)
            {
                // 静态表索引（1Txxxxxx）
                const auto idx = b & 0x3F;
                if (idx == 20)
                {
                    name = ":method";
                    value = "POST";
                }
                else if (idx == 23)
                {
                    name = ":scheme";
                    value = "https";
                }
                else if (idx == 0)
                {
                    name = ":authority";
                    value = "hysteria";
                }
                else if (idx == 1)
                {
                    name = ":path";
                    value = "/auth";
                }
                else
                {
                    continue;
                }
            }
            else if ((b & 0xE0) == 0x40)
            {
                // 名称引用静态表（01N S Index）
                const auto idx = b & 0x0F;
                if (idx == 0)
                    name = ":authority";
                else if (idx == 1)
                    name = ":path";
                else
                    name.clear();
                if (!detail::read_qpack_value(q, value))
                    return false;
            }
            else if ((b & 0xE0) == 0x20)
            {
                // 字面量名称（001xxxxx，3 位前缀 + 续字节）
                std::uint64_t name_len = b & 0x07;
                if (name_len == 7)
                {
                    std::uint64_t shift = 0;
                    for (;;)
                    {
                        std::uint8_t nb = 0;
                        if (!q.read_u8(nb))
                            return false;
                        name_len += static_cast<std::uint64_t>(nb & 0x7F) << shift;
                        if ((nb & 0x80) == 0)
                            break;
                        shift += 7;
                        if (shift >= 64)
                            return false;
                    }
                }
                if (name_len > 0)
                {
                    const auto nv = q.read(static_cast<std::size_t>(name_len));
                    if (nv.size() != name_len)
                        return false;
                    name.assign(reinterpret_cast<const char *>(nv.data()), nv.size());
                }
                if (!detail::read_qpack_value(q, value))
                    return false;
            }
            else
            {
                return false;
            }
            if (name == ":method")
                req.method = value;
            else if (name == ":path")
                req.path = value;
            else if (name == "hysteria-auth")
                req.auth = value;
        }
        const auto ok = req.method == "POST" && req.path == "/auth" && !req.auth.empty();
        if (ok)
        {
            req.valid = true;
            out = std::move(req);
        }
        return ok;
    }

    /// 构造 TCP 请求帧（0x401）
    [[nodiscard]] inline auto build_tcp_request(const address &dst, const view payload) -> buffer
    {
        byte_writer w;
        w.write_quic_varint(frame_tcp);
        byte_writer addr;
        encode_host(addr, dst.type, dst.host);
        addr.write_u16(dst.port);
        w.write_quic_varint(addr.size());
        w.write_bytes(addr.data());
        w.write_bytes(payload);
        return w.data();
    }

    /// 解析 TCP 请求帧
    [[nodiscard]] inline auto parse_tcp_request(const view data, address &dst,
                                                std::size_t &payload_offset) -> bool
    {
        byte_reader r(data);
        std::uint64_t type = 0;
        if (!r.read_quic_varint(type) || type != frame_tcp)
            return false;
        std::uint64_t addr_len = 0;
        if (!r.read_quic_varint(addr_len))
            return false;
        if (r.remaining() < addr_len + 2)
            return false;
        byte_reader ar(data.subspan(r.offset(), static_cast<std::size_t>(addr_len)));
        if (!parse_host(ar, dst.type, dst.host))
            return false;
        if (!ar.read_u16(dst.port))
            return false;
        payload_offset = r.offset() + static_cast<std::size_t>(addr_len);
        return true;
    }

    /// 构造 UDP 消息帧（0x402）
    [[nodiscard]] inline auto build_udp_message(const std::uint32_t session_id,
                                                const std::uint16_t packet_id,
                                                const address &dst, const view payload) -> buffer
    {
        byte_writer w;
        w.write_quic_varint(frame_udp);
        w.write_u32(session_id);
        w.write_u16(packet_id);
        w.write_u8(0); // frag id
        w.write_u8(1); // frag count
        byte_writer addr;
        encode_host(addr, dst.type, dst.host);
        addr.write_u16(dst.port);
        w.write_quic_varint(addr.size());
        w.write_bytes(addr.data());
        w.write_bytes(payload);
        return w.data();
    }

    /// 解析 UDP 消息帧
    [[nodiscard]] inline auto parse_udp_message(const view data, std::uint32_t &session_id,
                                                address &dst, std::size_t &payload_offset) -> bool
    {
        byte_reader r(data);
        std::uint64_t type = 0;
        if (!r.read_quic_varint(type) || type != frame_udp)
            return false;
        if (!r.read_u32(session_id))
            return false;
        std::uint16_t packet_id = 0;
        std::uint8_t frag_id = 0, frag_count = 0;
        if (!r.read_u16(packet_id) || !r.read_u8(frag_id) || !r.read_u8(frag_count))
            return false;
        std::uint64_t addr_len = 0;
        if (!r.read_quic_varint(addr_len))
            return false;
        if (r.remaining() < addr_len + 2)
            return false;
        byte_reader ar(data.subspan(r.offset(), static_cast<std::size_t>(addr_len)));
        if (!parse_host(ar, dst.type, dst.host))
            return false;
        if (!ar.read_u16(dst.port))
            return false;
        payload_offset = r.offset() + static_cast<std::size_t>(addr_len);
        return true;
    }

    /// 构造 TCP 响应帧（status + message + padding）
    [[nodiscard]] inline auto build_tcp_response(const bool ok, const std::string_view message) -> buffer
    {
        byte_writer w;
        w.write_u8(ok ? 0 : 1);
        w.write_quic_varint(message.size());
        w.write_bytes(message);
        w.write_quic_varint(0); // padding len
        return w.data();
    }

} // namespace psm_test::hysteria2
