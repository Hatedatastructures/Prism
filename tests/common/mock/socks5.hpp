/**
 * @file socks5.hpp
 * @brief Socks5 协议编解码（RFC 1928，客户端 + 服务端）
 * @details 纯逻辑（无锁无 I/O）：地址编解码、客户端握手、服务端握手。
 *          命名空间 psm_test::socks5，参考 mihomo transport/socks5。
 */

#pragma once

#include <common/common.hpp>

namespace psm_test::socks5
{

    inline constexpr std::uint8_t version = 0x05;
    inline constexpr std::uint8_t no_auth = 0x00;
    inline constexpr std::uint8_t user_pass = 0x02;
    inline constexpr std::uint8_t no_acceptable = 0xFF;
    inline constexpr std::uint8_t cmd_connect = 0x01;
    inline constexpr std::uint8_t cmd_bind = 0x02;
    inline constexpr std::uint8_t cmd_udp = 0x03;
    inline constexpr std::uint8_t rep_succeeded = 0x00;
    inline constexpr std::uint8_t rep_general_failure = 0x01;

    /// 目标地址
    struct address
    {
        std::uint8_t type{atyp::ipv4};
        std::string host; ///< IPv4/IPv6 字符串或域名
        std::uint16_t port{0};
    };

    /**
     * @brief 编码 SOCKS5 地址（ATYP + ADDR + PORT）
     * @param out 输出写入器
     * @param addr 目标地址（host 需为点分 IPv4 / 冒分 IPv6 / 域名）
     */
    inline auto encode_address(byte_writer &out, const address &addr) -> void
    {
        encode_host(out, addr.type, addr.host);
        out.write_u16(addr.port);
    }

    /**
     * @brief 解析 SOCKS5 地址
     * @param in 输入读取器
     * @param addr 输出地址（host 为字符串形式）
     * @return 是否成功
     */
    inline auto parse_address(byte_reader &in, address &addr) -> bool
    {
        if (!parse_host(in, addr.type, addr.host))
            return false;
        return in.read_u16(addr.port);
    }

    /**
     * @class client
     * @brief SOCKS5 客户端握手（greeting + CONNECT 请求）
     */
    class client
    {
    public:
        /// 构造握手字节流（greeting + connect），一次写入即可
        [[nodiscard]] auto handshake(const address &dst) const -> buffer
        {
            byte_writer w;
            w.write_u8(version);
            w.write_u8(1); // 方法数
            w.write_u8(no_auth);
            w.write_u8(version);
            w.write_u8(cmd_connect);
            w.write_u8(0); // RSV
            encode_address(w, dst);
            return w.data();
        }

        /// 解析服务端响应（[VER][REP]），成功返回 REP==0
        [[nodiscard]] auto parse_response(const view resp) const -> bool
        {
            byte_reader r(resp);
            std::uint8_t ver = 0, rep = 0;
            if (!r.read_u8(ver) || !r.read_u8(rep))
                return false;
            return ver == version && rep == rep_succeeded;
        }
    };

    /**
     * @class server
     * @brief SOCKS5 服务端握手（greeting 响应 + 请求解析）
     */
    class server
    {
    public:
        /// 解析客户端 greeting（[VER][NMETHODS][METHODS]）
        [[nodiscard]] auto parse_greeting(const view data) -> bool
        {
            byte_reader r(data);
            std::uint8_t ver = 0, nmethods = 0;
            if (!r.read_u8(ver) || ver != version || !r.read_u8(nmethods))
                return false;
            return r.remaining() >= nmethods;
        }

        /// greeting 响应（选择 no-auth）
        [[nodiscard]] static auto greeting_response() -> buffer
        {
            return buffer{version, no_auth};
        }

        /// 解析 CONNECT 请求（[VER][CMD][RSV][ATYP][ADDR][PORT]）
        [[nodiscard]] auto parse_request(const view data, address &dst) -> bool
        {
            byte_reader r(data);
            std::uint8_t ver = 0, cmd = 0, rsv = 0;
            if (!r.read_u8(ver) || ver != version || !r.read_u8(cmd) || !r.read_u8(rsv))
                return false;
            command_ = cmd;
            return parse_address(r, dst);
        }

        [[nodiscard]] auto command() const noexcept -> std::uint8_t
        {
            return command_;
        }

        /// 请求响应（REP 0 = 成功，附 BND.ADDR 0.0.0.0:0）
        [[nodiscard]] static auto request_response(const bool ok) -> buffer
        {
            byte_writer w;
            w.write_u8(version);
            w.write_u8(ok ? rep_succeeded : rep_general_failure);
            w.write_u8(0); // RSV
            address bind;
            bind.type = atyp::ipv4;
            bind.host = "0.0.0.0";
            bind.port = 0;
            encode_address(w, bind);
            return w.data();
        }

    private:
        std::uint8_t command_{cmd_connect};
    };

} // namespace psm_test::socks5
