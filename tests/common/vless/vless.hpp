/**
 * @file vless.hpp
 * @brief VLESS 协议编解码（客户端 + 服务端）
 * @details 纯逻辑（无锁无 I/O）：
 *          请求头 = [VER 0][UUID 16B][ADDONS_LEN 1B][ADDONS][CMD 1B][PORT 2B][ATYP][ADDR]
 *          响应头 = [VER 0][LEN 0]
 *          命名空间 psm_test::vless，参考 mihomo transport/vless。
 */

#pragma once

#include <common/common.hpp>
#include <common/socks5/socks5.hpp>

namespace psm_test::vless
{

    inline constexpr std::uint8_t version = 0x00;
    inline constexpr std::uint8_t cmd_tcp = 0x01;
    inline constexpr std::uint8_t cmd_udp = 0x02;
    inline constexpr std::uint8_t cmd_mux = 0x03;

    using address = socks5::address;

    /**
     * @class client
     * @brief VLESS 客户端（请求头构造 + 响应解析）
     */
    class client
    {
    public:
        explicit client(const std::span<const std::uint8_t> uuid)
        {
            std::copy(uuid.begin(), uuid.end(), uuid_.begin());
        }

        /// 构造请求头
        [[nodiscard]] auto handshake(const address &dst, const std::uint8_t cmd = cmd_tcp) const
            -> buffer
        {
            byte_writer w;
            w.write_u8(version);
            w.write_bytes(view(uuid_));
            w.write_u8(0); // addons len
            w.write_u8(cmd);
            if (cmd == cmd_mux)
                return w.data();
            w.write_u16(dst.port);
            encode_host(w, dst.type, dst.host);
            return w.data();
        }

        /// 解析响应头（[VER 0][LEN 0]）
        [[nodiscard]] static auto parse_response(const view resp) -> bool
        {
            if (resp.size() < 2)
                return false;
            return resp[0] == version && resp[1] == 0;
        }

    private:
        std::array<std::uint8_t, 16> uuid_{};
    };

    /**
     * @class server
     * @brief VLESS 服务端（请求头解析 + UUID 校验）
     */
    class server
    {
    public:
        explicit server(const std::span<const std::uint8_t> uuid)
        {
            std::copy(uuid.begin(), uuid.end(), uuid_.begin());
        }

        /// 解析结果
        struct request
        {
            std::array<std::uint8_t, 16> uuid{};
            std::uint8_t cmd{cmd_tcp};
            address dst;
            bool valid{false};
        };

        /// 解析请求头（数据需完整：至少 22 字节）
        [[nodiscard]] auto parse(const view data) const -> request
        {
            request req;
            byte_reader r(data);
            std::uint8_t ver = 0, addons_len = 0;
            if (!r.read_u8(ver) || ver != version)
                return req;
            const auto uuid_v = r.read(16);
            if (uuid_v.size() != 16)
                return req;
            std::copy(uuid_v.begin(), uuid_v.end(), req.uuid.begin());
            if (std::memcmp(uuid_v.data(), uuid_.data(), 16) != 0)
                return req;
            if (!r.read_u8(addons_len))
                return req;
            if (!r.skip(addons_len))
                return req;
            if (!r.read_u8(req.cmd))
                return req;
            if (req.cmd == cmd_mux)
            {
                req.valid = true;
                return req;
            }
            if (!r.read_u16(req.dst.port))
                return req;
            if (!parse_host(r, req.dst.type, req.dst.host))
                return req;
            req.valid = true;
            return req;
        }

        /// 响应头（[VER 0][LEN 0]）
        [[nodiscard]] static auto response() -> buffer
        {
            return buffer{version, 0};
        }

    private:
        std::array<std::uint8_t, 16> uuid_{};
    };

} // namespace psm_test::vless
