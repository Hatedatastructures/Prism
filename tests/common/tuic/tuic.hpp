/**
 * @file tuic.hpp
 * @brief TUIC v5 协议帧编解码（客户端 + 服务端）
 * @details 纯逻辑（无锁）：
 *          认证 = [VER 0x05][TYPE 0x00][UUID 16B][TOKEN 32B]
 *          Connect = [VER 0x05][TYPE 0x01][ATYP][ADDR][PORT 2B]
 *          Packet = [VER 0x05][TYPE 0x02][ASSOC_ID 2B][PKT_ID 2B][FRAG_TOTAL 1B][FRAG_ID 1B][SIZE 2B][ATYP][ADDR][PORT][DATA]
 *          Heartbeat = [VER 0x05][TYPE 0x04]（datagram）
 *          命名空间 psm_test::tuic，参考 mihomo transport/tuic/v5。
 */

#pragma once

#include <common/common.hpp>
#include <common/socks5/socks5.hpp>

namespace psm_test::tuic
{

    inline constexpr std::uint8_t version = 0x05;
    inline constexpr std::uint8_t cmd_authenticate = 0x00;
    inline constexpr std::uint8_t cmd_connect = 0x01;
    inline constexpr std::uint8_t cmd_packet = 0x02;
    inline constexpr std::uint8_t cmd_dissociate = 0x03;
    inline constexpr std::uint8_t cmd_heartbeat = 0x04;
    inline constexpr std::size_t token_len = 32;

    using address = socks5::address;

    /// 认证帧（uni 流）
    [[nodiscard]] inline auto build_authenticate(const std::span<const std::uint8_t> uuid,
                                                 const std::span<const std::uint8_t> token) -> buffer
    {
        byte_writer w;
        w.write_u8(version);
        w.write_u8(cmd_authenticate);
        w.write_bytes(uuid);
        w.write_bytes(token);
        return w.data();
    }

    /// 认证帧解析结果
    struct authenticate
    {
        std::array<std::uint8_t, 16> uuid{};
        std::array<std::uint8_t, token_len> token{};
        bool valid{false};
    };

    /// 解析认证帧
    [[nodiscard]] inline auto parse_authenticate(const view data) -> authenticate
    {
        authenticate auth;
        if (data.size() != 2 + 16 + token_len)
            return auth;
        byte_reader r(data);
        std::uint8_t ver = 0, type = 0;
        if (!r.read_u8(ver) || ver != version || !r.read_u8(type) || type != cmd_authenticate)
            return auth;
        const auto uuid_v = r.read(16);
        const auto token_v = r.read(token_len);
        std::copy(uuid_v.begin(), uuid_v.end(), auth.uuid.begin());
        std::copy(token_v.begin(), token_v.end(), auth.token.begin());
        auth.valid = true;
        return auth;
    }

    /// Connect 帧（bidi 流）
    [[nodiscard]] inline auto build_connect(const address &dst) -> buffer
    {
        byte_writer w;
        w.write_u8(version);
        w.write_u8(cmd_connect);
        encode_host(w, dst.type, dst.host);
        w.write_u16(dst.port);
        return w.data();
    }

    /// Connect 帧解析结果
    struct connect_request
    {
        address dst;
        bool valid{false};
    };

    /// 解析 Connect 帧
    [[nodiscard]] inline auto parse_connect(const view data) -> connect_request
    {
        connect_request req;
        byte_reader r(data);
        std::uint8_t ver = 0, type = 0;
        if (!r.read_u8(ver) || ver != version || !r.read_u8(type) || type != cmd_connect)
            return req;
        if (!parse_host(r, req.dst.type, req.dst.host))
            return req;
        if (!r.read_u16(req.dst.port))
            return req;
        req.valid = true;
        return req;
    }

    /// Packet 帧（UDP）
    [[nodiscard]] inline auto build_packet(const std::uint16_t assoc_id, const std::uint16_t pkt_id,
                                           const address &dst, const view payload) -> buffer
    {
        byte_writer w;
        w.write_u8(version);
        w.write_u8(cmd_packet);
        w.write_u16(assoc_id);
        w.write_u16(pkt_id);
        w.write_u8(1); // frag total
        w.write_u8(0); // frag id
        w.write_u16(static_cast<std::uint16_t>(payload.size()));
        encode_host(w, dst.type, dst.host);
        w.write_u16(dst.port);
        w.write_bytes(payload);
        return w.data();
    }

    /// Packet 帧解析结果
    struct packet
    {
        std::uint16_t assoc_id{0};
        std::uint16_t pkt_id{0};
        address dst;
        std::size_t payload_offset{0};
        bool valid{false};
    };

    /// 解析 Packet 帧
    [[nodiscard]] inline auto parse_packet(const view data) -> packet
    {
        packet pkt;
        byte_reader r(data);
        std::uint8_t ver = 0, type = 0;
        if (!r.read_u8(ver) || ver != version || !r.read_u8(type) || type != cmd_packet)
            return pkt;
        if (!r.read_u16(pkt.assoc_id) || !r.read_u16(pkt.pkt_id))
            return pkt;
        std::uint8_t frag_total = 0, frag_id = 0;
        std::uint16_t size = 0;
        if (!r.read_u8(frag_total) || !r.read_u8(frag_id) || !r.read_u16(size))
            return pkt;
        if (!parse_host(r, pkt.dst.type, pkt.dst.host))
            return pkt;
        if (!r.read_u16(pkt.dst.port))
            return pkt;
        if (r.remaining() < size)
            return pkt;
        pkt.payload_offset = r.offset();
        pkt.valid = true;
        return pkt;
    }

    /// Heartbeat 帧（datagram）
    [[nodiscard]] inline auto build_heartbeat() -> buffer
    {
        return buffer{version, cmd_heartbeat};
    }

    /// 解析命令头（VER + TYPE），校验版本
    [[nodiscard]] inline auto parse_head(const view data, std::uint8_t &type) -> bool
    {
        if (data.size() < 2)
            return false;
        if (data[0] != version)
            return false;
        type = data[1];
        return true;
    }

} // namespace psm_test::tuic
