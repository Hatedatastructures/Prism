/**
 * @file frame.cpp
 * @brief smux 帧协议实现（兼容 Mihomo/xtaci/smux v1）
 * @details 实现帧的序列化、反序列化和 mux 地址解析。
 * 帧格式为 8 字节定长帧头 + 变长负载，Length 和 StreamID 采用小端字节序。
 */

#include <cstdio>

#include <forward-engine/channel/smux/frame.hpp>
#include <forward-engine/trace.hpp>

constexpr std::string_view frame_tag = "[Smux.Frame]";

namespace ngx::channel::smux
{
    auto serialize(const frame_header &hdr, std::span<const std::byte> payload,
                   const memory::resource_pointer mr)
        -> memory::vector<std::byte>
    {
        memory::vector<std::byte> buffer(mr);
        buffer.reserve(frame_header_size + payload.size());

        // 字节 0: 版本号
        buffer.push_back(static_cast<std::byte>(hdr.version));

        // 字节 1: 命令类型
        buffer.push_back(static_cast<std::byte>(hdr.cmd));

        // 字节 2-3: 负载长度（小端序）
        buffer.push_back(static_cast<std::byte>(hdr.length & 0xFF));
        buffer.push_back(static_cast<std::byte>(hdr.length >> 8 & 0xFF));

        // 字节 4-7: 流 ID（小端序）
        buffer.push_back(static_cast<std::byte>(hdr.stream_id & 0xFF));
        buffer.push_back(static_cast<std::byte>(hdr.stream_id >> 8 & 0xFF));
        buffer.push_back(static_cast<std::byte>(hdr.stream_id >> 16 & 0xFF));
        buffer.push_back(static_cast<std::byte>(hdr.stream_id >> 24 & 0xFF));

        // 添加负载
        buffer.insert(buffer.end(), payload.begin(), payload.end());

        return buffer;
    }

    auto deserialization(std::span<const std::byte> data)
        -> std::optional<frame_header>
    {
        if (data.size() < frame_header_size)
        {
            return std::nullopt;
        }

        frame_header hdr{};

        // 解析版本号
        hdr.version = static_cast<std::uint8_t>(data[0]);
        if (hdr.version != protocol_version)
        {
            return std::nullopt;
        }

        // 解析命令类型
        hdr.cmd = static_cast<command>(data[1]);

        // 验证命令类型有效性
        switch (hdr.cmd)
        {
        case command::syn:
        case command::fin:
        case command::push:
        case command::nop:
            break;
        default:
            return std::nullopt;
        }

        // 解析负载长度（小端序）
        hdr.length = static_cast<std::uint16_t>(data[2]) |
                     static_cast<std::uint16_t>(data[3]) << 8;

        if (hdr.length > max_frame_length)
        {
            return std::nullopt;
        }

        // 解析流 ID（小端序）
        hdr.stream_id = static_cast<std::uint32_t>(data[4]) |
                        static_cast<std::uint32_t>(data[5]) << 8 |
                        static_cast<std::uint32_t>(data[6]) << 16 |
                        static_cast<std::uint32_t>(data[7]) << 24;

        return hdr;
    }

    /**
     * @details 解析 sing-mux StreamRequest 中的目标地址。
     * 格式：[Flags 2B][ATYP 1B][Addr][Port 2B]。
     * Flags bit0=UDP，目前仅支持 TCP（Flags=0）。
     * 支持 IPv4 (ATYP=0x01)、域名 (ATYP=0x03)、IPv6 (ATYP=0x04)。
     * 返回 nullopt 表示数据不足或格式错误。
     */
    auto parse_mux_address(std::span<const std::byte> data, const memory::resource_pointer mr)
        -> std::optional<parsed_address>
    {
        // 最小长度: Flags(2) + ATYP(1) = 3，后续按地址类型检查
        if (data.size() < 3)
        {
            return std::nullopt;
        }

        // 读取 Flags（2 字节，大端序），bit0=UDP
        const auto flags = static_cast<std::uint16_t>(data[0]) << 8 |
                           static_cast<std::uint16_t>(data[1]);
        if (flags & 1)
        {
            trace::warn("{} unsupported mux UDP request, flags: {}", frame_tag, flags);
            return std::nullopt;
        }

        const auto atype = static_cast<std::uint8_t>(data[2]);
        memory::string host(mr);
        std::size_t offset = 3; // 跳过 Flags(2) + ATYP(1)

        switch (atype)
        {
        case 0x01: // IPv4
        {
            if (data.size() < offset + 4 + 2)
            {
                return std::nullopt;
            }
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                          static_cast<unsigned>(data[3]),
                          static_cast<unsigned>(data[4]),
                          static_cast<unsigned>(data[5]),
                          static_cast<unsigned>(data[6]));
            host = buf;
            offset += 4;
            break;
        }
        case 0x03: // 域名
        {
            if (data.size() < offset + 1)
            {
                return std::nullopt;
            }
            const auto domain_len = static_cast<std::uint8_t>(data[3]);
            if (data.size() < 3 + 1 + domain_len + 2)
            {
                return std::nullopt;
            }
            host.assign(reinterpret_cast<const char *>(&data[4]), domain_len);
            offset += 1 + domain_len;
            break;
        }
        case 0x04: // IPv6
        {
            if (data.size() < offset + 16 + 2)
            {
                return std::nullopt;
            }
            char buf[64];
            std::snprintf(buf, sizeof(buf),
                          "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                          "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                          static_cast<unsigned>(data[3]),
                          static_cast<unsigned>(data[4]),
                          static_cast<unsigned>(data[5]),
                          static_cast<unsigned>(data[6]),
                          static_cast<unsigned>(data[7]),
                          static_cast<unsigned>(data[8]),
                          static_cast<unsigned>(data[9]),
                          static_cast<unsigned>(data[10]),
                          static_cast<unsigned>(data[11]),
                          static_cast<unsigned>(data[12]),
                          static_cast<unsigned>(data[13]),
                          static_cast<unsigned>(data[14]),
                          static_cast<unsigned>(data[15]),
                          static_cast<unsigned>(data[16]),
                          static_cast<unsigned>(data[17]),
                          static_cast<unsigned>(data[18]));
            host = buf;
            offset += 16;
            break;
        }
        default:
            trace::warn("{} unknown address type: {}", frame_tag, atype);
            return std::nullopt;
        }

        // 解析端口（大端序）
        if (data.size() < offset + 2)
        {
            return std::nullopt;
        }
        const std::uint16_t port = static_cast<std::uint16_t>(data[offset]) << 8 | static_cast<std::uint16_t>(data[offset + 1]);

        return parsed_address{
            .host = std::move(host),
            .port = port,
            .offset = offset + 2, // 跳过端口
        };
    }

} // namespace ngx::channel::smux
