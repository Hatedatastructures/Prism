/**
 * @file frame.cpp
 * @brief smux 帧协议实现（兼容 Mihomo/xtaci/smux v1）
 * @details 实现帧的序列化、反序列化和 mux 地址解析。
 * 帧格式为 8 字节定长帧头 + 变长负载，Length 和 StreamID 采用小端字节序。
 */

#include <forward-engine/multiplex/smux/frame.hpp>
#include <forward-engine/trace.hpp>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

constexpr std::string_view frame_tag = "[Smux.Frame]";

namespace ngx::multiplex::smux
{
    namespace
    {

        // IPv4 地址格式化：直接写入字符串，避免 printf 开销
        void format_ipv4(const std::byte *data, char *buf)
        {
            const auto a = static_cast<uint8_t>(data[0]);
            const auto b = static_cast<uint8_t>(data[1]);
            const auto c = static_cast<uint8_t>(data[2]);
            const auto d = static_cast<uint8_t>(data[3]);

            auto p = buf;
            // 第一段
            if (a >= 100)
                *p++ = '0' + a / 100;
            if (a >= 10)
                *p++ = '0' + (a / 10) % 10;
            *p++ = '0' + a % 10;
            *p++ = '.';
            // 第二段
            if (b >= 100)
                *p++ = '0' + b / 100;
            if (b >= 10)
                *p++ = '0' + (b / 10) % 10;
            *p++ = '0' + b % 10;
            *p++ = '.';
            // 第三段
            if (c >= 100)
                *p++ = '0' + c / 100;
            if (c >= 10)
                *p++ = '0' + (c / 10) % 10;
            *p++ = '0' + c % 10;
            *p++ = '.';
            // 第四段
            if (d >= 100)
                *p++ = '0' + d / 100;
            if (d >= 10)
                *p++ = '0' + (d / 10) % 10;
            *p++ = '0' + d % 10;
            *p = '\0';
        }
    } // namespace

    auto serialize(const frame_header &hdr, std::span<const std::byte> payload,
                   const memory::resource_pointer mr)
        -> memory::vector<std::byte>
    {
        memory::vector<std::byte> buffer(mr);
        buffer.resize(frame_header_size + payload.size());

        auto *p = buffer.data();
        p[0] = static_cast<std::byte>(hdr.version);
        p[1] = static_cast<std::byte>(hdr.cmd);
        p[2] = static_cast<std::byte>(hdr.length & 0xFF);
        p[3] = static_cast<std::byte>(hdr.length >> 8);
        p[4] = static_cast<std::byte>(hdr.stream_id & 0xFF);
        p[5] = static_cast<std::byte>(hdr.stream_id >> 8);
        p[6] = static_cast<std::byte>(hdr.stream_id >> 16);
        p[7] = static_cast<std::byte>(hdr.stream_id >> 24);

        if (!payload.empty())
        {
            std::memcpy(p + frame_header_size, payload.data(), payload.size());
        }

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

        hdr.version = static_cast<std::uint8_t>(data[0]);
        if (hdr.version != protocol_version)
        {
            return std::nullopt;
        }

        hdr.cmd = static_cast<command>(data[1]);

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

        hdr.length = static_cast<std::uint16_t>(data[2]) |
                     static_cast<std::uint16_t>(data[3]) << 8;

        if (hdr.length > max_frame_length)
        {
            return std::nullopt;
        }

        hdr.stream_id = static_cast<std::uint32_t>(data[4]) |
                        static_cast<std::uint32_t>(data[5]) << 8 |
                        static_cast<std::uint32_t>(data[6]) << 16 |
                        static_cast<std::uint32_t>(data[7]) << 24;

        return hdr;
    }

    auto parse_mux_address(std::span<const std::byte> data, const memory::resource_pointer mr)
        -> std::optional<parsed_address>
    {
        if (data.size() < 3)
        {
            return std::nullopt;
        }

        const auto flags = static_cast<std::uint16_t>(data[0]) << 8 | static_cast<std::uint16_t>(data[1]);
        const bool is_udp = (flags & 1) != 0;

        const auto atype = static_cast<std::uint8_t>(data[2]);
        memory::string host(mr);
        std::size_t offset = 3;

        switch (atype)
        {
        case 0x01: // IPv4
        {
            if (data.size() < offset + 4 + 2)
            {
                return std::nullopt;
            }
            char buf[16];
            format_ipv4(&data[3], buf);
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
            char buf[INET6_ADDRSTRLEN];
            if (!inet_ntop(AF_INET6, &data[3], buf, sizeof(buf)))
            {
                return std::nullopt;
            }
            host = buf;
            offset += 16;
            break;
        }
        default:
            trace::warn("{} unknown address type: {}", frame_tag, atype);
            return std::nullopt;
        }

        if (data.size() < offset + 2)
        {
            return std::nullopt;
        }
        const std::uint16_t port = static_cast<std::uint16_t>(data[offset]) << 8 | static_cast<std::uint16_t>(data[offset + 1]);

        return parsed_address{
            .host = std::move(host),
            .port = port,
            .offset = offset + 2,
            .is_udp = is_udp,
        };
    }

    auto parse_udp_datagram(std::span<const std::byte> data, const memory::resource_pointer mr)
        -> std::optional<udp_datagram>
    {
        if (data.size() < 1)
        {
            return std::nullopt;
        }

        const auto atype = static_cast<std::uint8_t>(data[0]);
        memory::string host(mr);
        std::size_t offset = 1;

        switch (atype)
        {
        case 0x01: // IPv4
        {
            if (data.size() < offset + 4 + 2)
            {
                return std::nullopt;
            }
            char buf[16];
            format_ipv4(&data[1], buf);
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
            const auto domain_len = static_cast<std::uint8_t>(data[1]);
            if (data.size() < 1 + 1 + domain_len + 2)
            {
                return std::nullopt;
            }
            host.assign(reinterpret_cast<const char *>(&data[2]), domain_len);
            offset += 1 + domain_len;
            break;
        }
        case 0x04: // IPv6
        {
            if (data.size() < offset + 16 + 2)
            {
                return std::nullopt;
            }
            char buf[INET6_ADDRSTRLEN];
            if (!inet_ntop(AF_INET6, &data[1], buf, sizeof(buf)))
            {
                return std::nullopt;
            }
            host = buf;
            offset += 16;
            break;
        }
        default:
            trace::warn("{} unknown UDP address type: {}", frame_tag, atype);
            return std::nullopt;
        }

        if (data.size() < offset + 2)
        {
            return std::nullopt;
        }
        const std::uint16_t port = static_cast<std::uint16_t>(data[offset]) << 8 |
                                   static_cast<std::uint16_t>(data[offset + 1]);
        offset += 2;

        const auto payload_size = data.size() > offset ? data.size() - offset : 0;
        return udp_datagram{
            .host = std::move(host),
            .port = port,
            .payload = data.subspan(offset, payload_size),
        };
    }

    auto build_udp_datagram(const std::string_view host, const std::uint16_t port, const std::span<const std::byte> payload,
                            const memory::resource_pointer mr)
        -> memory::vector<std::byte>
    {
        memory::vector<std::byte> buffer(mr);

        // IPv4
        std::array<uint8_t, 4> v4buf;
        if (inet_pton(AF_INET, host.data(), v4buf.data()) == 1)
        {
            buffer.resize(1 + 4 + 2 + payload.size());
            auto *p = buffer.data();
            p[0] = std::byte{0x01};
            std::memcpy(p + 1, v4buf.data(), 4);
            p[5] = static_cast<std::byte>(port >> 8);
            p[6] = static_cast<std::byte>(port & 0xFF);
            if (!payload.empty())
            {
                std::memcpy(p + 7, payload.data(), payload.size());
            }
            return buffer;
        }

        // IPv6
        std::array<uint8_t, 16> v6buf;
        if (inet_pton(AF_INET6, host.data(), v6buf.data()) == 1)
        {
            buffer.resize(1 + 16 + 2 + payload.size());
            auto *p = buffer.data();
            p[0] = std::byte{0x04};
            std::memcpy(p + 1, v6buf.data(), 16);
            p[17] = static_cast<std::byte>(port >> 8);
            p[18] = static_cast<std::byte>(port & 0xFF);
            if (!payload.empty())
            {
                std::memcpy(p + 19, payload.data(), payload.size());
            }
            return buffer;
        }

        // 域名
        buffer.resize(1 + 1 + host.size() + 2 + payload.size());
        auto *p = buffer.data();
        p[0] = std::byte{0x03};
        p[1] = static_cast<std::byte>(host.size());
        std::memcpy(p + 2, host.data(), host.size());
        const auto port_offset = 2 + host.size();
        p[port_offset] = static_cast<std::byte>(port >> 8);
        p[port_offset + 1] = static_cast<std::byte>(port & 0xFF);
        if (!payload.empty())
        {
            std::memcpy(p + port_offset + 2, payload.data(), payload.size());
        }

        return buffer;
    }

} // namespace ngx::multiplex::smux