/**
 * @file common.hpp
 * @brief 协议测试公共基础设施
 * @details 纯逻辑基础工具（无锁、无 I/O）：
 *          1. byte_reader / byte_writer —— 字节流编解码
 *          2. varint（QUIC 变长整数 + HPACK 变长整数）
 *          3. 缓冲区与视图
 *          所有协议模块（tests/common/<proto>/）基于此构建。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace psm_test
{

    /// 动态字节缓冲（简单 vector 封装）
    using buffer = std::vector<std::uint8_t>;

    /// 只读字节视图
    using view = std::span<const std::uint8_t>;

    /**
     * @class byte_reader
     * @brief 只读字节流解析器（不修改底层数据）
     */
    class byte_reader
    {
    public:
        explicit byte_reader(const view data) noexcept
            : data_(data)
        {
        }

        [[nodiscard]] auto remaining() const noexcept -> std::size_t
        {
            return data_.size() - off_;
        }

        [[nodiscard]] auto empty() const noexcept -> bool
        {
            return off_ >= data_.size();
        }

        [[nodiscard]] auto offset() const noexcept -> std::size_t
        {
            return off_;
        }

        [[nodiscard]] auto peek(const std::size_t n) const noexcept -> view
        {
            if (off_ + n > data_.size())
                return {};
            return data_.subspan(off_, n);
        }

        /// 读取 n 字节（不足返回空）
        [[nodiscard]] auto read(const std::size_t n) -> view
        {
            const auto v = peek(n);
            if (!v.empty())
                off_ += n;
            return v;
        }

        /// 读取 1 字节（失败返回 false）
        auto read_u8(std::uint8_t &out) -> bool
        {
            const auto v = read(1);
            if (v.empty())
                return false;
            out = v[0];
            return true;
        }

        /// 读取大端序 16 位
        auto read_u16(std::uint16_t &out) -> bool
        {
            const auto v = read(2);
            if (v.empty())
                return false;
            out = static_cast<std::uint16_t>((v[0] << 8) | v[1]);
            return true;
        }

        /// 读取大端序 32 位
        auto read_u32(std::uint32_t &out) -> bool
        {
            const auto v = read(4);
            if (v.empty())
                return false;
            out = static_cast<std::uint32_t>(v[0]) << 24
                | static_cast<std::uint32_t>(v[1]) << 16
                | static_cast<std::uint32_t>(v[2]) << 8
                | static_cast<std::uint32_t>(v[3]);
            return true;
        }

        /// 读取大端序 64 位
        auto read_u64(std::uint64_t &out) -> bool
        {
            std::uint32_t hi = 0, lo = 0;
            if (!read_u32(hi) || !read_u32(lo))
                return false;
            out = (static_cast<std::uint64_t>(hi) << 32) | lo;
            return true;
        }

        /// 读取 QUIC varint（RFC 9000，首字节高 2 位定长）
        auto read_quic_varint(std::uint64_t &out) -> bool
        {
            std::uint8_t b = 0;
            if (!read_u8(b))
                return false;
            const auto len = std::size_t{1} << (b >> 6);
            std::uint64_t v = b & 0x3F;
            const auto rest = read(len - 1);
            if (rest.size() != len - 1)
                return false;
            for (const auto c : rest)
                v = (v << 8) | c;
            out = v;
            return true;
        }

        /// 读取 HPACK 风格 varint（prefix 位前缀 + 7 位续字节）
        auto read_hpack_varint(const std::uint8_t prefix, std::uint64_t &out) -> bool
        {
            std::uint8_t b = 0;
            if (!read_u8(b))
                return false;
            const std::uint64_t mask = (1ULL << prefix) - 1;
            std::uint64_t v = b & mask;
            if (v < mask)
            {
                out = v;
                return true;
            }
            std::uint64_t shift = 0;
            for (;;)
            {
                if (!read_u8(b))
                    return false;
                v += static_cast<std::uint64_t>(b & 0x7F) << shift;
                if ((b & 0x80) == 0)
                    break;
                shift += 7;
                if (shift >= 64)
                    return false;
            }
            out = v;
            return true;
        }

        /// 跳过 n 字节（不足返回 false）
        auto skip(const std::size_t n) -> bool
        {
            if (off_ + n > data_.size())
                return false;
            off_ += n;
            return true;
        }

    private:
        view data_;
        std::size_t off_{0};
    };

    /**
     * @class byte_writer
     * @brief 追加式字节流编码器
     */
    class byte_writer
    {
    public:
        void write_u8(const std::uint8_t v)
        {
            data_.push_back(v);
        }

        void write_u16(const std::uint16_t v)
        {
            data_.push_back(static_cast<std::uint8_t>(v >> 8));
            data_.push_back(static_cast<std::uint8_t>(v & 0xFF));
        }

        void write_u32(const std::uint32_t v)
        {
            data_.push_back(static_cast<std::uint8_t>(v >> 24));
            data_.push_back(static_cast<std::uint8_t>(v >> 16));
            data_.push_back(static_cast<std::uint8_t>(v >> 8));
            data_.push_back(static_cast<std::uint8_t>(v));
        }

        void write_bytes(const view v)
        {
            data_.insert(data_.end(), v.begin(), v.end());
        }

        void write_bytes(const std::string_view v)
        {
            data_.insert(data_.end(), v.begin(), v.end());
        }

        /// 写入 QUIC varint
        void write_quic_varint(const std::uint64_t v)
        {
            if (v < (1ULL << 6))
            {
                write_u8(static_cast<std::uint8_t>(v));
            }
            else if (v < (1ULL << 14))
            {
                write_u8(static_cast<std::uint8_t>(0x40 | (v >> 8)));
                write_u8(static_cast<std::uint8_t>(v & 0xFF));
            }
            else if (v < (1ULL << 30))
            {
                write_u8(static_cast<std::uint8_t>(0x80 | (v >> 24)));
                write_u32(static_cast<std::uint32_t>(v & 0xFFFFFF));
            }
            else
            {
                write_u8(static_cast<std::uint8_t>(0xC0 | (v >> 56)));
                write_u64(v & 0xFFFFFFFFFFFFFFULL);
            }
        }

        /// 写入 HPACK 风格 varint（prefix 位前缀）
        void write_hpack_varint(const std::uint8_t prefix, const std::uint8_t pattern,
                                const std::uint64_t v)
        {
            const std::uint64_t mask = (1ULL << prefix) - 1;
            if (v < mask)
            {
                write_u8(static_cast<std::uint8_t>(pattern | v));
                return;
            }
            write_u8(static_cast<std::uint8_t>(pattern | mask));
            auto rest = v - mask;
            while (rest >= 128)
            {
                write_u8(static_cast<std::uint8_t>((rest & 0x7F) | 0x80));
                rest >>= 7;
            }
            write_u8(static_cast<std::uint8_t>(rest));
        }

        /// 写入长度前缀字符串（16 位大端长度）
        void write_len16_string(const std::string_view s)
        {
            write_u16(static_cast<std::uint16_t>(s.size()));
            write_bytes(s);
        }

        /// 写入 QUIC varint 长度前缀字符串
        void write_varint_string(const std::string_view s)
        {
            write_quic_varint(s.size());
            write_bytes(s);
        }

        [[nodiscard]] auto data() const noexcept -> const buffer &
        {
            return data_;
        }

        [[nodiscard]] auto size() const noexcept -> std::size_t
        {
            return data_.size();
        }

    private:
        void write_u64(const std::uint64_t v)
        {
            for (int i = 7; i >= 0; --i)
                write_u8(static_cast<std::uint8_t>(v >> (i * 8)));
        }

        buffer data_;
    };

    /// 解析 host:port 字符串（最后冒号分隔）
    [[nodiscard]] inline auto split_host_port(const std::string_view s, std::string &host,
                                              std::uint16_t &port) -> bool
    {
        const auto colon = s.find_last_of(':');
        if (colon == std::string_view::npos || colon + 1 >= s.size())
            return false;
        host.assign(s.data(), colon);
        std::uint32_t p = 0;
        for (std::size_t i = colon + 1; i < s.size(); ++i)
        {
            if (s[i] < '0' || s[i] > '9')
                return false;
            p = p * 10 + static_cast<std::uint32_t>(s[i] - '0');
            if (p > 65535)
                return false;
        }
        port = static_cast<std::uint16_t>(p);
        return true;
    }

    /// 地址类型常量（Socks5/VMess/VLESS 通用）
    namespace atyp
    {
        inline constexpr std::uint8_t ipv4 = 0x01;
        inline constexpr std::uint8_t domain = 0x03;
        inline constexpr std::uint8_t ipv6 = 0x04;
    } // namespace atyp

    namespace detail
    {

        /// 点分 IPv4 字符串 → 4 字节
        inline auto ipv4_bytes(const std::string_view host) -> std::array<std::uint8_t, 4>
        {
            std::array<std::uint8_t, 4> out{};
            std::size_t n = 0, start = 0;
            for (std::size_t i = 0; i <= host.size() && n < 4; ++i)
            {
                if (i == host.size() || host[i] == '.')
                {
                    std::uint32_t v = 0;
                    for (std::size_t j = start; j < i; ++j)
                        v = v * 10 + static_cast<std::uint32_t>(host[j] - '0');
                    out[n++] = static_cast<std::uint8_t>(v);
                    start = i + 1;
                }
            }
            return out;
        }

        /// 冒分 IPv6 字符串 → 16 字节（不支持 :: 压缩）
        inline auto ipv6_bytes(const std::string_view host) -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 16> out{};
            std::size_t n = 0, start = 0;
            for (std::size_t i = 0; i <= host.size() && n < 16; ++i)
            {
                if (i == host.size() || host[i] == ':')
                {
                    std::uint16_t v = 0;
                    for (std::size_t j = start; j < i; ++j)
                    {
                        const char c = host[j];
                        v = static_cast<std::uint16_t>(
                            v * 16 + (c >= 'a' ? c - 'a' + 10 : c - '0'));
                    }
                    out[n++] = static_cast<std::uint8_t>(v >> 8);
                    out[n++] = static_cast<std::uint8_t>(v & 0xFF);
                    start = i + 1;
                }
            }
            return out;
        }

        /// IPv6 字节 → 冒分字符串
        inline auto join_ipv6(const view v) -> std::string
        {
            std::string s;
            for (std::size_t i = 0; i < v.size(); i += 2)
            {
                if (i > 0)
                    s.push_back(':');
                char buf[5];
                std::snprintf(buf, sizeof(buf), "%x", (v[i] << 8) | v[i + 1]);
                s += buf;
            }
            return s;
        }

        inline auto hex_val(const char c) -> std::uint8_t
        {
            if (c >= '0' && c <= '9')
                return static_cast<std::uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f')
                return static_cast<std::uint8_t>(c - 'a' + 10);
            return static_cast<std::uint8_t>(c - 'A' + 10);
        }

    } // namespace detail

    /// 编码主机（ATYP + ADDR，不含 PORT）
    inline auto encode_host(byte_writer &out, const std::uint8_t type, const std::string_view host)
        -> void
    {
        out.write_u8(type);
        if (type == atyp::ipv4)
        {
            out.write_bytes(detail::ipv4_bytes(host));
        }
        else if (type == atyp::ipv6)
        {
            out.write_bytes(detail::ipv6_bytes(host));
        }
        else
        {
            out.write_u8(static_cast<std::uint8_t>(host.size()));
            out.write_bytes(host);
        }
    }

    /// 解析主机（ATYP + ADDR，不含 PORT）
    inline auto parse_host(byte_reader &in, std::uint8_t &type, std::string &host) -> bool
    {
        if (!in.read_u8(type))
            return false;
        switch (type)
        {
        case atyp::ipv4:
        {
            const auto v = in.read(4);
            if (v.size() != 4)
                return false;
            host = std::to_string(v[0]) + "." + std::to_string(v[1]) + "."
                + std::to_string(v[2]) + "." + std::to_string(v[3]);
            break;
        }
        case atyp::ipv6:
        {
            const auto v = in.read(16);
            if (v.size() != 16)
                return false;
            host = detail::join_ipv6(v);
            break;
        }
        case atyp::domain:
        {
            std::uint8_t len = 0;
            if (!in.read_u8(len))
                return false;
            const auto v = in.read(len);
            if (v.size() != len)
                return false;
            host.assign(reinterpret_cast<const char *>(v.data()), v.size());
            break;
        }
        default:
            return false;
        }
        return true;
    }

    /// 解析 36 字符 UUID（含连字符）为 16 字节
    [[nodiscard]] inline auto parse_uuid(const std::string_view hex) -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> out{};
        std::size_t idx = 0;
        bool hi = true;
        std::uint8_t nibble = 0;
        for (const char c : hex)
        {
            if (c == '-')
                continue;
            std::uint8_t d = 0;
            if (c >= '0' && c <= '9')
                d = static_cast<std::uint8_t>(c - '0');
            else if (c >= 'a' && c <= 'f')
                d = static_cast<std::uint8_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                d = static_cast<std::uint8_t>(c - 'A' + 10);
            else
                continue;
            if (hi)
            {
                nibble = static_cast<std::uint8_t>(d << 4);
                hi = false;
            }
            else
            {
                out[idx++] = static_cast<std::uint8_t>(nibble | d);
                hi = true;
            }
        }
        return out;
    }

    /// UUID 格式化为字符串（测试/日志用）
    [[nodiscard]] inline auto uuid_string(const std::span<const std::uint8_t> uuid) -> std::string
    {
        std::string s;
        for (std::size_t i = 0; i < uuid.size(); ++i)
        {
            if (i == 4 || i == 6 || i == 8 || i == 10)
                s.push_back('-');
            const auto b = uuid[i];
            s.push_back("0123456789abcdef"[b >> 4]);
            s.push_back("0123456789abcdef"[b & 0x0F]);
        }
        return s;
    }

} // namespace psm_test
