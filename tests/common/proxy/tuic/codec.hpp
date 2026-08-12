/**
 * @file codec.hpp
 * @brief Tuic 帧编解码（纯函数，零状态 + serializer/parser 类）
 * @details 帧格式（简化对齐 tuic 测试协议）：
 *          Connect：[Ver 1B][Cmd 1B][ATYP 1B][ADDR][PORT 2B BE]
 *          Packet：[Ver 1B][Cmd 1B][AssocID 4B LE][PktID 4B LE][ATYP 1B][ADDR][PORT 2B BE][Payload]
 *          Heartbeat：[Ver 1B][Cmd 1B]
 * @note 提供 serializer/parser 类（Beast 风格）与纯函数。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/proxy/tuic/types.hpp>

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace psmtest::tuic
{

    /// @brief 编码地址（ATYP + ADDR + PORT 2B BE）
    [[nodiscard]] inline auto encode_address(const address &addr)
    -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.push_back(static_cast<std::uint8_t>(addr.type));
        switch (addr.type)
        {
            case address_type::ipv4:
            {
                std::array<std::uint8_t, 4> ip{};
                std::size_t a = 0, p = 0;
                for (const char ch : addr.host)
                {
                    if (ch == '.')
                    {
                        ip[a++] = static_cast<std::uint8_t>(p);
                        p = 0;
                    }
                    else
                    {
                        p = p * 10 + static_cast<std::size_t>(ch - '0');
                    }
                }
                ip[a] = static_cast<std::uint8_t>(p);
                out.insert(out.end(), ip.begin(), ip.end());
                break;
            }
            case address_type::ipv6:
            {
                out.insert(out.end(), addr.host.begin(), addr.host.end());
                break;
            }
            case address_type::domain:
            default:
            {
                out.push_back(static_cast<std::uint8_t>(addr.host.size()));
                out.insert(out.end(), addr.host.begin(), addr.host.end());
                break;
            }
        }
        out.push_back(static_cast<std::uint8_t>((addr.port >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(addr.port & 0xFF));
        return out;
    }

    /// @brief 解析地址（增量）
    /// @param data 输入
    /// @param out 输出地址
    /// @param consumed 输出消耗字节数
    /// @return 错误码
    [[nodiscard]] inline auto parse_address(std::span<const std::uint8_t> data,
                                            address &out, std::size_t &consumed) -> error
    {
        if (data.empty())
            return error::need_more;
        out.type = static_cast<address_type>(data[0]);
        std::size_t off = 1;
        switch (out.type)
        {
            case address_type::ipv4:
            {
                if (data.size() < off + 4 + 2)
                    return error::need_more;
                std::array<char, 16> buf{};
                std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u",
                              data[off], data[off + 1], data[off + 2], data[off + 3]);
                out.host = buf.data();
                off += 4;
                break;
            }
            case address_type::ipv6:
            {
                if (data.size() < off + 16 + 2)
                    return error::need_more;
                out.host.assign(reinterpret_cast<const char *>(data.data() + off), 16);
                off += 16;
                break;
            }
            case address_type::domain:
            default:
            {
                if (off >= data.size())
                    return error::need_more;
                const auto len = data[off++];
                if (data.size() < off + len + 2)
                    return error::need_more;
                out.host.assign(reinterpret_cast<const char *>(data.data() + off), len);
                off += len;
                break;
            }
        }
        out.port = static_cast<std::uint16_t>(data[off]) << 8 | data[off + 1];
        consumed = off + 2;
        return error::none;
    }

    /// @brief 构造消息帧
    /// @param msg 消息
    /// @return wire 字节
    [[nodiscard]] inline auto build(const message &msg)
    -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.push_back(protocol_version);
        out.push_back(msg.cmd);
        if (msg.cmd == cmd_packet)
        {
            out.push_back(static_cast<std::uint8_t>(msg.assoc_id & 0xFF));
            out.push_back(static_cast<std::uint8_t>((msg.assoc_id >> 8) & 0xFF));
            out.push_back(static_cast<std::uint8_t>((msg.assoc_id >> 16) & 0xFF));
            out.push_back(static_cast<std::uint8_t>((msg.assoc_id >> 24) & 0xFF));
            out.push_back(static_cast<std::uint8_t>(msg.pkt_id & 0xFF));
            out.push_back(static_cast<std::uint8_t>((msg.pkt_id >> 8) & 0xFF));
            out.push_back(static_cast<std::uint8_t>((msg.pkt_id >> 16) & 0xFF));
            out.push_back(static_cast<std::uint8_t>((msg.pkt_id >> 24) & 0xFF));
        }
        if (msg.cmd == cmd_connect || msg.cmd == cmd_packet)
        {
            const auto addr = encode_address(msg.dst);
            out.insert(out.end(), addr.begin(), addr.end());
        }
        if (msg.cmd == cmd_packet)
            out.insert(out.end(), msg.payload.begin(), msg.payload.end());
        return out;
    }

    /// @brief 解析消息帧（增量）
    /// @param data 输入
    /// @param out 输出消息
    /// @param consumed 输出消耗字节数
    /// @return 错误码
    [[nodiscard]] inline auto parse(std::span<const std::uint8_t> data, message &out,
                                    std::size_t &consumed) -> error
    {
        if (data.size() < 2)
            return error::need_more;
        if (data[0] != protocol_version)
            return error::bad_magic;
        out.cmd = data[1];
        std::size_t off = 2;
        if (out.cmd == cmd_packet)
        {
            if (data.size() < off + 8)
                return error::need_more;
            out.assoc_id = static_cast<std::uint32_t>(data[off]) |
                           static_cast<std::uint32_t>(data[off + 1]) << 8 |
                           static_cast<std::uint32_t>(data[off + 2]) << 16 |
                           static_cast<std::uint32_t>(data[off + 3]) << 24;
            out.pkt_id = static_cast<std::uint32_t>(data[off + 4]) |
                         static_cast<std::uint32_t>(data[off + 5]) << 8 |
                         static_cast<std::uint32_t>(data[off + 6]) << 16 |
                         static_cast<std::uint32_t>(data[off + 7]) << 24;
            off += 8;
        }
        if (out.cmd == cmd_connect || out.cmd == cmd_packet)
        {
            std::size_t addr_consumed = 0;
            const auto ec = parse_address(data.subspan(off), out.dst, addr_consumed);
            if (ec != error::none)
                return ec;
            off += addr_consumed;
        }
        if (out.cmd == cmd_packet)
            out.payload.assign(reinterpret_cast<const char *>(data.data() + off), data.size() - off);
        consumed = data.size();
        return error::none;
    }

    /// @brief Tuic 帧序列化器（对象 → wire，Beast 风格）
    class serializer
    {
    public:
        /// @brief 重置并绑定消息
        auto reset(const message &msg) -> void
        {
            wire_ = build(msg);
            offset_ = 0;
        }

        /// @brief 增量输出
        auto get(boost::asio::mutable_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto n = std::min(buffer.size(), wire_.size() - offset_);
            std::memcpy(buffer.data(), wire_.data() + offset_, n);
            offset_ += n;
            return n;
        }

        /// 是否已全部输出
        [[nodiscard]] auto is_done() const -> bool
        {
            return offset_ >= wire_.size();
        }

    private:
        std::vector<std::uint8_t> wire_;
        std::size_t offset_{0};
    };

    /// @brief Tuic 帧解析器（wire → 对象，Beast 风格）
    class parser
    {
    public:
        /// @brief 增量喂入
        auto put(boost::asio::const_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto data = std::span<const std::uint8_t>(
                static_cast<const std::uint8_t *>(buffer.data()), buffer.size());
            buf_.insert(buf_.end(), data.begin(), data.end());
            std::size_t consumed = 0;
            const auto err = parse(buf_, msg_, consumed);
            if (err == error::need_more)
            {
                ec = make_error_code(error::need_more);
                return 0;
            }
            if (err != error::none)
            {
                ec = make_error_code(err);
                return 0;
            }
            done_ = true;
            return consumed;
        }

        /// 是否解析完成
        [[nodiscard]] auto is_done() const -> bool
        {
            return done_;
        }

        /// 解析结果
        [[nodiscard]] auto get() const -> const message &
        {
            return msg_;
        }

        /// 重置
        auto reset() -> void
        {
            buf_.clear();
            msg_ = message{};
            done_ = false;
        }

    private:
        std::vector<std::uint8_t> buf_;
        message msg_{};
        bool done_{false};
    };

} // namespace psmtest::tuic
