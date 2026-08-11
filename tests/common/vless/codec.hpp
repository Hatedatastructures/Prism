/**
 * @file codec.hpp
 * @brief VLESS 请求头编解码（纯函数 + serializer/parser 类，零状态）
 * @details 请求头格式：
 *          [Version 1B][UUID 16B][AddnlLen 1B][Addnl var][Cmd 1B]
 *          [Port 2B BE][Atyp 1B][Addr var]
 *          响应固定 2 字节：[Version 0x00][Addons Length 0x00]
 *          serializer/parser 类（Beast 风格）：对象 ↔ wire 字节。
 * @note 客户端必须发送 2 字节响应（1 字节会导致 mux 解析错位）。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/vless/types.hpp>

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace psmtest::vless
{

    /// @brief 构造 VLESS 请求头字节
    /// @param hdr 请求头
    /// @return 字节序列
    [[nodiscard]] inline auto build_request(const request_header &hdr) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(22 + hdr.addons.size() + hdr.target.host.size());
        out.push_back(hdr.version);
        out.insert(out.end(), hdr.uuid.begin(), hdr.uuid.end());
        out.push_back(static_cast<std::uint8_t>(hdr.addons.size()));
        out.insert(out.end(), hdr.addons.begin(), hdr.addons.end());
        out.push_back(static_cast<std::uint8_t>(hdr.cmd));
        out.push_back(static_cast<std::uint8_t>((hdr.target.port >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.target.port & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.target.type));
        switch (hdr.target.type)
        {
            case address_type::ipv4:
            {
                std::array<std::uint8_t, 4> ip{};
                std::size_t a = 0, p = 0;
                for (const char ch : hdr.target.host)
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
                out.insert(out.end(), hdr.target.host.begin(), hdr.target.host.end());
                break;
            }
            case address_type::domain:
            default:
            {
                out.push_back(static_cast<std::uint8_t>(hdr.target.host.size()));
                out.insert(out.end(), hdr.target.host.begin(), hdr.target.host.end());
                break;
            }
        }
        return out;
    }

    /// @brief 解析 VLESS 请求头
    /// @param data 输入数据
    /// @param out 输出请求头
    /// @param consumed 输出消耗字节数
    /// @return 错误码；need_more = 数据不足
    [[nodiscard]] inline auto parse_request(std::span<const std::uint8_t> data,
                                            request_header &out, std::size_t &consumed) -> error
    {
        if (data.size() < 22) // 1 + 16 + 1 + 1 + 2 + 1
            return error::need_more;
        out.version = data[0];
        if (out.version != protocol_version)
            return error::bad_magic;
        std::memcpy(out.uuid.data(), data.data() + 1, uuid_len);
        const auto addnl_len = data[17];
        if (data.size() < 18 + addnl_len + 1 + 2 + 1)
            return error::need_more;
        out.addons.assign(data.begin() + 18, data.begin() + 18 + addnl_len);
        std::size_t off = 18 + addnl_len;
        out.cmd = static_cast<command>(data[off++]);
        out.target.port = static_cast<std::uint16_t>(data[off]) << 8 | data[off + 1];
        off += 2;
        out.target.type = static_cast<address_type>(data[off++]);
        switch (out.target.type)
        {
            case address_type::ipv4:
            {
                if (data.size() < off + 4)
                    return error::need_more;
                std::array<char, 16> buf{};
                std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u",
                              data[off], data[off + 1], data[off + 2], data[off + 3]);
                out.target.host = buf.data();
                off += 4;
                break;
            }
            case address_type::ipv6:
            {
                if (data.size() < off + 16)
                    return error::need_more;
                out.target.host.assign(reinterpret_cast<const char *>(data.data() + off), 16);
                off += 16;
                break;
            }
            case address_type::domain:
            default:
            {
                if (off >= data.size())
                    return error::need_more;
                const auto len = data[off++];
                if (data.size() < off + len)
                    return error::need_more;
                out.target.host.assign(reinterpret_cast<const char *>(data.data() + off), len);
                off += len;
                break;
            }
        }
        consumed = off;
        return error::none;
    }

    /// @brief 构造响应字节（固定 2 字节）
    /// @return [Version 0x00][Addons Length 0x00]
    [[nodiscard]] inline constexpr auto make_response() -> std::array<std::uint8_t, 2>
    {
        return {protocol_version, 0x00};
    }

    /// @brief VLESS 帧消息（Beast 风格，供 serializer/parser 使用）
    struct message
    {
        /// 用户 UUID（16 字节）
        std::array<std::uint8_t, uuid_len> uuid{};
        /// 命令（cmd_tcp / cmd_udp / cmd_mux）
        std::uint8_t cmd{cmd_tcp};
        /// 目标地址
        address dst;
        /// 解析有效
        bool valid{false};
    };

    /// @brief VLESS 帧序列化器（对象 → wire，Beast 风格）
    class serializer
    {
    public:
        /// @brief 构造
        /// @param uuid 用户 UUID
        explicit serializer(const std::array<std::uint8_t, uuid_len> &uuid)
            : uuid_(uuid)
        {
        }

        /// @brief 重置并绑定消息
        /// @param msg 消息
        auto reset(const message &msg) -> void
        {
            request_header hdr;
            hdr.version = protocol_version;
            hdr.uuid = uuid_;
            hdr.cmd = static_cast<command>(msg.cmd);
            hdr.target = msg.dst;
            wire_ = build_request(hdr);
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
        std::array<std::uint8_t, uuid_len> uuid_;
        std::vector<std::uint8_t> wire_;
        std::size_t offset_{0};
    };

    /// @brief VLESS 帧解析器（wire → 对象，Beast 风格）
    class parser
    {
    public:
        /// @brief 构造
        /// @param uuid 期望的用户 UUID（校验用）
        explicit parser(const std::array<std::uint8_t, uuid_len> &uuid)
            : uuid_(uuid)
        {
        }

        /// @brief 增量喂入
        auto put(boost::asio::const_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto data = std::span<const std::uint8_t>(
                static_cast<const std::uint8_t *>(buffer.data()), buffer.size());
            buf_.insert(buf_.end(), data.begin(), data.end());
            std::size_t consumed = 0;
            request_header req;
            const auto err = parse_request(buf_, req, consumed);
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
            // UUID 校验
            if (req.uuid != uuid_)
            {
                ec = make_error_code(error::auth_failed);
                return 0;
            }
            msg_.uuid = req.uuid;
            msg_.cmd = static_cast<std::uint8_t>(req.cmd);
            msg_.dst = req.target;
            msg_.valid = true;
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
        std::array<std::uint8_t, uuid_len> uuid_;
        std::vector<std::uint8_t> buf_;
        message msg_{};
        bool done_{false};
    };

} // namespace psmtest::vless
