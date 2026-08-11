/**
 * @file codec.hpp
 * @brief SOCKS5 消息编解码（纯函数，零状态）
 * @details 实现 greeting / method_reply / request / reply 的编解码，
 *          支持增量解析（need_more）与边界校验。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/socks5/types.hpp>

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <system_error>
#include <vector>

namespace psmtest::socks5
{

    /// @brief 编码 greeting
    [[nodiscard]] inline auto build_greeting(const greeting &g) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(2 + g.methods.size());
        out.push_back(g.ver);
        out.push_back(static_cast<std::uint8_t>(g.methods.size()));
        out.insert(out.end(), g.methods.begin(), g.methods.end());
        return out;
    }

    /// @brief 解析 greeting（增量）
    /// @param data 输入
    /// @param out 输出
    /// @param consumed 输出消耗字节数
    /// @return 错误码
    [[nodiscard]] inline auto parse_greeting(std::span<const std::uint8_t> data,
                                             greeting &out, std::size_t &consumed) -> error
    {
        if (data.size() < 2)
            return error::need_more;
        out.ver = data[0];
        if (out.ver != version)
            return error::version_mismatch;
        const auto nmethods = data[1];
        if (data.size() < 2 + nmethods)
            return error::need_more;
        out.methods.assign(data.begin() + 2, data.begin() + 2 + nmethods);
        consumed = 2 + nmethods;
        return error::none;
    }

    /// @brief 编码方法选择
    [[nodiscard]] inline auto build_method_reply(const method_reply &m) -> std::array<std::uint8_t, 2>
    {
        return {m.ver, static_cast<std::uint8_t>(m.method)};
    }

    /// @brief 解析方法选择
    [[nodiscard]] inline auto parse_method_reply(std::span<const std::uint8_t> data,
                                                 method_reply &out) -> error
    {
        if (data.size() < 2)
            return error::need_more;
        out.ver = data[0];
        if (out.ver != version)
            return error::bad_magic;
        out.method = static_cast<auth_method>(data[1]);
        return error::none;
    }

    /// @brief 编码地址（ATYP + ADDR + PORT 2B BE）
    [[nodiscard]] inline auto encode_address(const address &addr) -> std::vector<std::uint8_t>
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
            default:
                return error::bad_message;
        }
        out.port = static_cast<std::uint16_t>(data[off]) << 8 | data[off + 1];
        consumed = off + 2;
        return error::none;
    }

    /// @brief 编码请求
    [[nodiscard]] inline auto build_request(const request &req) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.push_back(req.ver);
        out.push_back(static_cast<std::uint8_t>(req.cmd));
        out.push_back(req.rsv);
        const auto addr = encode_address(req.target);
        out.insert(out.end(), addr.begin(), addr.end());
        return out;
    }

    /// @brief 解析请求（增量）
    /// @param data 输入
    /// @param out 输出请求
    /// @param consumed 输出消耗字节数
    /// @return 错误码
    [[nodiscard]] inline auto parse_request(std::span<const std::uint8_t> data,
                                            request &out, std::size_t &consumed) -> error
    {
        if (data.size() < 4)
            return error::need_more;
        out.ver = data[0];
        if (out.ver != version)
            return error::bad_magic;
        out.cmd = static_cast<command>(data[1]);
        if (out.cmd != command::connect && out.cmd != command::udp_associate)
            return error::not_supported;
        out.rsv = data[2];
        std::size_t addr_consumed = 0;
        const auto ec = parse_address(data.subspan(3), out.target, addr_consumed);
        if (ec != error::none)
            return ec;
        consumed = 3 + addr_consumed;
        return error::none;
    }

    /// @brief 编码响应
    [[nodiscard]] inline auto build_reply(const reply &rep) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.push_back(rep.ver);
        out.push_back(static_cast<std::uint8_t>(rep.code));
        out.push_back(rep.rsv);
        const auto addr = encode_address(rep.bind);
        out.insert(out.end(), addr.begin(), addr.end());
        return out;
    }

    /// @brief 解析响应（增量）
    /// @param data 输入
    /// @param out 输出响应
    /// @param consumed 输出消耗字节数
    /// @return 错误码
    [[nodiscard]] inline auto parse_reply(std::span<const std::uint8_t> data,
                                          reply &out, std::size_t &consumed) -> error
    {
        if (data.size() < 4)
            return error::need_more;
        out.ver = data[0];
        out.code = static_cast<reply_code>(data[1]);
        out.rsv = data[2];
        std::size_t addr_consumed = 0;
        const auto ec = parse_address(data.subspan(3), out.bind, addr_consumed);
        if (ec != error::none)
            return ec;
        consumed = 3 + addr_consumed;
        return error::none;
    }

    /// @brief 用户名/密码认证请求（RFC 1929）
    [[nodiscard]] inline auto build_userpass(std::string_view user, std::string_view pass)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.push_back(0x01); // 版本
        out.push_back(static_cast<std::uint8_t>(user.size()));
        out.insert(out.end(), user.begin(), user.end());
        out.push_back(static_cast<std::uint8_t>(pass.size()));
        out.insert(out.end(), pass.begin(), pass.end());
        return out;
    }

    /// @brief 解析用户名/密码认证响应（1 字节状态）
    [[nodiscard]] inline auto parse_userpass_reply(std::span<const std::uint8_t> data) -> error
    {
        if (data.size() < 2)
            return error::need_more;
        if (data[0] != 0x01)
            return error::bad_magic;
        return data[1] == 0x00 ? error::none : error::bad_auth;
    }

    /// @brief SOCKS5 消息（Beast 风格，供 serializer/parser 使用）
    struct message
    {
        /// 消息类型
        enum class kind : std::uint8_t
        {
            /// 问候（greeting）
            greeting,
            /// 方法选择
            method_reply,
            /// 请求（CONNECT）
            request,
            /// 响应
            reply,
        };

        /// 消息类型
        kind type{kind::greeting};
        /// 认证方法列表（greeting）
        std::array<std::uint8_t, 16> methods{};
        /// 方法数量（greeting）
        std::uint8_t method_count{0};
        /// 命令（request）
        std::uint8_t cmd{0x01};
        /// 目标地址
        address dst;
    };

    /// @brief SOCKS5 消息序列化器（对象 → wire，Beast 风格）
    class serializer
    {
    public:
        /// @brief 重置并绑定消息
        /// @param msg 消息
        auto reset(const message &msg) -> void
        {
            wire_.clear();
            offset_ = 0;
            if (msg.type == message::kind::greeting)
            {
                greeting g;
                g.ver = version;
                g.methods.assign(msg.methods.begin(), msg.methods.begin() + msg.method_count);
                wire_ = build_greeting(g);
            }
            else if (msg.type == message::kind::request)
            {
                request req;
                req.ver = version;
                req.cmd = static_cast<command>(msg.cmd);
                req.target = msg.dst;
                wire_ = build_request(req);
            }
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

    /// @brief SOCKS5 消息解析器（wire → 对象，Beast 风格）
    class parser
    {
    public:
        /// @brief 设置期望的消息类型
        /// @param kind 消息类型
        auto expect(message::kind kind) -> void
        {
            expect_ = kind;
        }

        /// @brief 增量喂入
        auto put(boost::asio::const_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto data = std::span<const std::uint8_t>(
                static_cast<const std::uint8_t *>(buffer.data()), buffer.size());
            const auto prev_size = buf_.size();
            buf_.insert(buf_.end(), data.begin(), data.end());
            std::size_t consumed = 0;

            if (expect_ == message::kind::greeting)
            {
                greeting g;
                auto err = parse_greeting(buf_, g, consumed);
                if (err == error::need_more)
                {
                    return 0; // 半帧：ec 保持空，等待更多数据
                }
                if (err != error::none)
                {
                    ec = make_error_code(err);
                    return 0;
                }
                msg_.type = message::kind::greeting;
                msg_.method_count = static_cast<std::uint8_t>(g.methods.size());
                for (std::size_t i = 0; i < g.methods.size() && i < msg_.methods.size(); ++i)
                    msg_.methods[i] = g.methods[i];
            }
            else
            {
                request req;
                auto err = parse_request(buf_, req, consumed);
                if (err == error::need_more)
                {
                    return 0; // 半帧：ec 保持空，等待更多数据
                }
                if (err != error::none)
                {
                    ec = make_error_code(err);
                    return 0;
                }
                msg_.type = message::kind::request;
                msg_.cmd = static_cast<std::uint8_t>(req.cmd);
                msg_.dst = req.target;
            }
            done_ = true;
            // 返回本次 put 中构成帧的字节数（跨帧增量语义）
            if (consumed <= prev_size)
                return 0;
            return std::min(consumed, prev_size + data.size()) - prev_size;
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
        message::kind expect_{message::kind::greeting};
        std::vector<std::uint8_t> buf_;
        message msg_{};
        bool done_{false};
    };

} // namespace psmtest::socks5
