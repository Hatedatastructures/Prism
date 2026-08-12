/**
 * @file codec.hpp
 * @brief SOCKS5 消息编解码（纯函数，零状态）
 * @details 实现 greeting / method_reply / request / reply 的编解码，
 *          支持增量解析（need_more）与边界校验。
 */

#pragma once

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/proxy/socks5/types.hpp>

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace psmtest::socks5
{

    /**
     * @brief 编码 greeting
     * @param g 问候（版本 + 方法列表）
     * @return greeting 字节：[ver 1B][nmethods 1B][methods var]
     */
    [[nodiscard]] inline auto build_greeting(const greeting &g) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(2 + g.methods.size());
        out.push_back(g.ver);
        out.push_back(static_cast<std::uint8_t>(g.methods.size()));
        out.insert(out.end(), g.methods.begin(), g.methods.end());
        return out;
    }

    /**
     * @brief 解析 greeting（增量）
     * @param data 输入
     * @param out 输出
     * @param consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
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

    /**
     * @brief 编码方法选择
     * @param m 方法选择（版本 + 方法）
     * @return 2 字节回复
     */
    [[nodiscard]] inline auto build_method_reply(const method_reply &m) -> std::array<std::uint8_t, 2>
    {
        return {m.ver, static_cast<std::uint8_t>(m.method)};
    }

    /**
     * @brief 解析方法选择
     * @param data 输入
     * @param out 输出方法选择
     * @return 错误码；need_more = 数据不足
     */
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

    /**
     * @brief 编码地址（ATYP + ADDR + PORT 2B BE）
     * @param addr 目标地址
     * @return 地址字节
     */
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

    /**
     * @brief 解析地址（增量）
     * @param data 输入
     * @param out 输出地址
     * @param consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
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

    /**
     * @brief 编码请求
     * @param req 请求（命令 + 目标地址）
     * @return 请求字节：[ver][cmd][rsv][ATYP][ADDR][PORT]
     */
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

    /**
     * @brief 解析请求（增量）
     * @param data 输入
     * @param out 输出请求
     * @param consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
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

    /**
     * @brief 编码响应
     * @param rep 响应（状态码 + 绑定地址）
     * @return 响应字节：[ver][code][rsv][ATYP][ADDR][PORT]
     */
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

    /**
     * @brief 解析响应（增量）
     * @param data 输入
     * @param out 输出响应
     * @param consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
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

    /**
     * @brief 构造 SOCKS5 UDP 数据报（RFC 1928 UDP ASSOCIATE 数据面）
     * @param target 目标地址
     * @param payload UDP 载荷
     * @return 数据报字节：[RSV 2B 0x0000][FRAG 1B 0x00][ATYP 1B][ADDR var][PORT 2B BE][payload]
     * @details 头部无长度字段，载荷边界由调用方（一次底层读）约定。
     * @note FRAG 固定 0x00（不支持分片）
     */
    [[nodiscard]] inline auto build_udp_datagram(const address &target,
                                                 std::span<const std::uint8_t> payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        const auto addr = encode_address(target);
        out.reserve(3 + addr.size() + payload.size());
        out.push_back(0x00);
        out.push_back(0x00);
        out.push_back(0x00);
        out.insert(out.end(), addr.begin(), addr.end());
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    /**
     * @brief 解析 SOCKS5 UDP 数据报
     * @param data 输入数据
     * @param target 输出目标地址
     * @param payload 输出载荷（视图指向 data）
     * @return 错误码；need_more = 数据不足
     * @details 校验 RSV 与 FRAG，地址解析后剩余全部字节即为载荷。
     */
    [[nodiscard]] inline auto parse_udp_datagram(std::span<const std::uint8_t> data,
                                                 address &target,
                                                 std::span<const std::uint8_t> &payload) -> error
    {
        if (data.size() < 3)
            return error::need_more;
        if (data[0] != 0x00 || data[1] != 0x00)
            return error::bad_magic;
        if (data[2] != 0x00)
            return error::not_supported;
        std::size_t consumed = 0;
        auto err = parse_address(data.subspan(3), target, consumed);
        if (err != error::none)
            return err;
        payload = data.subspan(3 + consumed);
        return error::none;
    }

    /**
     * @brief 用户名/密码认证请求（RFC 1929）
     * @param user 用户名
     * @param pass 密码
     * @return 认证请求字节：[ver 0x01][ulen][uname][plen][passwd]
     */
    [[nodiscard]] inline auto build_userpass(std::string_view user, std::string_view pass)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(2 + user.size() + 1 + pass.size());
        out.push_back(0x01);
        out.push_back(static_cast<std::uint8_t>(user.size()));
        out.insert(out.end(), user.begin(), user.end());
        out.push_back(static_cast<std::uint8_t>(pass.size()));
        out.insert(out.end(), pass.begin(), pass.end());
        return out;
    }

    /**
     * @brief 解析用户名/密码认证响应（1 字节状态）
     * @param data 输入
     * @return 错误码；0x01 表示认证通过，其余为 bad_auth
     */
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
            /// 方法选择回复
            method_reply,
            /// 用户名/密码认证（RFC 1929）
            userpass,
            /// 请求（CONNECT / UDP_ASSOCIATE）
            request,
            /// 响应（reply）
            reply,
        };

        /// 消息类型
        kind type{kind::greeting};
        /// 认证方法列表（greeting）
        std::vector<std::uint8_t> methods;
        /// 认证方法选择（method_reply / userpass 状态）
        std::uint8_t method{0x00};
        /// 命令（request）
        command cmd{command::connect};
        /// 响应码（reply）
        reply_code rep{reply_code::success};
        /// 目标 / 绑定地址
        address addr;
        /// 用户名（userpass）
        std::string username;
        /// 密码（userpass）
        std::string password;
    };

    /// @brief SOCKS5 消息序列化器（对象 → wire，Beast 风格）
    class serializer
    {
    public:
        /**
         * @brief 重置并绑定消息
         * @param msg 消息（内部持有拷贝，生命周期安全）
         * @details 按消息类型编码为 wire 字节，随后可通过 get() 增量输出。
         */
        auto reset(const message &msg) -> void
        {
            wire_.clear();
            offset_ = 0;
            switch (msg.type)
            {
                case message::kind::greeting:
                {
                    greeting g;
                    g.ver = version;
                    g.methods = msg.methods;
                    wire_ = build_greeting(g);
                    break;
                }
                case message::kind::method_reply:
                {
                    method_reply mr;
                    mr.ver = version;
                    mr.method = static_cast<auth_method>(msg.method);
                    wire_.assign(build_method_reply(mr).begin(), build_method_reply(mr).end());
                    break;
                }
                case message::kind::userpass:
                {
                    wire_ = build_userpass(msg.username, msg.password);
                    break;
                }
                case message::kind::request:
                {
                    request req;
                    req.ver = version;
                    req.cmd = msg.cmd;
                    req.target = msg.addr;
                    wire_ = build_request(req);
                    break;
                }
                case message::kind::reply:
                {
                    reply rep;
                    rep.ver = version;
                    rep.code = msg.rep;
                    rep.bind = msg.addr;
                    wire_ = build_reply(rep);
                    break;
                }
            }
        }

        /**
         * @brief 增量输出
         * @param buffer 输出缓冲区
         * @param ec 错误码输出参数
         * @return 写入字节数
         */
        auto get(boost::asio::mutable_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto n = std::min(buffer.size(), wire_.size() - offset_);
            std::memcpy(buffer.data(), wire_.data() + offset_, n);
            offset_ += n;
            return n;
        }

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto is_done() const -> bool
        {
            return offset_ >= wire_.size();
        }

    private:
        std::vector<std::uint8_t> wire_;
        std::size_t offset_{0};
    };

    /// @brief SOCKS5 消息解析器（wire → 对象，Beast 风格）
    /// @details 增量喂入字节流，按 expect 的消息类型驱动状态机。
    /// put() 返回本次消耗的字节数；不足时返回 need_more（ec 保持空）。
    /// 解析完成后通过 get() 取结果，通过 remaining() 取未消耗的超读字节。
    class parser
    {
    public:
        /**
         * @brief 设置期望的消息类型
         * @param kind 消息类型
         * @details 决定 put() 内部解析路径（greeting/method_reply/userpass/request/reply）。
         */
        auto expect(message::kind kind) -> void
        {
            expect_ = kind;
        }

        /**
         * @brief 增量喂入字节
         * @param buffer 输入数据
         * @param ec 错误码输出参数
         * @return 本次消耗的字节数（0 = 半帧等待）
         */
        auto put(boost::asio::const_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto data = std::span<const std::uint8_t>(
                static_cast<const std::uint8_t *>(buffer.data()), buffer.size());
            prev_buf_size_ = buf_.size();
            buf_.insert(buf_.end(), data.begin(), data.end());
            if (done_)
                return 0;
            std::size_t consumed = 0;
            error err = error::none;

            switch (expect_)
            {
                case message::kind::greeting:
                {
                    greeting g;
                    err = parse_greeting(buf_, g, consumed);
                    if (err == error::none)
                    {
                        msg_.type = message::kind::greeting;
                        msg_.methods = std::move(g.methods);
                    }
                    break;
                }
                case message::kind::method_reply:
                {
                    method_reply mr;
                    err = parse_method_reply(buf_, mr);
                    if (err == error::none)
                    {
                        msg_.type = message::kind::method_reply;
                        msg_.method = static_cast<std::uint8_t>(mr.method);
                        consumed = 2;
                    }
                    break;
                }
                case message::kind::userpass:
                {
                    // 认证子协商：[ver 0x01][ulen][uname][plen][passwd]
                    std::size_t off = 0;
                    if (buf_.size() < off + 2)
                    {
                        err = error::need_more;
                        break;
                    }
                    if (buf_[0] != 0x01)
                    {
                        err = error::bad_magic;
                        break;
                    }
                    const auto ulen = buf_[1];
                    off = 2;
                    if (buf_.size() < off + ulen + 1)
                    {
                        err = error::need_more;
                        break;
                    }
                    msg_.username.assign(reinterpret_cast<const char *>(buf_.data() + off), ulen);
                    off += ulen;
                    const auto plen = buf_[off++];
                    if (buf_.size() < off + plen)
                    {
                        err = error::need_more;
                        break;
                    }
                    msg_.password.assign(reinterpret_cast<const char *>(buf_.data() + off), plen);
                    off += plen;
                    consumed = off;
                    msg_.type = message::kind::userpass;
                    break;
                }
                case message::kind::request:
                {
                    request req;
                    err = parse_request(buf_, req, consumed);
                    if (err == error::none)
                    {
                        msg_.type = message::kind::request;
                        msg_.cmd = req.cmd;
                        msg_.addr = req.target;
                    }
                    break;
                }
                case message::kind::reply:
                {
                    reply rep;
                    err = parse_reply(buf_, rep, consumed);
                    if (err == error::none)
                    {
                        msg_.type = message::kind::reply;
                        msg_.rep = rep.code;
                        msg_.addr = rep.bind;
                    }
                    break;
                }
            }

            if (err == error::need_more)
                return 0;
            if (err != error::none)
            {
                ec = make_error_code(err);
                return 0;
            }
            done_ = true;
            // 返回本次 put 中构成帧的字节数（跨帧增量语义）
            consumed_ = consumed;
            const auto incremental = std::min(consumed, prev_buf_size_ + data.size()) - prev_buf_size_;
            return incremental;
        }

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto is_done() const -> bool
        {
            return done_;
        }

        /**
         * @brief 解析结果
         * @return 消息引用（解析完成后调用）
         */
        [[nodiscard]] auto get() const -> const message &
        {
            return msg_;
        }

        /**
         * @brief 获取未消耗的超读字节
         * @return 剩余字节（解析完成后调用）
         */
        [[nodiscard]] auto remaining() const -> std::span<const std::uint8_t>
        {
            if (buf_.empty() || !done_)
                return {};
            // 记录 consumed 偏移：put 成功时保存
            return std::span<const std::uint8_t>(buf_.data() + consumed_, buf_.size() - consumed_);
        }

        /**
         * @brief 提取未消耗的超读字节（所有权移交）
         * @return 剩余字节
         */
        [[nodiscard]] auto take_remaining() -> std::vector<std::uint8_t>
        {
            if (!done_ || consumed_ >= buf_.size())
                return {};
            std::vector<std::uint8_t> out(buf_.begin() + static_cast<std::ptrdiff_t>(consumed_), buf_.end());
            buf_.clear();
            consumed_ = 0;
            prev_buf_size_ = 0;
            return out;
        }

        /**
         * @brief 重置
         * @details 清空内部缓冲与解析状态，可复用同一解析器。
         */
        auto reset() -> void
        {
            buf_.clear();
            msg_ = message{};
            done_ = false;
            consumed_ = 0;
            prev_buf_size_ = 0;
        }

    private:
        message::kind expect_{message::kind::greeting};
        std::vector<std::uint8_t> buf_;
        message msg_{};
        std::size_t consumed_{0};
        std::size_t prev_buf_size_{0};
        bool done_{false};
    };

    /**
     * @brief 异步读取并解析一条消息（组合操作）
     * @param transport 底层传输（transmission 接口）
     * @param p 解析器（expect 已设置）
     * @return 错误码（半帧等待由内部循环处理；EOF = unexpected_eof）
     * @details Beast 风格自由函数：循环 async_read_some → put，直到解析完成。
     */
    [[nodiscard]] inline auto async_read(shared_transmission transport, parser &p)
        -> net::awaitable<error>
    {
        std::array<std::uint8_t, 512> buf{};
        while (!p.is_done())
        {
            std::error_code ec;
            auto buffer = as_bytes(std::span<std::uint8_t>(buf));
            const auto n = co_await transport->async_read_some(buffer, ec);
            if (ec)
                co_return error::io_error;
            if (n == 0)
                co_return error::unexpected_eof;
            std::error_code perr;
            p.put(boost::asio::buffer(buf.data(), n), perr);
            if (perr)
                co_return static_cast<error>(perr.value());
        }
        co_return error::none;
    }

    /**
     * @brief 异步发送一条消息（组合操作）
     * @param transport 底层传输（transmission 接口）
     * @param s 序列化器（reset 已设置）
     * @return 错误码
     * @details Beast 风格自由函数：循环 get → async_write_some，直到输出完成。
     */
    [[nodiscard]] inline auto async_write(shared_transmission transport, serializer &s)
        -> net::awaitable<error>
    {
        std::array<std::uint8_t, 512> buf{};
        while (!s.is_done())
        {
            std::error_code ec;
            const auto n = s.get(boost::asio::buffer(buf.data(), buf.size()), ec);
            if (ec)
                co_return error::io_error;
            if (n == 0)
                co_return error::bad_length;
            std::size_t done = 0;
            while (done < n)
            {
                auto view = as_bytes(std::span<const std::uint8_t>(buf.data() + done, n - done));
                const auto w = co_await transport->async_write_some(view, ec);
                if (ec)
                    co_return error::io_error;
                if (w == 0)
                    co_return error::broken_pipe;
                done += w;
            }
        }
        co_return error::none;
    }

} // namespace psmtest::socks5
