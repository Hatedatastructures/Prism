/**
 * @file Codec.hpp
 * @brief SOCKS5 消息编解码（纯函数，零状态）
 * @details 实现 Greeting / MethodReply / Request / Reply 的编解码，
 *          支持增量解析（need_more）与边界校验。
 */

#pragma once

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

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Error.hpp>
#include <common/Core/Protocol/Address.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Socks5/Types.hpp>

namespace Preview::Socks5
{

    /**
     * @brief 编码 Greeting（写入复用缓冲）
     * @param g 问候（版本 + 方法列表）
     * @param out 输出缓冲（调用方持有复用，热路径零分配）
     * @details 覆盖式写入；缓冲容量不足时自动扩容（首次分配后复用）。
     * 接受任意分配器 vector（std::vector / pmr vector 均可）。
     */
    template <typename Alloc>
    inline auto BuildGreeting(const Greeting &g, std::vector<std::uint8_t, Alloc> &out) -> void
    {
        out.clear();
        out.reserve(2 + g.methods.size());
        out.push_back(g.Ver);
        out.push_back(static_cast<std::uint8_t>(g.methods.size()));
        out.insert(out.end(), g.methods.begin(), g.methods.end());
    }

    /**
     * @brief 编码 Greeting
     * @param g 问候（版本 + 方法列表）
     * @return Greeting 字节：[ver 1B][nmethods 1B][methods var]
     */
    [[nodiscard]] inline auto BuildGreeting(const Greeting &g) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        BuildGreeting(g, out);
        return out;
    }

    /**
     * @brief 解析 Greeting（增量）
     * @param Data 输入
     * @param out 输出
     * @param consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseGreeting(std::span<const std::uint8_t> Data, Greeting &out,
                                             std::size_t &consumed) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::need_more;
        }
        out.Ver = Data[0];
        if (out.Ver != Version)
        {
            return Error::version_mismatch;
        }
        const auto nmethods = Data[1];
        if (Data.size() < 2 + nmethods)
        {
            return Error::need_more;
        }
        out.methods.assign(Data.begin() + 2, Data.begin() + 2 + nmethods);
        consumed = 2 + nmethods;
        return Error::none;
    }

    /**
     * @brief 编码方法选择
     * @param m 方法选择（版本 + 方法）
     * @return 2 字节回复
     */
    [[nodiscard]] inline auto BuildMethodReply(const MethodReply &m) -> std::array<std::uint8_t, 2>
    {
        return {m.Ver, static_cast<std::uint8_t>(m.Method)};
    }

    /**
     * @brief 解析方法选择
     * @param Data 输入
     * @param out 输出方法选择
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseMethodReply(std::span<const std::uint8_t> Data, MethodReply &out)
        -> Error
    {
        if (Data.size() < 2)
        {
            return Error::need_more;
        }
        out.Ver = Data[0];
        if (out.Ver != Version)
        {
            return Error::bad_magic;
        }
        out.Method = static_cast<AuthMethod>(Data[1]);
        return Error::none;
    }

    /**
     * @brief 编码地址（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @param addr 目标地址
     * @param out 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     * @note 转发层：统一实现见 Protocol/common::EncodeAddress（行为一致）
     */
    template <typename Alloc>
    inline auto EncodeAddress(const Address &addr, std::vector<std::uint8_t, Alloc> &out) -> void
    {
        Preview::Protocol::Common::EncodeAddress(addr, out);
    }

    /**
     * @brief 编码地址（ATYP + ADDR + PORT 2B BE）
     * @param addr 目标地址
     * @return 地址字节
     */
    [[nodiscard]] inline auto EncodeAddress(const Address &addr) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        EncodeAddress(addr, out);
        return out;
    }

    /**
     * @brief 解析地址（增量）
     * @param Data 输入
     * @param out 输出地址
     * @param consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseAddress(std::span<const std::uint8_t> Data, Address &out,
                                            std::size_t &consumed) -> Error
    {
        if (Data.empty())
        {
            return Error::need_more;
        }
        out.Type = static_cast<AddressType>(Data[0]);
        std::size_t off = 1;
        switch (out.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < off + 4 + 2)
            {
                return Error::need_more;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", Data[off], Data[off + 1], Data[off + 2],
                          Data[off + 3]);
            out.Host = buf.data();
            off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < off + 16 + 2)
            {
                return Error::need_more;
            }
            out.Host.assign(reinterpret_cast<const char *>(Data.data() + off), 16);
            off += 16;
            break;
        }
        case AddressType::Domain: {
            if (off >= Data.size())
            {
                return Error::need_more;
            }
            const auto len = Data[off++];
            if (Data.size() < off + len + 2)
            {
                return Error::need_more;
            }
            out.Host.assign(reinterpret_cast<const char *>(Data.data() + off), len);
            off += len;
            break;
        }
        default: return Error::bad_message;
        }
        out.Port = static_cast<std::uint16_t>(Data[off]) << 8 | Data[off + 1];
        consumed = off + 2;
        return Error::none;
    }

    /**
     * @brief 编码请求（写入复用缓冲）
     * @param req 请求（命令 + 目标地址）
     * @param out 输出缓冲（调用方持有复用，热路径零分配）
     * @details 头部 3 字节后直接续写地址，无中间缓冲。
     */
    template <typename Alloc>
    inline auto BuildRequest(const Request &req, std::vector<std::uint8_t, Alloc> &out) -> void
    {
        out.clear();
        out.reserve(3 + req.Target.Host.size() + 8);
        out.push_back(req.Ver);
        out.push_back(static_cast<std::uint8_t>(req.Cmd));
        out.push_back(req.Rsv);
        EncodeAddress(req.Target, out);
    }

    /**
     * @brief 编码请求
     * @param req 请求（命令 + 目标地址）
     * @return 请求字节：[ver][cmd][rsv][ATYP][ADDR][PORT]
     */
    [[nodiscard]] inline auto BuildRequest(const Request &req) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        BuildRequest(req, out);
        return out;
    }

    /**
     * @brief 解析请求（增量）
     * @param Data 输入
     * @param out 输出请求
     * @param consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseRequest(std::span<const std::uint8_t> Data, Request &out,
                                            std::size_t &consumed) -> Error
    {
        if (Data.size() < 4)
        {
            return Error::need_more;
        }
        out.Ver = Data[0];
        if (out.Ver != Version)
        {
            return Error::bad_magic;
        }
        out.Cmd = static_cast<Command>(Data[1]);
        if (out.Cmd != Command::Connect && out.Cmd != Command::UdpAssociate)
        {
            return Error::not_supported;
        }
        out.Rsv = Data[2];
        std::size_t AddrConsumed = 0;
        const auto ec = ParseAddress(Data.subspan(3), out.Target, AddrConsumed);
        if (ec != Error::none)
        {
            return ec;
        }
        consumed = 3 + AddrConsumed;
        return Error::none;
    }

    /**
     * @brief 编码响应（写入复用缓冲）
     * @param rep 响应（状态码 + 绑定地址）
     * @param out 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildReply(const Reply &rep, std::vector<std::uint8_t, Alloc> &out) -> void
    {
        out.clear();
        out.reserve(3 + rep.Bind.Host.size() + 8);
        out.push_back(rep.Ver);
        out.push_back(static_cast<std::uint8_t>(rep.Code));
        out.push_back(rep.Rsv);
        EncodeAddress(rep.Bind, out);
    }

    /**
     * @brief 编码响应
     * @param rep 响应（状态码 + 绑定地址）
     * @return 响应字节：[ver][Code][rsv][ATYP][ADDR][PORT]
     */
    [[nodiscard]] inline auto BuildReply(const Reply &rep) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        BuildReply(rep, out);
        return out;
    }

    /**
     * @brief 解析响应（增量）
     * @param Data 输入
     * @param out 输出响应
     * @param consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseReply(std::span<const std::uint8_t> Data, Reply &out,
                                          std::size_t &consumed) -> Error
    {
        if (Data.size() < 4)
        {
            return Error::need_more;
        }
        out.Ver = Data[0];
        out.Code = static_cast<ReplyCode>(Data[1]);
        out.Rsv = Data[2];
        std::size_t AddrConsumed = 0;
        const auto ec = ParseAddress(Data.subspan(3), out.Bind, AddrConsumed);
        if (ec != Error::none)
        {
            return ec;
        }
        consumed = 3 + AddrConsumed;
        return Error::none;
    }

    /**
     * @brief 构造 SOCKS5 UDP 数据报（写入复用缓冲）
     * @param Target 目标地址
     * @param payload UDP 载荷
     * @param out 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildUdpDatagram(const Address &Target, std::span<const std::uint8_t> payload,
                                   std::vector<std::uint8_t, Alloc> &out) -> void
    {
        out.clear();
        out.reserve(3 + Target.Host.size() + 8 + payload.size());
        out.push_back(0x00);
        out.push_back(0x00);
        out.push_back(0x00);
        EncodeAddress(Target, out);
        out.insert(out.end(), payload.begin(), payload.end());
    }

    /**
     * @brief 构造 SOCKS5 UDP 数据报（RFC 1928 UDP ASSOCIATE 数据面）
     * @param Target 目标地址
     * @param payload UDP 载荷
     * @return 数据报字节：[RSV 2B 0x0000][FRAG 1B 0x00][ATYP 1B][ADDR var][PORT 2B BE][payload]
     * @details 头部无长度字段，载荷边界由调用方（一次底层读）约定。
     * @note FRAG 固定 0x00（不支持分片）
     */
    [[nodiscard]] inline auto BuildUdpDatagram(const Address &Target, std::span<const std::uint8_t> payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        BuildUdpDatagram(Target, payload, out);
        return out;
    }

    /**
     * @brief 解析 SOCKS5 UDP 数据报
     * @param Data 输入数据
     * @param Target 输出目标地址
     * @param payload 输出载荷（视图指向 Data）
     * @return 错误码；need_more = 数据不足
     * @details 校验 RSV 与 FRAG，地址解析后剩余全部字节即为载荷。
     */
    [[nodiscard]] inline auto ParseUdpDatagram(std::span<const std::uint8_t> Data, Address &Target,
                                                 std::span<const std::uint8_t> &payload) -> Error
    {
        if (Data.size() < 3)
        {
            return Error::need_more;
        }
        if (Data[0] != 0x00 || Data[1] != 0x00)
        {
            return Error::bad_magic;
        }
        if (Data[2] != 0x00)
        {
            return Error::not_supported;
        }
        std::size_t consumed = 0;
        auto err = ParseAddress(Data.subspan(3), Target, consumed);
        if (err != Error::none)
        {
            return err;
        }
        payload = Data.subspan(3 + consumed);
        return Error::none;
    }

    /**
     * @brief 用户名/密码认证请求（写入复用缓冲）
     * @param user 用户名
     * @param pass 密码
     * @param out 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildUserpass(std::string_view user, std::string_view pass,
                               std::vector<std::uint8_t, Alloc> &out) -> void
    {
        out.clear();
        out.reserve(2 + user.size() + 1 + pass.size());
        out.push_back(0x01);
        out.push_back(static_cast<std::uint8_t>(user.size()));
        out.insert(out.end(), user.begin(), user.end());
        out.push_back(static_cast<std::uint8_t>(pass.size()));
        out.insert(out.end(), pass.begin(), pass.end());
    }

    /**
     * @brief 用户名/密码认证请求（RFC 1929）
     * @param user 用户名
     * @param pass 密码
     * @return 认证请求字节：[ver 0x01][ulen][uname][plen][passwd]
     */
    [[nodiscard]] inline auto BuildUserpass(std::string_view user, std::string_view pass)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        BuildUserpass(user, pass, out);
        return out;
    }

    /**
     * @brief 解析用户名/密码认证响应（1 字节状态）
     * @param Data 输入
     * @return 错误码；0x01 表示认证通过，其余为 bad_auth
     */
    [[nodiscard]] inline auto ParseUserpassReply(std::span<const std::uint8_t> Data) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::need_more;
        }
        if (Data[0] != 0x01)
        {
            return Error::bad_magic;
        }
        if (Data[1] == 0x00)
        {
            return Error::none;
        }
        return Error::bad_auth;
    }

    /**
     * @brief SOCKS5 消息（Beast 风格，供 Serializer/Parser 使用）
     */
    struct Message
    {
        /// 消息类型
        enum class Kind : std::uint8_t
        {
            /// 问候（Greeting）
            Greeting,
            /// 方法选择回复
            MethodReply,
            /// 用户名/密码认证（RFC 1929）
            userpass,
            /// 请求（CONNECT / UDP_ASSOCIATE）
            Request,
            /// 响应（Reply）
            Reply,
        };

        /// 消息类型
        Kind Type{Kind::Greeting};
        /// 认证方法列表（Greeting）
        std::vector<std::uint8_t> methods;
        /// 认证方法选择（MethodReply / userpass 状态）
        std::uint8_t Method{0x00};
        /// 命令（Request）
        Command Cmd{Command::Connect};
        /// 响应码（Reply）
        ReplyCode rep{ReplyCode::success};
        /// 目标 / 绑定地址
        Address addr;
        /// 用户名（userpass）
        std::string username;
        /// 密码（userpass）
        std::string password;
    };

    /**
     * @brief SOCKS5 消息序列化器（对象 → wire，Beast 风格）
     */
    class Serializer
    {
    public:
        /**
         * @brief 重置并绑定消息
         * @param msg 消息（内部持有拷贝，生命周期安全）
         * @details 按消息类型编码为 wire 字节，随后可通过 Get() 增量输出。
         */
        auto Reset(const Message &msg) -> void
        {
            wire_.clear();
            offset_ = 0;
            switch (msg.Type)
            {
            case Message::Kind::Greeting: {
                Greeting g;
                g.Ver = Version;
                g.methods = msg.methods;
                wire_ = BuildGreeting(g);
                break;
            }
            case Message::Kind::MethodReply: {
                MethodReply mr;
                mr.Ver = Version;
                mr.Method = static_cast<AuthMethod>(msg.Method);
                wire_.assign(BuildMethodReply(mr).begin(), BuildMethodReply(mr).end());
                break;
            }
            case Message::Kind::userpass: {
                wire_ = BuildUserpass(msg.username, msg.password);
                break;
            }
            case Message::Kind::Request: {
                Request req;
                req.Ver = Version;
                req.Cmd = msg.Cmd;
                req.Target = msg.addr;
                wire_ = BuildRequest(req);
                break;
            }
            case Message::Kind::Reply: {
                Reply rep;
                rep.Ver = Version;
                rep.Code = msg.rep;
                rep.Bind = msg.addr;
                wire_ = BuildReply(rep);
                break;
            }
            }
        }

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲区
         * @param ec 错误码输出参数
         * @return 写入字节数
         */
        auto Get(boost::asio::mutable_buffer Buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto n = std::min(Buffer.size(), wire_.size() - offset_);
            std::memcpy(Buffer.data(), wire_.data() + offset_, n);
            offset_ += n;
            return n;
        }

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return offset_ >= wire_.size();
        }

    private:
        std::vector<std::uint8_t> wire_;
        std::size_t offset_{0};
    };

    /**
     * @brief SOCKS5 消息解析器（wire → 对象，Beast 风格）
     * @details 增量喂入字节流，按 Expect 的消息类型驱动状态机。
     * Put() 返回本次消耗的字节数；不足时返回 need_more（ec 保持空）。
     * 解析完成后通过 Get() 取结果，通过 Remaining() 取未消耗的超读字节。
     */
    class Parser
    {
    public:
        /**
         * @brief 设置期望的消息类型
         * @param Kind 消息类型
         * @details 决定 Put() 内部解析路径（Greeting/MethodReply/userpass/Request/Reply）。
         */
        auto Expect(Message::Kind Kind) -> void
        {
            expect_ = Kind;
        }

        /**
         * @brief 增量喂入字节
         * @param Buffer 输入数据
         * @param ec 错误码输出参数
         * @return 本次消耗的字节数（0 = 半帧等待）
         */
        auto Put(boost::asio::const_buffer Buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto Data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(Buffer.data()),
                                                            Buffer.size());
            PrevBufSize_ = buf_.size();
            buf_.insert(buf_.end(), Data.begin(), Data.end());
            if (done_)
            {
                return 0;
            }
            std::size_t consumed = 0;
            Error err = Error::none;

            switch (expect_)
            {
            case Message::Kind::Greeting: {
                Greeting g;
                err = ParseGreeting(buf_, g, consumed);
                if (err == Error::none)
                {
                    msg_.Type = Message::Kind::Greeting;
                    msg_.methods = std::move(g.methods);
                }
                break;
            }
            case Message::Kind::MethodReply: {
                MethodReply mr;
                err = ParseMethodReply(buf_, mr);
                if (err == Error::none)
                {
                    msg_.Type = Message::Kind::MethodReply;
                    msg_.Method = static_cast<std::uint8_t>(mr.Method);
                    consumed = 2;
                }
                break;
            }
            case Message::Kind::userpass: {
                // 认证子协商：[ver 0x01][ulen][uname][plen][passwd]
                std::size_t off = 0;
                if (buf_.size() < off + 2)
                {
                    err = Error::need_more;
                    break;
                }
                if (buf_[0] != 0x01)
                {
                    err = Error::bad_magic;
                    break;
                }
                const auto ulen = buf_[1];
                off = 2;
                if (buf_.size() < off + ulen + 1)
                {
                    err = Error::need_more;
                    break;
                }
                msg_.username.assign(reinterpret_cast<const char *>(buf_.data() + off), ulen);
                off += ulen;
                const auto plen = buf_[off++];
                if (buf_.size() < off + plen)
                {
                    err = Error::need_more;
                    break;
                }
                msg_.password.assign(reinterpret_cast<const char *>(buf_.data() + off), plen);
                off += plen;
                consumed = off;
                msg_.Type = Message::Kind::userpass;
                break;
            }
            case Message::Kind::Request: {
                Request req;
                err = ParseRequest(buf_, req, consumed);
                if (err == Error::none)
                {
                    msg_.Type = Message::Kind::Request;
                    msg_.Cmd = req.Cmd;
                    msg_.addr = req.Target;
                }
                break;
            }
            case Message::Kind::Reply: {
                Reply rep;
                err = ParseReply(buf_, rep, consumed);
                if (err == Error::none)
                {
                    msg_.Type = Message::Kind::Reply;
                    msg_.rep = rep.Code;
                    msg_.addr = rep.Bind;
                }
                break;
            }
            }

            if (err == Error::need_more)
            {
                return 0;
            }
            if (err != Error::none)
            {
                ec = make_error_code(err);
                return 0;
            }
            done_ = true;
            // 返回本次 Put 中构成帧的字节数（跨帧增量语义）
            consumed_ = consumed;
            const auto incremental = std::min(consumed, PrevBufSize_ + Data.size()) - PrevBufSize_;
            return incremental;
        }

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return done_;
        }

        /**
         * @brief 解析结果
         * @return 消息引用（解析完成后调用）
         */
        [[nodiscard]] auto Get() const -> const Message &
        {
            return msg_;
        }

        /**
         * @brief 获取未消耗的超读字节
         * @return 剩余字节（解析完成后调用）
         */
        [[nodiscard]] auto Remaining() const -> std::span<const std::uint8_t>
        {
            if (buf_.empty() || !done_)
            {
                return {};
            }
            // 记录 consumed 偏移：Put 成功时保存
            return std::span<const std::uint8_t>(buf_.data() + consumed_, buf_.size() - consumed_);
        }

        /**
         * @brief 提取未消耗的超读字节（所有权移交）
         * @return 剩余字节
         */
        [[nodiscard]] auto TakeRemaining() -> std::vector<std::uint8_t>
        {
            if (!done_ || consumed_ >= buf_.size())
            {
                return {};
            }
            std::vector<std::uint8_t> out(buf_.begin() + static_cast<std::ptrdiff_t>(consumed_), buf_.end());
            buf_.clear();
            consumed_ = 0;
            PrevBufSize_ = 0;
            return out;
        }

        /**
         * @brief 重置
         * @details 清空内部缓冲与解析状态，可复用同一解析器。
         */
        auto Reset() -> void
        {
            buf_.clear();
            msg_ = Message{};
            done_ = false;
            consumed_ = 0;
            PrevBufSize_ = 0;
        }

    private:
        Message::Kind expect_{Message::Kind::Greeting};
        std::vector<std::uint8_t> buf_;
        Message msg_{};
        std::size_t consumed_{0};
        std::size_t PrevBufSize_{0};
        bool done_{false};
    };

    /**
     * @brief 异步读取并解析一条消息（组合操作）
     * @param transport 底层传输（Transmission 接口）
     * @param p 解析器（Expect 已设置）
     * @return 错误码（半帧等待由内部循环处理；EOF = unexpected_eof）
     * @details Beast 风格自由函数：循环 AsyncReadSome → Put，直到解析完成。
     */
    [[nodiscard]] inline auto AsyncRead(SharedTransmission transport, Parser &p) -> net::awaitable<Error>
    {
        std::array<std::uint8_t, 512> buf{};
        while (!p.IsDone())
        {
            std::error_code ec;
            auto Buffer = AsBytes(std::span<std::uint8_t>(buf));
            const auto n = co_await transport->AsyncReadSome(Buffer, ec);
            if (ec)
            {
                co_return Error::io_error;
            }
            if (n == 0)
            {
                co_return Error::unexpected_eof;
            }
            std::error_code perr;
            p.Put(boost::asio::buffer(buf.data(), n), perr);
            if (perr)
            {
                co_return static_cast<Error>(perr.value());
            }
        }
        co_return Error::none;
    }

    /**
     * @brief 异步发送一条消息（组合操作）
     * @param transport 底层传输（Transmission 接口）
     * @param s 序列化器（Reset 已设置）
     * @return 错误码
     * @details Beast 风格自由函数：循环 Get → AsyncWriteSome，直到输出完成。
     */
    [[nodiscard]] inline auto AsyncWrite(SharedTransmission transport, Serializer &s)
        -> net::awaitable<Error>
    {
        std::array<std::uint8_t, 512> buf{};
        while (!s.IsDone())
        {
            std::error_code ec;
            const auto n = s.Get(boost::asio::buffer(buf.data(), buf.size()), ec);
            if (ec)
            {
                co_return Error::io_error;
            }
            if (n == 0)
            {
                co_return Error::bad_length;
            }
            std::size_t Done = 0;
            while (Done < n)
            {
                auto view = AsBytes(std::span<const std::uint8_t>(buf.data() + Done, n - Done));
                const auto w = co_await transport->AsyncWriteSome(view, ec);
                if (ec)
                {
                    co_return Error::io_error;
                }
                if (w == 0)
                {
                    co_return Error::broken_pipe;
                }
                Done += w;
            }
        }
        co_return Error::none;
    }

} // namespace Preview::Socks5
