/**
 * @file codec.hpp
 * @brief Hysteria2 帧编解码（纯函数 + serializer/parser 类）
 * @details 帧格式（简化对齐 hysteria2 测试协议）：
 *          TCP：[Kind 1B][ATYP 1B][ADDR][PORT 2B BE][Payload]
 *          UDP：[Kind 1B][SessionID 4B LE][PacketID 4B LE][ATYP 1B][ADDR][PORT 2B BE][Payload]
 *          另含认证请求构造（make_auth_request，HTTP/3 HEADERS 风格）
 *          与 Beast 风格 serializer/parser 类。
 * @note 参考 hysteria2 协议规范。
 */

#pragma once

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <common/core/error.hpp>
#include <common/proxy/hysteria2/types.hpp>

namespace psmtest::hysteria2
{

    /**
     * @brief 编码地址（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @param addr 目标地址
     * @param out 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto encode_address(const address &addr, std::vector<std::uint8_t, Alloc> &out) -> void
    {
        out.push_back(static_cast<std::uint8_t>(addr.type));
        switch (addr.type)
        {
        case address_type::ipv4: {
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
        case address_type::ipv6: {
            out.insert(out.end(), addr.host.begin(), addr.host.end());
            break;
        }
        case address_type::domain:
        default: {
            out.push_back(static_cast<std::uint8_t>(addr.host.size()));
            out.insert(out.end(), addr.host.begin(), addr.host.end());
            break;
        }
        }
        out.push_back(static_cast<std::uint8_t>((addr.port >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(addr.port & 0xFF));
    }

    /**
     * @brief 编码地址（ATYP + ADDR + PORT 2B BE）
     */
    [[nodiscard]] inline auto encode_address(const address &addr) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        encode_address(addr, out);
        return out;
    }

    /**
     * @brief 解析地址（增量）
     * @param data 输入
     * @param out 输出地址
     * @param consumed 输出消耗字节数
     * @return 错误码
     */
    [[nodiscard]] inline auto parse_address(std::span<const std::uint8_t> data, address &out,
                                            std::size_t &consumed) -> error
    {
        if (data.empty())
        {
            return error::need_more;
        }
        out.type = static_cast<address_type>(data[0]);
        std::size_t off = 1;
        switch (out.type)
        {
        case address_type::ipv4: {
            if (data.size() < off + 4 + 2)
            {
                return error::need_more;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", data[off], data[off + 1], data[off + 2],
                          data[off + 3]);
            out.host = buf.data();
            off += 4;
            break;
        }
        case address_type::ipv6: {
            if (data.size() < off + 16 + 2)
            {
                return error::need_more;
            }
            out.host.assign(reinterpret_cast<const char *>(data.data() + off), 16);
            off += 16;
            break;
        }
        case address_type::domain:
        default: {
            if (off >= data.size())
            {
                return error::need_more;
            }
            const auto len = data[off++];
            if (data.size() < off + len + 2)
            {
                return error::need_more;
            }
            out.host.assign(reinterpret_cast<const char *>(data.data() + off), len);
            off += len;
            break;
        }
        }
        out.port = static_cast<std::uint16_t>(data[off]) << 8 | data[off + 1];
        consumed = off + 2;
        return error::none;
    }

    /**
     * @brief 构造 TCP 帧
     */
    [[nodiscard]] inline auto build_tcp(const address &dst, std::span<const std::uint8_t> payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.push_back(static_cast<std::uint8_t>(message::kind::tcp));
        const auto addr = encode_address(dst);
        out.insert(out.end(), addr.begin(), addr.end());
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    /**
     * @brief UDP 帧构造输入（session_id + packet_id + dst + payload）
     */
    struct udp_frame_input
    {
        std::uint32_t session_id{0};           ///< 会话 ID
        std::uint32_t packet_id{0};            ///< 包 ID
        const address *dst{nullptr};           ///< 目标地址
        std::span<const std::uint8_t> payload; ///< 载荷
    };

    /**
     * @brief 构造 UDP 帧（写入复用缓冲）
     * @param in 输入
     * @param out 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto build_udp(const udp_frame_input &in, std::vector<std::uint8_t, Alloc> &out) -> void
    {
        out.clear();
        if (!in.dst)
        {
            return;
        }
        out.push_back(static_cast<std::uint8_t>(message::kind::udp));
        out.push_back(static_cast<std::uint8_t>(in.session_id & 0xFF));
        out.push_back(static_cast<std::uint8_t>((in.session_id >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((in.session_id >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((in.session_id >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(in.packet_id & 0xFF));
        out.push_back(static_cast<std::uint8_t>((in.packet_id >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((in.packet_id >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((in.packet_id >> 24) & 0xFF));
        encode_address(*in.dst, out);
        out.insert(out.end(), in.payload.begin(), in.payload.end());
    }

    /**
     * @brief 构造 UDP 帧
     */
    [[nodiscard]] inline auto build_udp(const udp_frame_input &in) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        build_udp(in, out);
        return out;
    }

    /**
     * @brief 解析帧（增量）
     * @param data 输入
     * @param out 输出消息
     * @param consumed 输出消耗字节数
     * @return 错误码
     */
    [[nodiscard]] inline auto parse(std::span<const std::uint8_t> data, message &out, std::size_t &consumed)
        -> error
    {
        if (data.size() < 1)
        {
            return error::need_more;
        }
        out.type = static_cast<message::kind>(data[0]);
        std::size_t off = 1;
        if (out.type == message::kind::udp)
        {
            if (data.size() < off + 8)
            {
                return error::need_more;
            }
            out.session_id = static_cast<std::uint32_t>(data[off]) |
                             static_cast<std::uint32_t>(data[off + 1]) << 8 |
                             static_cast<std::uint32_t>(data[off + 2]) << 16 |
                             static_cast<std::uint32_t>(data[off + 3]) << 24;
            out.packet_id = static_cast<std::uint32_t>(data[off + 4]) |
                            static_cast<std::uint32_t>(data[off + 5]) << 8 |
                            static_cast<std::uint32_t>(data[off + 6]) << 16 |
                            static_cast<std::uint32_t>(data[off + 7]) << 24;
            off += 8;
        }
        std::size_t addr_consumed = 0;
        const auto ec = parse_address(data.subspan(off), out.dst, addr_consumed);
        if (ec != error::none)
        {
            return ec;
        }
        off += addr_consumed;
        out.payload.assign(reinterpret_cast<const char *>(data.data() + off), data.size() - off);
        consumed = data.size();
        return error::none;
    }

    // ==================== auth（认证请求）合并 ====================

    /**
     * @brief 认证请求（HTTP/3 HEADERS 帧，首字节 0x01）
     * @param password 认证密码
     * @return 认证请求字节
     */
    [[nodiscard]] inline auto make_auth_request(std::string_view password) -> std::string
    {
        // QUIC HEADERS 帧：[Type 0x01][Length varint][HTTP/3 头块]
        // 简化头块：:method POST、:path /auth、authorization: <password>
        std::string payload = "POST /auth HTTP/1.1\r\n";
        payload += "Host: hysteria2\r\n";
        payload += "Authorization: " + std::string(password) + "\r\n";
        payload += "\r\n";
        std::string out;
        out.push_back(static_cast<char>(0x01));           // HEADERS 帧类型
        out.push_back(static_cast<char>(payload.size())); // 长度（简化 1 字节）
        out += payload;
        return out;
    }
    // ==================== session.hpp（serializer/parser）合并 ====================

    /**
     * @brief Hysteria2 帧序列化器（对象 → wire）
     */
    class serializer
    {
    public:
        /**
         * @brief 重置并绑定消息
         * @param msg 待序列化消息
         */
        auto reset(const message &msg) -> void
        {
            if (msg.type == message::kind::udp)
            {
                wire_ = build_udp(udp_frame_input{
                    msg.session_id, msg.packet_id, &msg.dst,
                    std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(msg.payload.data()),
                                                  msg.payload.size())});
            }
            else
            {
                wire_ = build_tcp(msg.dst, std::span<const std::uint8_t>(
                                               reinterpret_cast<const std::uint8_t *>(msg.payload.data()),
                                               msg.payload.size()));
            }
            offset_ = 0;
        }

        /**
         * @brief 增量输出 wire 字节
         * @param buffer 输出缓冲
         * @param ec 输出错误码
         * @return 本次写入字节数
         */
        auto get(boost::asio::mutable_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto space = buffer.size();
            const auto remain = wire_.size() - offset_;
            const auto n = std::min(space, remain);
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

        /**
         * @brief 剩余未输出字节数
         * @return 剩余未输出字节数
         */
        [[nodiscard]] auto remaining() const -> std::size_t
        {
            return wire_.size() - offset_;
        }

    private:
        std::vector<std::uint8_t> wire_;
        std::size_t offset_{0};
    };

    /**
     * @brief Hysteria2 帧解析器（wire → 对象）
     */
    class parser
    {
    public:
        /**
         * @brief 增量喂入 wire 字节
         * @param buffer 输入缓冲
         * @param ec 输出错误码
         * @return 本次消耗字节数
         */
        auto put(boost::asio::const_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(buffer.data()),
                                                            buffer.size());
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

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto is_done() const -> bool
        {
            return done_;
        }

        /**
         * @brief 解析结果（done 后有效）
         * @return 消息引用（done 后有效）
         */
        [[nodiscard]] auto get() const -> const message &
        {
            return msg_;
        }

        /**
         * @brief 重置解析器
         */
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

} // namespace psmtest::hysteria2
