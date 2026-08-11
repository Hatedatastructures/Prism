/**
 * @file codec.hpp
 * @brief Trojan 头部编解码（纯函数，零状态）
 * @details 实现：
 *          - credential()：SHA224(password) 的 56 字符 hex
 *          - build_request() / parse_request()：请求头编解码
 *          - parse_crlf()：CRLF 校验
 * @note 请求头：[SHA224 56B][CRLF][CMD][ATYP][ADDR][PORT 2B][CRLF]
 */

#pragma once

#include <common/core/error.hpp>
#include <common/trojan/types.hpp>

#include <boost/asio/buffer.hpp>

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace psmtest::trojan
{

    namespace detail
    {

        /// SHA-224 摘要
        [[nodiscard]] inline auto sha224(std::span<const std::uint8_t> data)
            -> std::array<std::uint8_t, 28>
        {
            std::array<std::uint8_t, 28> out{};
            unsigned int len = 0;
            EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha224(), nullptr);
            return out;
        }

    } // namespace detail

    /// @brief 计算密码凭据（SHA224 hex 56 字符）
    /// @param password 密码
    /// @return 56 字符 hex 凭据
    [[nodiscard]] inline auto credential(std::string_view password) -> std::string
    {
        const auto hash = detail::sha224(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(password.data()),
                                          password.size()));
        std::string out;
        out.reserve(credential_len);
        static constexpr char hex[] = "0123456789abcdef";
        for (const auto b : hash)
        {
            out.push_back(hex[(b >> 4) & 0x0F]);
            out.push_back(hex[b & 0x0F]);
        }
        return out;
    }

    /// @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE）
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

    /// @brief 构造完整请求头（凭据 + CRLF + 命令地址 + CRLF）
    /// @param cred 56 字符凭据
    /// @param cmd 命令
    /// @param target 目标地址
    /// @return 请求头字节
    [[nodiscard]] inline auto build_request(std::string_view cred, command cmd,
                                            const address &target) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(credential_len + 2 + 1 + target.host.size() + 2 + 2);
        out.insert(out.end(), cred.begin(), cred.end());
        out.push_back('\r');
        out.push_back('\n');
        out.push_back(static_cast<std::uint8_t>(cmd));
        const auto addr = encode_address(target);
        out.insert(out.end(), addr.begin(), addr.end());
        out.push_back('\r');
        out.push_back('\n');
        return out;
    }

    /// @brief 解析 Trojan 请求头（增量）
    /// @param data 输入数据
    /// @param out 输出请求头
    /// @param consumed 输出消耗字节数
    /// @return 错误码；need_more = 数据不足
    [[nodiscard]] inline auto parse_request(std::span<const std::uint8_t> data,
                                            request_header &out, std::size_t &consumed) -> error
    {
        // 凭据 + CRLF = 58 字节
        if (data.size() < credential_len + 2)
            return error::need_more;
        if (data[credential_len] != '\r' || data[credential_len + 1] != '\n')
            return error::bad_magic;
        std::size_t off = credential_len + 2;
        if (data.size() < off + 2)
            return error::need_more;
        out.cmd = static_cast<command>(data[off++]);
        out.target.type = static_cast<address_type>(data[off++]);
        switch (out.target.type)
        {
            case address_type::ipv4:
            {
                if (data.size() < off + 4 + 2)
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
                if (data.size() < off + 16 + 2)
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
                if (data.size() < off + len + 2)
                    return error::need_more;
                out.target.host.assign(reinterpret_cast<const char *>(data.data() + off), len);
                off += len;
                break;
            }
        }
        out.target.port = static_cast<std::uint16_t>(data[off]) << 8 | data[off + 1];
        off += 2;
        if (data.size() < off + 2)
            return error::need_more;
        if (data[off] != '\r' || data[off + 1] != '\n')
            return error::bad_message;
        consumed = off + 2;
        return error::none;
    }

    /// @brief Trojan 帧消息（Beast 风格，供 serializer/parser 使用）
    struct message
    {
        /// 目标地址
        address dst;
        /// UDP 模式
        bool udp{false};
        /// 解析有效
        bool valid{false};
    };

    /// @brief Trojan 帧序列化器（对象 → wire，Beast 风格）
    class serializer
    {
    public:
        /// @brief 构造
        /// @param password 密码
        explicit serializer(std::string_view password)
            : cred_(credential(password))
        {
        }

        /// @brief 重置并绑定消息
        /// @param msg 消息
        auto reset(const message &msg) -> void
        {
            wire_ = build_request(cred_, msg.udp ? command::udp_associate : command::connect, msg.dst);
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
        std::string cred_;
        std::vector<std::uint8_t> wire_;
        std::size_t offset_{0};
    };

    /// @brief Trojan 帧解析器（wire → 对象，Beast 风格）
    class parser
    {
    public:
        /// @brief 构造
        /// @param password 密码
        explicit parser(std::string_view password)
            : cred_(credential(password))
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
            // 凭据校验（前 56 字节）
            if (buf_.size() < credential_len ||
                std::memcmp(buf_.data(), cred_.data(), credential_len) != 0)
            {
                ec = make_error_code(error::auth_failed);
                return 0;
            }
            msg_.dst = req.target;
            msg_.udp = req.cmd == command::udp_associate;
            msg_.valid = true;
            valid_ = true;
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
            valid_ = false;
            done_ = false;
        }

    private:
        std::string cred_;
        std::vector<std::uint8_t> buf_;
        message msg_{};
        bool valid_{false};
        bool done_{false};
    };
} // namespace psmtest::trojan