/**
 * @file codec.hpp
 * @brief HTTP CONNECT 消息编解码（纯函数 + serializer/parser 类）
 * @details 实现：
 *          - build_connect() / parse_connect()：CONNECT 请求编解码
 *          - find_crlf()：增量查找行尾
 *          - parse_status_line()：解析响应状态行
 *          - message / serializer / parser 类（Beast 风格）
 * @note 参考 RFC 7230 / RFC 7231。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/http/types.hpp>

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace psmtest::http
{

    /// @brief 在缓冲区中查找 CRLF
    /// @param data 输入
    /// @return CRLF 位置（不含）；未找到返回 npos
    [[nodiscard]] inline auto find_crlf(std::span<const std::uint8_t> data) -> std::size_t
    {
        for (std::size_t i = 0; i + 1 < data.size(); ++i)
        {
            if (data[i] == '\r' && data[i + 1] == '\n')
                return i;
        }
        return std::string_view::npos;
    }

    /// @brief 构造 CONNECT 请求
    /// @param target 目标地址
    /// @return 请求字节（含 CRLF）
    [[nodiscard]] inline auto build_connect(const address &target) -> std::vector<std::uint8_t>
    {
        std::string req = "CONNECT " + target.host + ":" + std::to_string(target.port) +
                          " HTTP/1.1\r\nHost: " + target.host + ":" + std::to_string(target.port) +
                          "\r\n\r\n";
        return {req.begin(), req.end()};
    }

    /// @brief 解析 CONNECT 请求（请求行 + Host 头）
    /// @param data 完整请求（含头部）
    /// @param target 输出目标地址
    /// @return 错误码；need_more = 数据不足
    [[nodiscard]] inline auto parse_connect(std::span<const std::uint8_t> data,
                                            address &target) -> error
    {
        const auto line_end = find_crlf(data);
        if (line_end == std::string_view::npos)
            return error::need_more;
        const std::string_view line(reinterpret_cast<const char *>(data.data()), line_end);

        if (!line.starts_with(connect_method))
            return error::bad_message;
        const auto sp1 = line.find(' ', connect_method.size());
        if (sp1 == std::string_view::npos)
            return error::bad_message;
        const auto sp2 = line.find(' ', sp1 + 1);
        if (sp2 == std::string_view::npos)
            return error::bad_message;
        const std::string_view authority = line.substr(sp1 + 1, sp2 - sp1 - 1);

        const auto colon = authority.rfind(':');
        if (colon == std::string_view::npos)
            return error::bad_message;
        target.host = std::string(authority.substr(0, colon));
        const auto port_str = authority.substr(colon + 1);
        char *end = nullptr;
        const auto port = std::strtoul(std::string(port_str).c_str(), &end, 10);
        if (end == nullptr || *end != '\0' || port > 65535)
            return error::bad_message;
        target.port = static_cast<std::uint16_t>(port);
        return error::none;
    }

    /// @brief 解析响应状态行（HTTP/1.1 xxx ...）
    /// @param data 输入
    /// @return 状态码（负值 = 失败/不足）
    [[nodiscard]] inline auto parse_status_line(std::span<const std::uint8_t> data) -> int
    {
        const auto line_end = find_crlf(data);
        if (line_end == std::string_view::npos)
            return -1;
        const std::string_view line(reinterpret_cast<const char *>(data.data()), line_end);
        if (!line.starts_with("HTTP/1.1 ") && !line.starts_with("HTTP/1.0 "))
            return -2;
        const auto sp = line.find(' ', 8);
        if (sp == std::string_view::npos)
            return -2;
        char *end = nullptr;
        const auto code = std::strtol(std::string(line.substr(sp + 1, 3)).c_str(), &end, 10);
        return code > 0 ? static_cast<int>(code) : -2;
    }

    /// @brief HTTP 消息（Beast 风格，供 serializer/parser 使用）
    struct message
    {
        /// 消息类型
        enum class kind : std::uint8_t
        {
            /// 请求（CONNECT）
            request,
            /// 响应
            response,
        };

        /// 消息类型
        kind type{kind::request};
        /// 目标主机（request）
        std::string host;
        /// 目标端口（request）
        std::uint16_t port{0};
        /// 状态码（response）
        int status{0};
    };

    /// @brief HTTP 消息序列化器（对象 → wire，Beast 风格）
    class serializer
    {
    public:
        /// @brief 重置并绑定消息
        /// @param msg 消息
        auto reset(const message &msg) -> void
        {
            wire_.clear();
            offset_ = 0;
            if (msg.type == message::kind::request)
            {
                const address target{msg.host, msg.port};
                wire_ = build_connect(target);
            }
            else
            {
                const std::string resp = "HTTP/1.1 " + std::to_string(msg.status) + "\r\n\r\n";
                wire_.assign(resp.begin(), resp.end());
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

    /// @brief HTTP 消息解析器（wire → 对象，Beast 风格）
    class parser
    {
    public:
        /// @brief 设置期望的消息类型
        /// @param kind 消息类型（request/response）
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
            buf_.insert(buf_.end(), data.begin(), data.end());

            if (expect_ == message::kind::request)
            {
                // 头部需以 CRLFCRLF 结束（请求行 + 头字段）
                const auto first = find_crlf(buf_);
                if (first == std::string_view::npos ||
                    find_crlf(std::span<const std::uint8_t>(buf_.data() + first + 2,
                                                            buf_.size() - first - 2)) == std::string_view::npos)
                {
                    return 0; // 半帧：ec 保持空，等待更多数据
                }
                address target;
                const auto err = parse_connect(buf_, target);
                if (err == error::need_more)
                {
                    return 0; // 半帧：ec 保持空
                }
                if (err != error::none)
                {
                    ec = make_error_code(err);
                    return 0;
                }
                msg_.type = message::kind::request;
                msg_.host = target.host;
                msg_.port = target.port;
            }
            else
            {
                const auto status = parse_status_line(buf_);
                if (status < 0)
                {
                    ec = make_error_code(status == -1 ? error::need_more : error::bad_message);
                    return 0;
                }
                msg_.type = message::kind::response;
                msg_.status = status;
            }
            done_ = true;
            return buf_.size();
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
        message::kind expect_{message::kind::request};
        std::vector<std::uint8_t> buf_;
        message msg_{};
        bool done_{false};
    };

} // namespace psmtest::http
