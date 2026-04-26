/**
 * @file probe.hpp
 * @brief 外层协议探测
 * @details 从传输层预读数据检测协议类型（HTTP/SOCKS5/TLS/Shadowsocks）。
 * 迁移自 protocol/probe.hpp，职责下沉到 recognition 模块。
 */

#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <string_view>
#include <boost/asio.hpp>
#include <prism/fault/code.hpp>
#include <prism/fault/handling.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/channel/transport/transmission.hpp>
#include <prism/memory/container.hpp>
#include <prism/recognition/probe/analyzer.hpp>

namespace psm::recognition::probe
{
    namespace net = boost::asio;

    /**
     * @struct probe_result
     * @brief 外层协议探测结果
     */
    struct probe_result
    {
        /** @brief 检测到的协议类型 */
        protocol::protocol_type type{protocol::protocol_type::unknown};
        /** @brief 预读数据缓冲区（最大 32 字节） */
        std::array<std::byte, 32> pre_read_data{};
        /** @brief 实际预读数据大小 */
        std::size_t pre_read_size{0};
        /** @brief 错误代码 */
        fault::code ec{fault::code::success};

        /**
         * @brief 检测是否成功
         */
        auto success() const noexcept -> bool
        {
            return ec == fault::code::success && type != protocol::protocol_type::unknown;
        }

        /**
         * @brief 获取预读数据的字符串视图
         */
        auto preload_view() const noexcept -> std::string_view
        {
            return std::string_view(reinterpret_cast<const char *>(pre_read_data.data()), pre_read_size);
        }

        /**
         * @brief 获取预读数据的字节视图
         */
        auto preload_bytes() const noexcept -> std::span<const std::byte>
        {
            return std::span<const std::byte>(pre_read_data.data(), pre_read_size);
        }
    };

    /**
     * @brief 外层协议探测
     * @param transport 传输层对象
     * @param max_peek_size 最大预读字节数（默认 24）
     * @return 探测结果
     * @details 预读数据并调用 detect() 检测协议类型
     */
    inline auto probe(channel::transport::transmission &transport, std::size_t max_peek_size = 24)
        -> net::awaitable<probe_result>
    {
        probe_result result;

        const std::size_t peek_size = (std::min)(max_peek_size, result.pre_read_data.size());
        auto span = std::span<std::byte>(result.pre_read_data.data(), peek_size);

        std::error_code sys_ec;
        std::size_t n = co_await transport.async_read_some(span, sys_ec);
        if (sys_ec)
        {
            result.ec = fault::to_code(sys_ec);
            co_return result;
        }
        if (n == 0)
        {
            result.ec = fault::code::eof;
            co_return result;
        }

        std::string_view peek_view(reinterpret_cast<const char *>(result.pre_read_data.data()), n);
        result.type = probe::detect(peek_view);

        result.pre_read_size = n;
        result.ec = fault::code::success;

        co_return result;
    }
} // namespace psm::recognition::probe