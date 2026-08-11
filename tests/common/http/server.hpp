/**
 * @file server.hpp
 * @brief HTTP 代理服务端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 服务端模式：accept() 完成握手：
 *          1. 增量读取 CONNECT 请求（flat_buffer + CRLF 扫描）
 *          2. 解析目标地址
 *          3. 发送 200 响应
 *          4. 返回透传会话（剩余缓冲数据前移）
 * @note 参考 RFC 7231 CONNECT 方法。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/session_base.hpp>
#include <common/core/transport/transport_base.hpp>
#include <common/http/codec.hpp>
#include <common/http/session.hpp>
#include <common/http/types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace psmtest::http
{

    /// HTTP 服务端配置
    struct server_config
    {
        /// 会话读超时
        std::chrono::milliseconds timeout{0};
    };

    /// @brief HTTP 代理服务端
    class server
    {
    public:
        /// @brief 构造
        /// @param cfg 服务端配置
        explicit server(const server_config &cfg = {})
            : cfg_(cfg)
        {
        }

        /// 不可拷贝
        server(const server &) = delete;
        auto operator=(const server &) -> server & = delete;

        /// 获取执行器（accept 后有效）
        [[nodiscard]] auto executor() const -> net::any_io_executor
        {
            return ex_;
        }

        /// @brief 接收连接并完成 CONNECT 握手
        /// @param raw 底层传输
        /// @param target 输出参数：客户端请求的目标地址
        /// @param timeout 握手超时
        /// @return 数据会话；nullptr = 解析失败
        auto accept(std::shared_ptr<transport_base> raw, address &target,
                    std::chrono::milliseconds timeout = std::chrono::milliseconds{5000})
            -> net::awaitable<std::shared_ptr<session>>
        {
            if (!raw || !raw->is_open())
                co_return nullptr;
            ex_ = raw->executor();
            if (timeout.count() > 0)
                raw->set_timeout(timeout);

            // 1. 增量读取 CONNECT 请求
            std::vector<std::uint8_t> buf;
            buf.reserve(512);
            while (true)
            {
                const auto hdr_end = find_crlf(buf);
                if (hdr_end != std::string_view::npos)
                {
                    // 解析请求行
                    if (parse_connect(buf, target) != error::none)
                        co_return nullptr;
                    break;
                }
                std::array<std::uint8_t, 64> chunk{};
                const auto n = co_await raw->read_some(chunk);
                if (n == 0)
                    co_return nullptr;
                buf.insert(buf.end(), chunk.begin(), chunk.begin() + n);
                if (buf.size() > 4096)
                    co_return nullptr;
            }

            // 2. 发送 200 响应
            const auto resp = std::string(status_line_ok);
            const auto ec = co_await raw->write_all(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(resp.data()), resp.size()));
            if (ec)
                co_return nullptr;

            co_return std::make_shared<session>(std::move(raw));
        }

    private:
        server_config cfg_;
        net::any_io_executor ex_;
    };

} // namespace psmtest::http
