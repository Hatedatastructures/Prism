/**
 * @file client.hpp
 * @brief HTTP 代理客户端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 客户端模式：connect() 完成握手：
 *          1. 构造 CONNECT 请求（目标 host:port）
 *          2. 发送
 *          3. 读取响应状态行（校验 200）
 *          4. 返回透传会话
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

#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace psmtest::http
{

    /// HTTP 客户端配置
    struct client_config
    {
        /// 会话读超时
        std::chrono::milliseconds timeout{0};
    };

    /// @brief HTTP 代理客户端
    class client
    {
    public:
        /// @brief 构造
        /// @param cfg 客户端配置
        explicit client(const client_config &cfg = {})
            : cfg_(cfg)
        {
        }

        /// 不可拷贝
        client(const client &) = delete;
        auto operator=(const client &) -> client & = delete;

        /// 获取执行器（连接后有效）
        [[nodiscard]] auto executor() const -> net::any_io_executor
        {
            return ex_;
        }

        /// @brief 建立连接并完成 CONNECT 握手
        /// @param raw 底层传输
        /// @param target 目标地址
        /// @param timeout 握手超时
        /// @return 数据会话；nullptr = 握手失败
        auto connect(std::shared_ptr<transport_base> raw, const address &target,
                     std::chrono::milliseconds timeout = std::chrono::milliseconds{5000})
            -> net::awaitable<std::shared_ptr<session>>
        {
            if (!raw || !raw->is_open())
                co_return nullptr;
            ex_ = raw->executor();
            if (timeout.count() > 0)
                raw->set_timeout(timeout);

            // 1. 发送 CONNECT 请求
            const auto request = build_connect(target);
            const auto ec = co_await raw->write_all(request);
            if (ec)
                co_return nullptr;

            // 2. 读取响应状态行（直到 CRLFCRLF 或至少一行）
            std::vector<std::uint8_t> buf;
            buf.reserve(256);
            while (true)
            {
                std::array<std::uint8_t, 64> chunk{};
                const auto n = co_await raw->read_some(chunk);
                if (n == 0)
                    co_return nullptr;
                buf.insert(buf.end(), chunk.begin(), chunk.begin() + n);
                const auto status = parse_status_line(buf);
                if (status > 0)
                {
                    if (status != status_ok)
                        co_return nullptr;
                    break;
                }
                if (buf.size() > 4096)
                    co_return nullptr;
            }

            co_return std::make_shared<session>(std::move(raw));
        }

    private:
        client_config cfg_;
        net::any_io_executor ex_;
    };

} // namespace psmtest::http
