/**
 * @file client.hpp
 * @brief Trojan 客户端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 客户端模式：connect() 完成握手：
 *          1. 计算密码凭据（SHA224 hex）
 *          2. 构造请求头（凭据 + CRLF + CONNECT + 地址 + CRLF）
 *          3. 发送
 *          4. 返回透传会话
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/session_base.hpp>
#include <common/core/transport/transport_base.hpp>
#include <common/trojan/codec.hpp>
#include <common/trojan/session.hpp>
#include <common/trojan/types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <span>

namespace psmtest::trojan
{

    /// Trojan 客户端配置
    struct client_config
    {
        /// 密码
        std::string password;
        /// 会话读超时
        std::chrono::milliseconds timeout{0};
    };

    /// @brief Trojan 客户端
    class client
    {
    public:
        /// @brief 构造
        /// @param cfg 客户端配置
        explicit client(const client_config &cfg)
            : cfg_(cfg), cred_(credential(cfg.password))
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

        /// @brief 建立连接并完成 Trojan 握手
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

            const auto request = build_request(cred_, command::connect, target);
            const auto ec = co_await raw->write_all(request);
            if (ec)
                co_return nullptr;

            co_return std::make_shared<session>(std::move(raw));
        }

    private:
        client_config cfg_;
        std::string cred_;
        net::any_io_executor ex_;
    };

} // namespace psmtest::trojan
