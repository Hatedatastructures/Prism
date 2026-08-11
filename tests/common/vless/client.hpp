/**
 * @file client.hpp
 * @brief VLESS 客户端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 客户端模式：connect() 完成握手：
 *          1. 构造请求头（版本 + UUID + 命令 + 地址）
 *          2. 发送
 *          3. 读取 2 字节响应（校验版本）
 *          4. 返回透传会话
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/session_base.hpp>
#include <common/core/transport/transport_base.hpp>
#include <common/vless/codec.hpp>
#include <common/vless/session.hpp>
#include <common/vless/types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>

namespace psmtest::vless
{

    /// VLESS 客户端配置
    struct client_config
    {
        /// 16 字节 UUID
        std::array<std::uint8_t, uuid_len> uuid{};
        /// 会话读超时
        std::chrono::milliseconds timeout{0};
    };

    /// @brief VLESS 客户端
    class client
    {
    public:
        /// @brief 构造
        /// @param cfg 客户端配置
        explicit client(const client_config &cfg)
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

        /// @brief 建立连接并完成 VLESS 握手
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

            request_header hdr;
            hdr.version = protocol_version;
            hdr.uuid = cfg_.uuid;
            hdr.cmd = command::tcp;
            hdr.target = target;
            const auto request = build_request(hdr);

            const auto ec = co_await raw->write_all(request);
            if (ec)
                co_return nullptr;

            // 读取 2 字节响应
            std::array<std::uint8_t, 2> resp{};
            std::size_t done = 0;
            while (done < resp.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(resp.data() + done, resp.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            if (resp[0] != protocol_version)
                co_return nullptr;

            co_return std::make_shared<session>(std::move(raw));
        }

    private:
        client_config cfg_;
        net::any_io_executor ex_;
    };

} // namespace psmtest::vless
