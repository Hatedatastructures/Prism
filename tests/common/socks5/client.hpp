/**
 * @file client.hpp
 * @brief SOCKS5 客户端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 客户端模式：connect() 完成完整握手：
 *          1. 发送 greeting（版本 + 方法列表）
 *          2. 读取方法选择
 *          3. 发送 CONNECT 请求（命令 + 地址）
 *          4. 读取响应（校验成功码）
 *          5. 返回透传会话
 * @note 参考 RFC 1928。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/session_base.hpp>
#include <common/core/transport/transport_base.hpp>
#include <common/socks5/codec.hpp>
#include <common/socks5/session.hpp>
#include <common/socks5/types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace psmtest::socks5
{

    /// SOCKS5 客户端配置
    struct client_config
    {
        /// 用户名（user_pass 认证时）
        std::string username;
        /// 密码（user_pass 认证时）
        std::string password;
        /// 会话读超时
        std::chrono::milliseconds timeout{0};
    };

    /// @brief SOCKS5 客户端
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

        /// @brief 建立连接并完成 SOCKS5 握手
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

            // 1. greeting
            greeting g;
            g.ver = version;
            g.methods = cfg_.username.empty()
                            ? std::vector<std::uint8_t>{static_cast<std::uint8_t>(auth_method::no_auth)}
                            : std::vector<std::uint8_t>{static_cast<std::uint8_t>(auth_method::user_pass)};
            auto ec = co_await raw->write_all(build_greeting(g));
            if (ec)
                co_return nullptr;

            // 2. 方法选择
            std::array<std::uint8_t, 2> mreply{};
            std::size_t done = 0;
            while (done < mreply.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(mreply.data() + done, mreply.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            method_reply mr;
            if (parse_method_reply(mreply, mr) != error::none)
                co_return nullptr;
            if (mr.method == auth_method::no_acceptable)
                co_return nullptr;

            // 3. user_pass 认证（如需）
            if (mr.method == auth_method::user_pass)
            {
                const auto auth_req = build_userpass(cfg_.username, cfg_.password);
                ec = co_await raw->write_all(auth_req);
                if (ec)
                    co_return nullptr;
                std::array<std::uint8_t, 2> auth_reply{};
                done = 0;
                while (done < auth_reply.size())
                {
                    const auto n = co_await raw->read_some(
                        std::span<std::uint8_t>(auth_reply.data() + done, auth_reply.size() - done));
                    if (n == 0)
                        co_return nullptr;
                    done += n;
                }
                if (parse_userpass_reply(auth_reply) != error::none)
                    co_return nullptr;
            }

            // 4. CONNECT 请求
            request req;
            req.ver = version;
            req.cmd = command::connect;
            req.target = target;
            ec = co_await raw->write_all(build_request(req));
            if (ec)
                co_return nullptr;

            // 5. 响应（先读 4 字节头，再读地址）
            std::array<std::uint8_t, 4> rhead{};
            done = 0;
            while (done < rhead.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(rhead.data() + done, rhead.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            if (rhead[0] != version)
                co_return nullptr;
            if (rhead[1] != static_cast<std::uint8_t>(reply_code::success))
                co_return nullptr;
            // 跳过绑定地址
            const auto atyp = rhead[3];
            std::size_t addr_len = 0;
            if (atyp == static_cast<std::uint8_t>(address_type::ipv4))
                addr_len = 4;
            else if (atyp == static_cast<std::uint8_t>(address_type::ipv6))
                addr_len = 16;
            else if (atyp == static_cast<std::uint8_t>(address_type::domain))
            {
                std::array<std::uint8_t, 1> len_byte{};
                done = 0;
                while (done < len_byte.size())
                {
                    const auto n = co_await raw->read_some(
                        std::span<std::uint8_t>(len_byte.data() + done, len_byte.size() - done));
                    if (n == 0)
                        co_return nullptr;
                    done += n;
                }
                addr_len = len_byte[0];
            }
            else
                co_return nullptr;
            std::vector<std::uint8_t> addr_rest(addr_len + 2);
            done = 0;
            while (done < addr_rest.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(addr_rest.data() + done, addr_rest.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }

            co_return std::make_shared<session>(std::move(raw));
        }

    private:
        client_config cfg_;
        net::any_io_executor ex_;
    };

} // namespace psmtest::socks5
