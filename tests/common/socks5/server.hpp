/**
 * @file server.hpp
 * @brief SOCKS5 服务端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 服务端模式：accept() 完成握手：
 *          1. 读取并解析 greeting
 *          2. 选择方法（no_auth / user_pass）
 *          3. 读取并解析 CONNECT 请求
 *          4. 发送成功响应
 *          5. 返回透传会话
 * @note 参考 RFC 1928。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/session_base.hpp>
#include <common/core/transport/transport_base.hpp>
#include <common/socks5/codec.hpp>
#include <common/socks5/types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace psmtest::socks5
{

    /// SOCKS5 服务端配置
    struct server_config
    {
        /// 要求用户名/密码认证
        bool require_auth{false};
        /// 用户名
        std::string username;
        /// 密码
        std::string password;
        /// 会话读超时
        std::chrono::milliseconds timeout{0};
    };

    /// @brief SOCKS5 服务端
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

        /// @brief 接收连接并完成 SOCKS5 握手
        /// @param raw 底层传输
        /// @param target 输出参数：客户端请求的目标地址
        /// @param timeout 握手超时
        /// @return 数据会话；nullptr = 握手失败
        auto accept(std::shared_ptr<transport_base> raw, address &target,
                    std::chrono::milliseconds timeout = std::chrono::milliseconds{5000})
            -> net::awaitable<std::shared_ptr<session>>
        {
            if (!raw || !raw->is_open())
                co_return nullptr;
            ex_ = raw->executor();
            if (timeout.count() > 0)
                raw->set_timeout(timeout);

            // 1. 读取 greeting（2 字节头 + 方法列表）
            std::array<std::uint8_t, 2> ghead{};
            std::size_t done = 0;
            while (done < ghead.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(ghead.data() + done, ghead.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            if (ghead[0] != version)
                co_return nullptr;
            std::vector<std::uint8_t> methods(ghead[1]);
            done = 0;
            while (done < methods.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(methods.data() + done, methods.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }

            // 2. 方法选择
            auth_method chosen = auth_method::no_acceptable;
            const auto want = cfg_.require_auth ? auth_method::user_pass : auth_method::no_auth;
            for (const auto m : methods)
            {
                if (static_cast<auth_method>(m) == want)
                {
                    chosen = static_cast<auth_method>(m);
                    break;
                }
            }
            method_reply mr;
            mr.ver = version;
            mr.method = chosen;
            auto ec = co_await raw->write_all(build_method_reply(mr));
            if (ec)
                co_return nullptr;
            if (chosen == auth_method::no_acceptable)
                co_return nullptr;

            // 3. user_pass 认证
            if (chosen == auth_method::user_pass)
            {
                // 读取：版本 + 用户长度 + 用户 + 密码长度 + 密码
                std::array<std::uint8_t, 2> ahead{};
                done = 0;
                while (done < ahead.size())
                {
                    const auto n = co_await raw->read_some(
                        std::span<std::uint8_t>(ahead.data() + done, ahead.size() - done));
                    if (n == 0)
                        co_return nullptr;
                    done += n;
                }
                if (ahead[0] != 0x01)
                    co_return nullptr;
                std::vector<std::uint8_t> user(ahead[1]);
                done = 0;
                while (done < user.size())
                {
                    const auto n = co_await raw->read_some(
                        std::span<std::uint8_t>(user.data() + done, user.size() - done));
                    if (n == 0)
                        co_return nullptr;
                    done += n;
                }
                std::array<std::uint8_t, 1> plen{};
                done = 0;
                while (done < plen.size())
                {
                    const auto n = co_await raw->read_some(
                        std::span<std::uint8_t>(plen.data() + done, plen.size() - done));
                    if (n == 0)
                        co_return nullptr;
                    done += n;
                }
                std::vector<std::uint8_t> pass(plen[0]);
                done = 0;
                while (done < pass.size())
                {
                    const auto n = co_await raw->read_some(
                        std::span<std::uint8_t>(pass.data() + done, pass.size() - done));
                    if (n == 0)
                        co_return nullptr;
                    done += n;
                }
                const bool auth_ok = std::string(user.begin(), user.end()) == cfg_.username &&
                                     std::string(pass.begin(), pass.end()) == cfg_.password;
                const std::array<std::uint8_t, 2> auth_resp{
                    0x01, static_cast<std::uint8_t>(auth_ok ? 0x00 : 0x01)};
                ec = co_await raw->write_all(auth_resp);
                if (ec)
                    co_return nullptr;
                if (!auth_ok)
                    co_return nullptr;
            }

            // 4. 读取请求（4 字节头 + 地址）
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
            const auto cmd = static_cast<command>(rhead[1]);
            if (cmd != command::connect)
                co_return nullptr;
            target.type = static_cast<address_type>(rhead[3]);

            // 5. 读取地址体
            std::vector<std::uint8_t> addr_body;
            switch (target.type)
            {
                case address_type::ipv4:
                {
                    std::array<std::uint8_t, 4> ip{};
                    done = 0;
                    while (done < ip.size())
                    {
                        const auto n = co_await raw->read_some(
                            std::span<std::uint8_t>(ip.data() + done, ip.size() - done));
                        if (n == 0)
                            co_return nullptr;
                        done += n;
                    }
                    std::array<char, 16> buf{};
                    std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u",
                                  ip[0], ip[1], ip[2], ip[3]);
                    target.host = buf.data();
                    break;
                }
                case address_type::ipv6:
                {
                    addr_body.resize(16);
                    done = 0;
                    while (done < addr_body.size())
                    {
                        const auto n = co_await raw->read_some(
                            std::span<std::uint8_t>(addr_body.data() + done, addr_body.size() - done));
                        if (n == 0)
                            co_return nullptr;
                        done += n;
                    }
                    target.host.assign(reinterpret_cast<const char *>(addr_body.data()), 16);
                    break;
                }
                case address_type::domain:
                default:
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
                    addr_body.resize(len_byte[0]);
                    done = 0;
                    while (done < addr_body.size())
                    {
                        const auto n = co_await raw->read_some(
                            std::span<std::uint8_t>(addr_body.data() + done, addr_body.size() - done));
                        if (n == 0)
                            co_return nullptr;
                        done += n;
                    }
                    target.host.assign(reinterpret_cast<const char *>(addr_body.data()), addr_body.size());
                    break;
                }
            }
            // 端口
            std::array<std::uint8_t, 2> port_bytes{};
            done = 0;
            while (done < port_bytes.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(port_bytes.data() + done, port_bytes.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            target.port = static_cast<std::uint16_t>(port_bytes[0]) << 8 | port_bytes[1];

            // 6. 发送成功响应（绑定地址 = 0.0.0.0:0）
            reply rep;
            rep.ver = version;
            rep.code = reply_code::success;
            rep.bind.type = address_type::ipv4;
            rep.bind.host = "0.0.0.0";
            rep.bind.port = 0;
            ec = co_await raw->write_all(build_reply(rep));
            if (ec)
                co_return nullptr;

            co_return std::make_shared<session>(std::move(raw));
        }

    private:
        server_config cfg_;
        net::any_io_executor ex_;
    };

} // namespace psmtest::socks5
