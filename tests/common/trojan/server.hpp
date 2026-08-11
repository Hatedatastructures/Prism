/**
 * @file server.hpp
 * @brief Trojan 服务端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 服务端模式：accept() 完成握手：
 *          1. 读取并解析请求头（凭据校验 + CRLF）
 *          2. 返回透传会话
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
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

namespace psmtest::trojan
{

    /// Trojan 服务端配置
    struct server_config
    {
        /// 密码
        std::string password;
        /// 会话读超时
        std::chrono::milliseconds timeout{0};
    };

    /// @brief Trojan 服务端
    class server
    {
    public:
        /// @brief 构造
        /// @param cfg 服务端配置
        explicit server(const server_config &cfg)
            : cfg_(cfg), cred_(credential(cfg.password))
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

        /// @brief 接收连接并完成 Trojan 握手
        /// @param raw 底层传输
        /// @param target 输出参数：客户端请求的目标地址
        /// @param timeout 握手超时
        /// @return 数据会话；nullptr = 认证失败
        auto accept(std::shared_ptr<transport_base> raw, address &target,
                    std::chrono::milliseconds timeout = std::chrono::milliseconds{5000})
            -> net::awaitable<std::shared_ptr<session>>
        {
            if (!raw || !raw->is_open())
                co_return nullptr;
            ex_ = raw->executor();
            if (timeout.count() > 0)
                raw->set_timeout(timeout);

            // 1. 读取凭据 + CRLF（58 字节）
            std::array<std::uint8_t, credential_len + 2> prefix{};
            std::size_t done = 0;
            while (done < prefix.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(prefix.data() + done, prefix.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            // 凭据校验
            if (std::memcmp(prefix.data(), cred_.data(), credential_len) != 0)
                co_return nullptr;
            if (prefix[credential_len] != '\r' || prefix[credential_len + 1] != '\n')
                co_return nullptr;

            // 2. 读取命令 + 地址类型（2 字节）
            std::array<std::uint8_t, 2> addr_prefix{};
            done = 0;
            while (done < addr_prefix.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(addr_prefix.data() + done, addr_prefix.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            const auto cmd = static_cast<command>(addr_prefix[0]);
            if (cmd != command::connect && cmd != command::udp_associate)
                co_return nullptr;
            target.type = static_cast<address_type>(addr_prefix[1]);

            // 3. 读取地址体 + 端口 + CRLF
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
            // 端口 2 字节
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
            // CRLF
            std::array<std::uint8_t, 2> crlf{};
            done = 0;
            while (done < crlf.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(crlf.data() + done, crlf.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            if (crlf[0] != '\r' || crlf[1] != '\n')
                co_return nullptr;

            co_return std::make_shared<session>(std::move(raw));
        }

    private:
        server_config cfg_;
        std::string cred_;
        net::any_io_executor ex_;
    };

} // namespace psmtest::trojan
