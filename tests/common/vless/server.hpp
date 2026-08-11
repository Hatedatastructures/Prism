/**
 * @file server.hpp
 * @brief VLESS 服务端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 服务端模式：accept() 完成握手：
 *          1. 读取并解析请求头（版本校验 + UUID 校验 + 命令）
 *          2. 发送 2 字节响应
 *          3. 返回透传会话
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

#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

namespace psmtest::vless
{

    /// VLESS 服务端配置
    struct server_config
    {
        /// 16 字节 UUID
        std::array<std::uint8_t, uuid_len> uuid{};
        /// 会话读超时
        std::chrono::milliseconds timeout{0};
    };

    /// @brief VLESS 服务端
    class server
    {
    public:
        /// @brief 构造
        /// @param cfg 服务端配置
        explicit server(const server_config &cfg)
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

        /// @brief 接收连接并完成 VLESS 握手
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

            // 1. 读取请求头前缀（版本 + UUID + AddnlLen = 18 字节）
            std::array<std::uint8_t, 18> prefix{};
            std::size_t done = 0;
            while (done < prefix.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(prefix.data() + done, prefix.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }
            if (prefix[0] != protocol_version)
                co_return nullptr;

            // 2. 读取 addons
            const auto addnl_len = prefix[17];
            std::vector<std::uint8_t> addons(addnl_len);
            done = 0;
            while (done < addons.size())
            {
                const auto n = co_await raw->read_some(
                    std::span<std::uint8_t>(addons.data() + done, addons.size() - done));
                if (n == 0)
                    co_return nullptr;
                done += n;
            }

            // 3. 读取地址（cmd + port + atyp + addr）
            std::array<std::uint8_t, 4> addr_prefix{};
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
            if (cmd != command::tcp && cmd != command::udp)
                co_return nullptr;
            target.port = static_cast<std::uint16_t>(addr_prefix[1]) << 8 | addr_prefix[2];
            target.type = static_cast<address_type>(addr_prefix[3]);

            // 4. 读取地址体
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

            // 5. UUID 校验（客户端的 UUID 在 prefix 1..17）
            if (std::memcmp(prefix.data() + 1, cfg_.uuid.data(), uuid_len) != 0)
                co_return nullptr;

            // 6. 发送响应
            const auto resp = make_response();
            const auto ec = co_await raw->write_all(resp);
            if (ec)
                co_return nullptr;

            co_return std::make_shared<session>(std::move(raw));
        }

    private:
        server_config cfg_;
        net::any_io_executor ex_;
    };

} // namespace psmtest::vless
