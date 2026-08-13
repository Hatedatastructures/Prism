/**
 * @file conn.hpp
 * @brief SOCKS5 流连接对象（TCP，实现 transmission）
 * @details 单条 SOCKS5 连接的完整协议状态：
 * - 客户端握手：write_handshake(req)（greeting → 方法选择 → 认证 →
 *   请求 → 响应校验），成功后 bind_endpoint() 可取 BND 地址
 * - 服务端握手：read_handshake(cfg)（greeting → 方法协商 → 认证 →
 *   请求解析 → 响应），返回解析的请求
 * 握手后为纯字节流透传（预读缓冲优先）。UDP 数据面由 dgram.hpp
 * 提供（独立包连接类型，嵌入本连接）。
 * @note 对齐 mihomo transport：TCP = net.Conn（纯流语义）。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/proxy/socks5/codec.hpp>
#include <common/proxy/socks5/types.hpp>

namespace psmtest::socks5
{

    /**
     * @class conn
     * @brief SOCKS5 流连接对象
     * @details 单条连接的协议状态：双端握手、数据透传、预读缓冲、
     * 认证状态。实现 transmission 接口可挂载装饰器链。
     * 由工厂创建，调用方以 shared_ptr 持有。
     */
    class conn : public psmtest::transmission, public std::enable_shared_from_this<conn>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param upstream 上游传输（所有权移交）
         */
        explicit conn(shared_transmission upstream) : next_layer_(std::move(upstream))
        {
        }

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return next_layer_->executor();
        }

        /**
         * @brief 异步读取（预读缓冲优先）
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数
         * @details 握手阶段预读的剩余字节先被消费，清空后透传底层。
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            if (used_ > 0)
            {
                const auto n = std::min(buffer.size(), used_);
                std::memcpy(buffer.data(), buf_.data(), n);
                if (n < used_)
                {
                    std::memmove(buf_.data(), buf_.data() + n, used_ - n);
                }
                else
                {
                    buf_.clear();
                }
                used_ -= n;
                co_return n;
            }
            co_return co_await next_layer_->async_read_some(buffer, ec);
        }

        /**
         * @brief 异步写入（透传）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->async_write_some(buffer, ec);
        }

        /**
         * @brief 关闭传输层
         */
        void close() override
        {
            if (next_layer_)
            {
                next_layer_->close();
            }
        }

        /**
         * @brief 取消挂起操作
         */
        void cancel() override
        {
            if (next_layer_)
            {
                next_layer_->cancel();
            }
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         */
        [[nodiscard]] auto next_layer() noexcept -> psmtest::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         */
        [[nodiscard]] auto next_layer() const noexcept -> const psmtest::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto release() -> shared_transmission override
        {
            return std::move(next_layer_);
        }

        /**
         * @brief 客户端握手：greeting → 方法选择 → 认证 → 请求 → 响应
         * @param req 目标请求（cmd + target）
         * @param enable_auth 是否启用用户名/密码认证（RFC 1929）
         * @param username 认证用户名（enable_auth 为 true 时生效）
         * @param password 认证密码（enable_auth 为 true 时生效）
         * @return 错误码
         * @details 完整客户端流程（RFC 1928 + 1929）。成功后 BND
         * 地址可通过 bind_endpoint() 获取（UDP_ASSOCIATE 用）。
         */
        [[nodiscard]] auto write_handshake(const request &req, const client_config &cfg)
            -> net::awaitable<error>
        {
            const auto &enable_auth = cfg.enable_auth;
            const auto &username = cfg.username;
            const auto &password = cfg.password;
            // 1. 发送 greeting
            greeting g;
            g.ver = version;
            g.methods = enable_auth
                            ? std::vector<std::uint8_t>{static_cast<std::uint8_t>(auth_method::user_pass)}
                            : std::vector<std::uint8_t>{static_cast<std::uint8_t>(auth_method::no_auth)};
            if (co_await send_bytes(build_greeting(g)))
            {
                co_return error::io_error;
            }

            // 2. 读取方法选择
            std::array<std::uint8_t, 2> sel{};
            if (co_await read_exact(std::span<std::uint8_t>(sel)))
            {
                co_return error::io_error;
            }
            if (sel[0] != version)
            {
                co_return error::version_mismatch;
            }
            if (sel[1] == static_cast<std::uint8_t>(auth_method::no_acceptable))
            {
                co_return error::not_supported;
            }

            // 3. 认证（如需，RFC 1929）
            if (sel[1] == static_cast<std::uint8_t>(auth_method::user_pass))
            {
                const auto auth = build_userpass(username, password);
                if (co_await send_bytes(auth))
                {
                    co_return error::io_error;
                }
                std::array<std::uint8_t, 2> resp{};
                if (co_await read_exact(std::span<std::uint8_t>(resp)))
                {
                    co_return error::io_error;
                }
                if (resp[0] != 0x01 || resp[1] != 0x00)
                {
                    co_return error::bad_auth;
                }
            }
            else if (sel[1] != static_cast<std::uint8_t>(auth_method::no_auth) && !enable_auth)
            {
                co_return error::not_supported;
            }

            // 4. 发送请求
            if (co_await send_bytes(build_request(req)))
            {
                co_return error::io_error;
            }

            // 5. 读取响应并校验
            reply rep;
            auto err = co_await read_reply(rep);
            if (err != error::none)
            {
                co_return err;
            }
            if (rep.code != reply_code::success)
            {
                co_return error::bad_auth;
            }
            bind_ = rep.bind;
            co_return error::none;
        }

        /**
         * @brief 服务端握手：greeting → 方法协商 → 认证 → 请求 → 响应
         * @param enable_tcp 是否允许 CONNECT 命令（TCP 转发）
         * @param enable_udp 是否允许 UDP_ASSOCIATE 命令（UDP 中继）
         * @param enable_auth 是否启用用户名/密码认证（RFC 1929）
         * @param username 认证用户名（enable_auth 为 true 时生效）
         * @param password 认证密码（enable_auth 为 true 时生效）
         * @return 错误码与解析的请求
         * @details 完整服务端流程（RFC 1928 + 1929）。失败时按协议
         * 发送对应错误响应。
         */
        [[nodiscard]] auto read_handshake(const server_config &cfg)
            -> net::awaitable<std::pair<error, request>>
        {
            const auto &enable_tcp = cfg.enable_tcp;
            const auto &enable_udp = cfg.enable_udp;
            const auto &enable_auth = cfg.enable_auth;
            const auto &username = cfg.username;
            const auto &password = cfg.password;
            // 1. 方法协商：读取 greeting（2B 头 + 方法列表）
            std::array<std::uint8_t, 2> head{};
            if (co_await read_exact(std::span<std::uint8_t>(head)))
            {
                co_return std::pair{error::io_error, request{}};
            }
            if (head[0] != version)
            {
                co_return std::pair{error::version_mismatch, request{}};
            }
            std::vector<std::uint8_t> methods(head[1]);
            if (!methods.empty() && co_await read_exact(methods))
            {
                co_return std::pair{error::io_error, request{}};
            }

            // 2. 选择认证方法（检查客户端方法列表）
            const auto want = enable_auth ? static_cast<std::uint8_t>(auth_method::user_pass)
                                          : static_cast<std::uint8_t>(auth_method::no_auth);
            const bool acceptable = std::find(methods.begin(), methods.end(), want) != methods.end();
            if (!acceptable)
            {
                co_await send_method_reply(static_cast<std::uint8_t>(auth_method::no_acceptable));
                co_return std::pair{error::not_supported, request{}};
            }

            // 3. 发送方法选择
            if (co_await send_method_reply(want) != error::none)
            {
                co_return std::pair{error::io_error, request{}};
            }

            // 4. 认证（如需）
            if (want == static_cast<std::uint8_t>(auth_method::user_pass))
            {
                const bool ok = co_await userpass_auth(username, password);
                if (!ok)
                {
                    co_return std::pair{error::bad_auth, request{}};
                }
            }

            // 5. 解析请求
            request req;
            auto err = co_await read_request(req);
            if (err != error::none)
            {
                co_await send_reply(reply_code::general_failure);
                co_return std::pair{err, request{}};
            }

            // 6. 命令检查
            if (req.cmd == command::connect && !enable_tcp)
            {
                co_await send_reply(reply_code::command_not_supported);
                co_return std::pair{error::not_supported, request{}};
            }
            if (req.cmd == command::udp_associate && !enable_udp)
            {
                co_await send_reply(reply_code::command_not_supported);
                co_return std::pair{error::not_supported, request{}};
            }

            // 7. 发送成功响应（bind 固定 0.0.0.0:0）
            co_await send_reply(reply_code::success);
            req_ = req;
            co_return std::pair{error::none, std::move(req)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（read_handshake 成功后有效）
         */
        [[nodiscard]] auto parsed() const -> const request &
        {
            return req_;
        }

        /**
         * @brief 获取客户端握手返回的绑定地址（UDP_ASSOCIATE 的 BND）
         * @return 绑定地址（握手前为空）
         */
        [[nodiscard]] auto bind_endpoint() const -> const address &
        {
            return bind_;
        }

        /**
         * @brief 精确分段读取（供包连接复用预读缓冲）
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto read_exact(std::span<std::uint8_t> dst) -> net::awaitable<bool>
        {
            return read_exact_impl(dst);
        }

    private:
        /**
         * @brief 发送方法选择回复
         */
        [[nodiscard]] auto send_method_reply(std::uint8_t method) const -> net::awaitable<error>
        {
            const std::array<std::uint8_t, 2> wire{version, method};
            co_return co_await send_bytes(wire) ? error::io_error : error::none;
        }

        /**
         * @brief RFC 1929 用户名/密码认证子协商（服务端）
         * @param username 期望用户名
         * @param password 期望密码
         * @return 认证结果
         */
        [[nodiscard]] auto userpass_auth(const std::string &username, const std::string &password)
            -> net::awaitable<bool>
        {
            std::array<std::uint8_t, 2> head{};
            if (co_await read_exact(std::span<std::uint8_t>(head)))
            {
                co_return false;
            }
            if (head[0] != 0x01)
            {
                co_return false;
            }
            std::vector<std::uint8_t> user(head[1]);
            if (co_await read_exact(user))
            {
                co_return false;
            }
            std::array<std::uint8_t, 1> plen{};
            if (co_await read_exact(std::span<std::uint8_t>(plen)))
            {
                co_return false;
            }
            std::vector<std::uint8_t> pass(plen[0]);
            if (co_await read_exact(pass))
            {
                co_return false;
            }
            const bool ok = std::string(user.begin(), user.end()) == username &&
                            std::string(pass.begin(), pass.end()) == password;
            const std::array<std::uint8_t, 2> resp{0x01, ok ? std::uint8_t{0x00} : std::uint8_t{0x01}};
            co_await send_bytes(resp);
            co_return ok;
        }

        /**
         * @brief 发送响应（bind 空 = 0.0.0.0:0）
         */
        [[nodiscard]] auto send_reply(reply_code code, const address &bind = {}) const
            -> net::awaitable<error>
        {
            reply rep;
            rep.ver = version;
            rep.code = code;
            if (bind.host.empty())
            {
                rep.bind.type = address_type::ipv4;
                rep.bind.host = "0.0.0.0";
                rep.bind.port = 0;
            }
            else
            {
                rep.bind = bind;
            }
            co_return co_await send_bytes(build_reply(rep)) ? error::io_error : error::none;
        }

        /**
         * @brief 读取并解析请求（命令 + 地址）
         */
        [[nodiscard]] auto read_request(request &req) -> net::awaitable<error>
        {
            std::array<std::uint8_t, 4> head{};
            auto ec = co_await read_exact(std::span<std::uint8_t>(head));
            if (ec)
            {
                co_return error::io_error;
            }
            if (head[0] != version)
            {
                co_return error::version_mismatch;
            }
            req.cmd = static_cast<command>(head[1]);
            if (req.cmd != command::connect && req.cmd != command::udp_associate)
            {
                co_return error::not_supported;
            }
            req.target.type = static_cast<address_type>(head[3]);
            co_return co_await read_address(req.target);
        }

        /**
         * @brief 读取响应（reply）
         */
        [[nodiscard]] auto read_reply(reply &rep) -> net::awaitable<error>
        {
            std::array<std::uint8_t, 4> head{};
            if (co_await read_exact(std::span<std::uint8_t>(head)))
            {
                co_return error::io_error;
            }
            if (head[0] != version)
            {
                co_return error::version_mismatch;
            }
            rep.code = static_cast<reply_code>(head[1]);
            rep.bind.type = static_cast<address_type>(head[3]);
            co_return co_await read_address(rep.bind);
        }

        /**
         * @brief 读取地址（ATYP + ADDR + PORT）
         */
        [[nodiscard]] auto read_address(address &addr) -> net::awaitable<error>
        {
            switch (addr.type)
            {
            case address_type::ipv4: {
                std::array<std::uint8_t, 4> ip{};
                if (co_await read_exact_impl(std::span<std::uint8_t>(ip)))
                {
                    co_return error::io_error;
                }
                std::array<char, 16> buf{};
                std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
                addr.host = buf.data();
                break;
            }
            case address_type::ipv6: {
                std::array<std::uint8_t, 16> ip{};
                if (co_await read_exact_impl(std::span<std::uint8_t>(ip)))
                {
                    co_return error::io_error;
                }
                addr.host.assign(reinterpret_cast<const char *>(ip.data()), 16);
                break;
            }
            case address_type::domain: {
                std::array<std::uint8_t, 1> len{};
                if (co_await read_exact_impl(std::span<std::uint8_t>(len)))
                {
                    co_return error::io_error;
                }
                std::vector<std::uint8_t> host(len[0]);
                if (co_await read_exact_impl(host))
                {
                    co_return error::io_error;
                }
                addr.host.assign(reinterpret_cast<const char *>(host.data()), host.size());
                break;
            }
            default: co_return error::bad_message;
            }
            std::array<std::uint8_t, 2> port{};
            if (co_await read_exact_impl(std::span<std::uint8_t>(port)))
            {
                co_return error::io_error;
            }
            addr.port = static_cast<std::uint16_t>(port[0]) << 8 | port[1];
            co_return error::none;
        }

        /**
         * @brief 精确读取指定字节数（内部缓冲优先 + 底层补充）
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto read_exact_impl(std::span<std::uint8_t> dst) -> net::awaitable<bool>
        {
            std::size_t done = 0;
            while (done < dst.size())
            {
                if (used_ > 0)
                {
                    const auto n = std::min(dst.size() - done, used_);
                    std::memcpy(dst.data() + done, buf_.data(), n);
                    if (n < used_)
                    {
                        std::memmove(buf_.data(), buf_.data() + n, used_ - n);
                        used_ -= n;
                    }
                    else
                    {
                        buf_.clear();
                        used_ = 0;
                    }
                    done += n;
                    continue;
                }
                std::array<std::uint8_t, 512> chunk{};
                std::error_code ec;
                const auto n = co_await next_layer_->async_read_some(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(chunk.data()), chunk.size()), ec);
                if (ec || n == 0)
                {
                    co_return true;
                }
                buf_.insert(buf_.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
                used_ += n;
            }
            co_return false;
        }

        /**
         * @brief 发送全部字节
         * @param data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto send_bytes(std::span<const std::uint8_t> data) const -> net::awaitable<bool>
        {
            std::size_t done = 0;
            while (done < data.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(data.data() + done),
                                               data.size() - done),
                    ec);
                if (ec)
                {
                    co_return true;
                }
                done += n;
            }
            co_return false;
        }

        shared_transmission next_layer_; ///< 上游传输（独占所有权）
        request req_;                    ///< 服务端握手解析结果
        address bind_;                   ///< 客户端握手 BND 地址
        std::vector<std::uint8_t> buf_;  ///< 预读缓冲（隧道数据暂存）
        std::size_t used_{0};            ///< 缓冲中有效字节数
    };

    /// 流连接共享指针
    using shared_conn = std::shared_ptr<conn>;

    static_assert(psmtest::transmission_like<conn>);

} // namespace psmtest::socks5
