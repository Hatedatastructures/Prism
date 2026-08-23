/**
 * @file conn.hpp
 * @brief Trojan 流连接对象（装饰器模式：内存策略模板化）
 * @details 单条 TCP 协议连接的完整状态：持有上游传输（所有权，
 * shared_transmission 运行时多态）、预读缓冲、凭据。读写经虚接口
 * 静态委托给上游具体传输（内存流 / 可靠连接均满足 transmission_like）。
 * - 客户端：write_handshake 发送请求头（凭据 + 命令 + 地址）
 * - 服务端：read_handshake 解析校验请求头
 * UDP 数据面由 dgram.hpp 提供（独立包连接类型，嵌入本连接）。
 * @note 对齐 mihomo transport：TCP = net.Conn（纯流语义）。
 * @note 模板参数仅 Memory（会话内存策略：arena 复用零分配），
 *      上游传输类型经 transmission 虚接口擦除，装饰器链统一。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <common/core/authenticator.hpp>
#include <common/core/error.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/protocol/address.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/trojan/codec.hpp>
#include <common/protocols/trojan/types.hpp>

namespace preview::trojan
{

    /**
     * @class conn
     * @brief Trojan 流连接对象（装饰器模式）
     * @tparam Memory 会话内存策略（默认 8KB arena）
     * @details 单条 TCP 连接的协议状态：握手（客户端写 / 服务端读）、
     * 数据透传、预读缓冲。读写经传输虚接口委托上游具体类型。
     * 由工厂（connect / accept）创建，调用方以 shared_ptr 持有。
     */
    template <preview::memory::restrict Memory = preview::memory::session_resource<>>
    class conn : public preview::transmission, public std::enable_shared_from_this<conn<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param upstream 上游传输（所有权移交）
         * @param password 协议密码（派生 SHA224 hex 凭据）
         * @param auth 认证器（非拥有；nullptr = 静态比对 password）
         */
        explicit conn(shared_transmission upstream, std::string password,
                      const preview::authenticator *auth = nullptr)
            : next_layer_(std::move(upstream)), auth_(auth)
        {
            cred_ = credential(password);
        }

        /**
         * @brief 获取执行器（静态分派到上游）
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
         * @brief 异步写入（静态分派透传）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->async_write_some(buffer, ec);
        }

        /**
         * @brief 异步读取直至缓冲区读满（组合操作）
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数（满 = buffer.size()；EOF 提前返回）
         */
        [[nodiscard]] auto async_read(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            std::size_t done = 0;
            while (done < buffer.size())
            {
                const auto n = co_await async_read_some(buffer.subspan(done), ec);
                if (ec)
                {
                    co_return done;
                }
                if (n == 0)
                {
                    co_return done;
                }
                done += n;
            }
            co_return done;
        }

        /**
         * @brief 异步写入直至缓冲区写满（组合操作）
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 实际写入字节数（满 = buffer.size()）
         */
        [[nodiscard]] auto async_write(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            std::size_t done = 0;
            while (done < buffer.size())
            {
                const auto n = co_await async_write_some(buffer.subspan(done), ec);
                if (ec)
                {
                    co_return done;
                }
                if (n == 0)
                {
                    ec = make_error_code(error::broken_pipe);
                    co_return done;
                }
                done += n;
            }
            co_return done;
        }

        /**
         * @brief 关闭传输层（静态分派）
         */
        void close() override
        {
            next_layer_->close();
        }

        /**
         * @brief 取消挂起操作（静态分派）
         */
        void cancel() override
        {
            next_layer_->cancel();
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         */
        [[nodiscard]] auto next_layer() noexcept 
            -> preview::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         */
        [[nodiscard]] auto next_layer() const noexcept 
            -> const preview::transmission * override
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
         * @brief 会话是否有效（已握手且底层存在）
         * @return 有效返回 true
         */
        [[nodiscard]] auto is_valid() const noexcept -> bool
        {
            return next_layer_ != nullptr && handshaken_;
        }

        /**
         * @brief 获取底层传输引用（非拥有）
         * @return 底层传输
         */
        [[nodiscard]] auto underlying() noexcept -> shared_transmission
        {
            return next_layer_;
        }

        /**
         * @brief 获取会话级内存竞技场
         * @return 非拥有资源指针（供握手/解析的临时分配）
         * @note 分配的对象随 conn 存活，conn 析构时一次性回收
         */
        [[nodiscard]] auto arena() noexcept -> preview::memory::resource_pointer
        {
            return mem_.arena();
        }

        /**
         * @brief 客户端握手：发送请求头（凭据 + 命令 + 地址）
         * @param target 目标地址
         * @param cmd 命令（CONNECT / udp_associate / mux）
         * @return 错误码
         * @details 构造并发送请求头，不读响应（对齐主库 trojan）。
         * 由工厂 connect 内部调用。
         */
        [[nodiscard]] auto write_handshake(const address &target, command cmd = command::connect)
            -> net::awaitable<error>
        {
            const auto wire = build_request(cred_, cmd, target);
            const bool failed = co_await send_bytes(wire); // true = 发送失败
            handshaken_ = !failed;
            if (failed)
            {
                co_return error::io_error;
            }
            co_return error::none;
        }

        /**
         * @brief 服务端握手：解析请求头
         * @param enable_tcp 是否允许 CONNECT 命令
         * @param enable_udp 是否允许 UDP_ASSOCIATE 命令
         * @return 错误码与解析的请求
         * @details 精确分段读取并校验（凭据/CRLF/命令开关/atyp/尾部）。
         * 认证失败不发送响应，静默断开（对齐 trojan-gfw）。
         * 由工厂 accept 内部调用。
         */
        [[nodiscard]] auto read_handshake(bool enable_tcp = true, bool enable_udp = false)
            -> net::awaitable<std::pair<error, request_header>>
        {
            // 1. 凭据前缀：Credential(56) + CRLF(2)
            std::array<std::uint8_t, credential_len + 2> prefix{};
            if (co_await read_exact_impl(std::span<std::uint8_t>(prefix)))
            {
                co_return std::pair{error::io_error, request_header{}};
            }
            const std::string_view got(reinterpret_cast<const char *>(prefix.data()), credential_len);
            bool bad_auth = false;
            if (auth_)
            {
                bad_auth = !auth_->check("", got).ok;
            }
            else
            {
                bad_auth = (got != cred_);
            }
            if (bad_auth)
            {
                co_return std::pair{error::bad_auth, request_header{}};
            }
            if (prefix[credential_len] != '\r' || prefix[credential_len + 1] != '\n')
            {
                co_return std::pair{error::bad_magic, request_header{}};
            }

            // 2. 头部：Cmd(1) + Atyp(1)
            std::array<std::uint8_t, 2> head{};
            if (co_await read_exact_impl(std::span<std::uint8_t>(head)))
            {
                co_return std::pair{error::io_error, request_header{}};
            }
            const auto cmd = static_cast<command>(head[0]);
            if (cmd != command::connect && cmd != command::udp_associate && cmd != command::mux)
            {
                co_return std::pair{error::bad_message, request_header{}};
            }
            if (cmd == command::connect && !enable_tcp)
            {
                co_return std::pair{error::not_supported, request_header{}};
            }
            if (cmd == command::udp_associate && !enable_udp)
            {
                co_return std::pair{error::not_supported, request_header{}};
            }
            const auto atyp = static_cast<address_type>(head[1]);
            if (atyp != address_type::ipv4 && atyp != address_type::domain && atyp != address_type::ipv6)
            {
                co_return std::pair{error::bad_message, request_header{}};
            }

            // 3. 地址体
            request_header req;
            req.cmd = cmd;
            req.target.type = atyp;
            auto err = co_await read_address_body(req.target);
            if (err != error::none)
            {
                co_return std::pair{err, request_header{}};
            }

            // 4. 尾部：Port(2 BE) + CRLF(2)
            std::array<std::uint8_t, 4> tail{};
            if (co_await read_exact_impl(std::span<std::uint8_t>(tail)))
            {
                co_return std::pair{error::io_error, request_header{}};
            }
            req.target.port = static_cast<std::uint16_t>(tail[0]) << 8 | tail[1];
            if (tail[2] != '\r' || tail[3] != '\n')
            {
                co_return std::pair{error::bad_magic, request_header{}};
            }

            request_ = req;
            handshaken_ = true;
            co_return std::pair{error::none, std::move(req)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（read_handshake 成功后有效）
         */
        [[nodiscard]] auto request() const -> const request_header &
        {
            return request_;
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
         * @brief 读取地址体（ATYP 已由调用方解析）
         * @param addr 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 protocol/common::read_address_body
         */
        [[nodiscard]] auto read_address_body(address &addr)
            -> net::awaitable<error>
        {
            return preview::protocol::common::read_address_body(
                addr, [this](std::span<std::uint8_t> dst) -> net::awaitable<bool> { return read_exact_impl(dst); });
        }

        /**
         * @brief 精确读取指定字节数（内部缓冲优先 + 底层补充）
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         * @details 超读字节保留在内部缓冲供后续消费。
         */
        [[nodiscard]] auto read_exact_impl(std::span<std::uint8_t> dst) 
            -> net::awaitable<bool>
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

        shared_transmission next_layer_;              ///< 上游传输（基类传参，运行时多态）
        std::string cred_;                            ///< 预计算凭据（SHA224 hex）
        const preview::authenticator *auth_{nullptr}; ///< 认证器（非拥有）
        request_header request_;                      ///< 服务端握手解析结果
        Memory mem_;                                  ///< 会话内存策略（arena，热路径零释放分配）
        typename Memory::template buffer<std::uint8_t> buf_{mem_.arena()}; ///< 预读缓冲（隧道数据暂存）
        std::size_t used_{0};                                              ///< 缓冲中有效字节数
        bool handshaken_{false};                                           ///< 握手完成标志
    };

    /// 流连接共享指针
    using shared_conn = std::shared_ptr<conn<>>;

    // 编译期验证：conn 满足传输接口概念（可被其他协议工厂接收）
    static_assert(preview::transmission_like<conn<>>);

} // namespace preview::trojan
