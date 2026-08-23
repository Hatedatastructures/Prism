/**
 * @file conn.hpp
 * @brief VLESS 流连接对象（TCP，实现 transmission）
 * @details 单条 VLESS 连接的完整协议状态：
 * - 客户端握手：write_handshake(target, cmd)（发送请求头 →
 *   读取 2 字节响应校验 Version 回显）
 * - 服务端握手：read_handshake()（四段精确解析：固定前缀 →
 *   Addons → 尾部 → 地址体，校验 version/uuid/cmd/atyp，
 *   发送 2 字节响应）
 * 握手后为纯字节流透传（预读缓冲优先）。UDP 数据面由 dgram.hpp
 * 提供（独立包连接类型，嵌入本连接）。
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
#include <utility>
#include <vector>

#include <common/core/error.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/protocol/address.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/vless/codec.hpp>
#include <common/protocols/vless/types.hpp>

namespace preview::vless
{

    /**
     * @class conn
     * @brief VLESS 流连接对象
     * @details 单条连接的协议状态：双端握手、数据透传、预读缓冲。
     * 实现 transmission 接口可挂载装饰器链。由工厂创建，
     * 调用方以 shared_ptr 持有。
     */
    template <preview::memory::restrict Memory = preview::memory::session_resource<>>
    class conn : public preview::transmission, public std::enable_shared_from_this<conn<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param upstream 上游传输（所有权移交）
         * @param uuid 协议 UUID（16 字节，凭据/校验用）
         * @param auth 认证器（非拥有；nullptr = 静态比对 uuid）
         */
        explicit conn(shared_transmission upstream, std::array<std::uint8_t, uuid_len> uuid,
                      const preview::authenticator *auth = nullptr)
            : next_layer_(std::move(upstream)), uuid_(uuid), auth_(auth)
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
        [[nodiscard]] auto next_layer() noexcept -> preview::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         */
        [[nodiscard]] auto next_layer() const noexcept -> const preview::transmission * override
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
         * @brief 客户端握手：发送请求头 + 读取 2 字节响应
         * @param target 目标地址
         * @param cmd 命令（默认 tcp；UDP 场景传 udp）
         * @return 错误码
         * @details 构造请求头（version/uuid/cmd/target）发送，
         * 读取 2 字节响应校验 Version 回显（对齐 Xray）。
         */
        [[nodiscard]] auto write_handshake(const address &target, command cmd = command::tcp)
            -> net::awaitable<error>
        {
            request_header hdr;
            hdr.version = protocol_version;
            hdr.uuid = uuid_;
            hdr.cmd = cmd;
            hdr.target = target;
            const auto wire = build_request(hdr);
            if (co_await send_bytes(wire))
            {
                co_return error::io_error;
            }

            std::array<std::uint8_t, 2> resp{};
            if (co_await read_exact_impl(std::span<std::uint8_t>(resp)))
            {
                co_return error::io_error;
            }
            if (resp[0] != protocol_version)
            {
                co_return error::bad_magic;
            }
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 服务端握手：四段解析请求头 + 校验 + 发送响应
         * @param enable_tcp 是否允许 TCP 命令
         * @param enable_udp 是否允许 UDP 命令
         * @param enable_mux 是否允许 MUX 命令
         * @return 错误码与解析的请求
         * @details 精确分段读取（固定前缀 18B → Addons → 尾部 4B →
         * 地址体），校验 version/addnl/uuid/cmd/atyp。认证失败
         * （UUID 不匹配）不发送响应，静默断开（对齐 Xray）。
         */
        [[nodiscard]] auto read_handshake(bool enable_tcp = true, bool enable_udp = true,
                                          bool enable_mux = true)
            -> net::awaitable<std::pair<error, request_header>>
        {
            // 1. 固定前缀：Version(1) + UUID(16) + AddnlLen(1)
            std::array<std::uint8_t, 18> prefix{};
            if (co_await read_exact_impl(std::span<std::uint8_t>(prefix)))
            {
                co_return std::pair{error::io_error, request_header{}};
            }
            if (prefix[0] != protocol_version)
            {
                co_return std::pair{error::bad_magic, request_header{}};
            }

            // 2. Addons（对齐主库：addnl_len 必须为 0）
            if (prefix[17] != 0)
            {
                co_return std::pair{error::bad_message, request_header{}};
            }

            // 3. 尾部：Cmd(1) + Port(2 BE) + Atyp(1)
            std::array<std::uint8_t, 4> tail{};
            if (co_await read_exact_impl(std::span<std::uint8_t>(tail)))
            {
                co_return std::pair{error::io_error, request_header{}};
            }
            const auto cmd = static_cast<command>(tail[0]);
            if (cmd != command::tcp && cmd != command::udp && cmd != command::mux)
            {
                co_return std::pair{error::bad_message, request_header{}};
            }
            if ((cmd == command::tcp && !enable_tcp) || (cmd == command::udp && !enable_udp) ||
                (cmd == command::mux && !enable_mux))
            {
                co_return std::pair{error::not_supported, request_header{}};
            }
            const auto atyp = static_cast<address_type>(tail[3]);
            if (atyp != address_type::ipv4 && atyp != address_type::domain && atyp != address_type::ipv6)
            {
                co_return std::pair{error::bad_message, request_header{}};
            }

            // 4. 地址体
            request_header req;
            std::memcpy(req.uuid.data(), prefix.data() + 1, uuid_len);
            req.cmd = cmd;
            req.target.type = atyp;
            req.target.port = static_cast<std::uint16_t>(tail[1]) << 8 | tail[2];
            auto err = co_await read_address_body(req.target);
            if (err != error::none)
            {
                co_return std::pair{err, request_header{}};
            }

            // 5. UUID 校验（memcmp，不匹配则静默断开；可注入认证器）
            const std::string_view got_uuid(reinterpret_cast<const char *>(prefix.data() + 1), uuid_len);
            const std::string_view expect_uuid(reinterpret_cast<const char *>(uuid_.data()), uuid_len);
            bool bad_auth = false;
            if (auth_)
            {
                bad_auth = !auth_->check("", got_uuid).ok;
            }
            else
            {
                bad_auth = (got_uuid != expect_uuid);
            }
            if (bad_auth)
            {
                co_return std::pair{error::bad_auth, request_header{}};
            }

            // 6. 发送 2 字节响应 [Version 0x00][Addons Length 0x00]
            const auto resp = make_response();
            if (co_await send_bytes(resp))
            {
                co_return std::pair{error::io_error, request_header{}};
            }

            parsed_ = req;
            handshaken_ = true;
            co_return std::pair{error::none, std::move(req)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（read_handshake 成功后有效）
         */
        [[nodiscard]] auto parsed() const -> const request_header &
        {
            return parsed_;
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
         * @brief 读取地址体（ATYP 已从尾部解析）
         * @param addr 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 protocol/common::read_address_body
         */
        [[nodiscard]] auto read_address_body(address &addr) -> net::awaitable<error>
        {
            return preview::protocol::common::read_address_body(
                addr, [this](std::span<std::uint8_t> dst) -> net::awaitable<bool> { return read_exact_impl(dst); });
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

        shared_transmission next_layer_;          ///< 上游传输（独占所有权）
        std::array<std::uint8_t, uuid_len> uuid_; ///< 协议 UUID（凭据/校验）
        const preview::authenticator *auth_{nullptr}; ///< 认证器（非拥有）
        request_header parsed_;                   ///< 服务端握手解析结果
        Memory mem_;                     ///< 会话内存策略（arena，热路径零释放分配）
        typename Memory::template buffer<std::uint8_t> buf_{mem_.arena()}; ///< 预读缓冲（隧道数据暂存）
        std::size_t used_{0};                     ///< 缓冲中有效字节数
        bool handshaken_{false};         ///< 握手完成标志
    };


    /// 流连接共享指针
    using shared_conn = std::shared_ptr<conn<>>;

    static_assert(preview::transmission_like<conn<>>);

} // namespace preview::vless
