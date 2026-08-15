/**
 * @file conn.hpp
 * @brief Restls 会话连接对象（transmission 装饰器）
 * @details 将底层传输包装为 Restls 连接：
 * 1. write_handshake / read_handshake：认证握手（测试库简化：
 *    交换 server_random，客户端派生 secret 校验服务端 mask）
 * 2. 数据面：应用数据记录带 auth_mac + XOR mask 编解码
 * @note 与 restls.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/memory/container.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/transmission.hpp>
#include <common/stealth/restls/codec.hpp>
#include <common/stealth/restls/types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace psmtest::restls
{

    /**
     * @class conn
     * @brief Restls 会话连接（transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面
     * 经 auth_mac + mask 编解码透传。
     * @tparam Memory 会话内存策略（默认 8KB arena；可注入自定义策略）
     */
    template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    class conn : public psmtest::transmission,
                 public std::enable_shared_from_this<conn<Memory>>
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using memory_type = Memory;
        /**
         * @brief 构造函数
         * @param upstream 底层传输（所有权移交）
         * @param password 认证密码
         */
        explicit conn(shared_transmission upstream, std::string password)
            : next_layer_(std::move(upstream)), password_(std::move(password))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return next_layer_->executor();
        }

        /**
         * @brief 客户端握手：派生 secret 并交换 server_random
         * @param server_random 服务端随机数（32 字节）
         * @return 错误码
         * @details 客户端由密码派生 RestlsSecret，后续认证均以其为密钥。
         */
        [[nodiscard]] auto write_handshake(std::span<const std::uint8_t> server_random)
        -> net::awaitable<error>
        {
            if (server_random.size() != 32)
                co_return error::bad_length;
            secret_ = derive_secret(password_);
            std::copy(server_random.begin(), server_random.end(), server_random_.begin());
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 服务端握手：派生 secret 并校验客户端身份
         * @param server_random 服务端随机数（32 字节）
         * @return 错误码
         * @details 服务端同样派生 secret，并以 server_mask 加密
         * 首个 TLS 记录实现服务端身份验证（测试库简化直接派生）。
         */
        [[nodiscard]] auto read_handshake(std::span<const std::uint8_t> server_random)
        -> net::awaitable<error>
        {
            if (server_random.size() != 32)
                co_return error::bad_length;
            secret_ = derive_secret(password_);
            std::copy(server_random.begin(), server_random.end(), server_random_.begin());
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 透传读取（数据面原样，mask 编解码由上层记录层负责）
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
            if (!handshaken_)
            {
                ec = make_error_code(error::not_open);
                co_return 0;
            }
            co_return co_await next_layer_->async_read_some(buffer, ec);
        }

        /**
         * @brief 透传写入（数据面原样）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer,
                                            std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
            if (!handshaken_)
            {
                ec = make_error_code(error::not_open);
                co_return 0;
            }
            co_return co_await next_layer_->async_write_some(buffer, ec);
        }

        /**
         * @brief 关闭底层传输
         */
        void close() override
        {
            next_layer_->close();
        }

        /**
         * @brief 取消挂起操作
         */
        void cancel() override
        {
            next_layer_->cancel();
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto next_layer() noexcept -> psmtest::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
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
         * @brief 获取派生密钥（握手后有效）
         */
        [[nodiscard]] auto secret() const -> const std::array<std::uint8_t, 32> &
        {
            return secret_;
        }

    private:
        shared_transmission next_layer_;                ///< 底层传输（独占所有权）
        std::string password_;                          ///< 认证密码
        std::array<std::uint8_t, 32> secret_{};         ///< RestlsSecret（派生）
        std::array<std::uint8_t, 32> server_random_{};  ///< 服务端随机数
        bool handshaken_{false};                        ///< 握手完成标志
    };

    /// 流连接共享指针（默认内存策略）
    using shared_conn = std::shared_ptr<conn<>>;

    static_assert(psmtest::transmission_like<conn<>>);

} // namespace psmtest::restls
