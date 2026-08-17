/**
 * @file conn.hpp
 * @brief gRPC (gun) 会话连接对象（transmission 装饰器）
 * @details 将底层传输包装为 gun 连接（对齐 mihomo transport/gun）：
 * 1. write_handshake / read_handshake：HTTP/2 CONNECT 握手（简化）
 * 2. 数据面：gun 帧编解码（codec.hpp 纯函数），本类负责帧边界恢复
 * @note 与 gun.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/memory/container.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/gun/codec.hpp>
#include <common/protocols/gun/types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace preview::gun
{

    /**
     * @class conn
     * @brief gRPC (gun) 会话连接（transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面透传。
     * @tparam Memory 会话内存策略（默认 8KB arena；可注入自定义策略）
     */
    template <preview::memory::restrict Memory = preview::memory::session_resource<>>
    class conn : public preview::transmission, public std::enable_shared_from_this<conn<Memory>>
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using memory_type = Memory;

        /**
         * @brief 构造函数
         * @param upstream 底层传输（所有权移交）
         */
        explicit conn(shared_transmission upstream)
            : next_layer_(std::move(upstream))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto executor() const 
            -> net::any_io_executor override
        {
            return next_layer_->executor();
        }

        /**
         * @brief 客户端握手：发送 CONNECT 帧（简化）
         * @param host 目标主机
         * @return 错误码
         */
        [[nodiscard]] auto write_handshake(std::string_view host)
            -> net::awaitable<error>
        {
            const std::string header = "CONNECT " + std::string(host) + " HTTP/2\r\n\r\n";
            if (co_await send_bytes(as_u8_span(header)))
                co_return error::io_error;
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 服务端握手：解析 CONNECT 帧（简化）
         * @param host 输出目标主机
         * @return 错误码；bad_magic = 非 CONNECT 帧
         */
        [[nodiscard]] auto read_handshake(std::string &host)
            -> net::awaitable<error>
        {
            std::array<std::uint8_t, 256> chunk{};
            std::string header;
            for (int i = 0; i < 16; ++i)
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_read_some(
                    as_bytes(std::span<std::uint8_t>(chunk)), ec);
                if (ec || n == 0)
                    break;
                header.append(reinterpret_cast<const char *>(chunk.data()), n);
                if (header.find("\r\n\r\n") != std::string::npos)
                    break;
            }
            if (header.find("CONNECT ") != 0)
                co_return error::bad_magic;
            const auto first_line_end = header.find("\r\n");
            host = header.substr(8, first_line_end - 8);
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 透传读取（数据面原样）
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
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
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
        [[nodiscard]] auto next_layer() noexcept
            -> preview::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto next_layer() const noexcept 
            -> const preview::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto release() 
            -> shared_transmission override
        {
            return std::move(next_layer_);
        }

    private:
        /**
         * @brief 发送全部字节
         * @param data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto send_bytes(std::span<const std::uint8_t> data) const
            -> net::awaitable<bool>
        {
            std::size_t done = 0;
            while (done < data.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_write_some(as_bytes(data.subspan(done)), ec);
                if (ec)
                    co_return true;
                done += n;
            }
            co_return false;
        }

        shared_transmission next_layer_;  ///< 底层传输（独占所有权）
        bool handshaken_{false};          ///< 握手完成标志
    };

    /// 流连接共享指针（默认内存策略）
    using shared_conn = std::shared_ptr<conn<>>;

    static_assert(preview::transmission_like<conn<>>);

} // namespace preview::gun
