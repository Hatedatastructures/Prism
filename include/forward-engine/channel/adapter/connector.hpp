/**
 * @file connector.hpp
 * @brief Socket 异步 IO 适配器
 * @details 统一 TCP 和 UDP 的异步读写接口，屏蔽底层 API 差异。
 * 同时提供将 transmission 接口适配为 Boost.Asio 概念的适配器。
 * 适配器类 connector 模板将 transmission 接口适配为
 * AsyncReadStream/AsyncWriteStream 概念，支持注入预读数据，
 * 避免协议检测时丢失数据。提供 async_read_some 和 async_write_some
 * 方法，支持协程和回调，兼容 reliable（TCP）和 unreliable（UDP）
 * 传输层。该模块是传输层和上层协议处理之间的适配层，
 * 不应直接用于网络 IO。
 * @note 预读数据注入必须在协议握手之前完成，否则可能导致协议解析失败。
 * @warning 预读数据注入可能导致协议解析失败，请确保在正确的时机注入数据。
 */

#pragma once

#include <boost/asio.hpp>
#include <span>
#include <utility>
#include <forward-engine/channel/transport/transmission.hpp>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/fault/compatible.hpp>

namespace ngx::channel
{
    namespace net = boost::asio;

    /**
     * @class connector
     * @brief Transmission 适配器
     * @details 将 transmission 接口适配为 Boost.Asio 的
     * AsyncReadStream/AsyncWriteStream 概念，以便与 Boost.Beast、
     * Boost.Asio.SSL 等库协同工作。该适配器是连接传输层和上层协议处理
     * 的关键桥梁。
     * @tparam TransmissionPtr 传输层指针类型，通常是 std::unique_ptr<transmission>
     */
    template <typename TransmissionPtr>
    class connector
    {
    public:
        using executor_type = net::any_io_executor;
        using transmission_type = typename TransmissionPtr::element_type;

        /**
         * @brief 构造函数（传输层指针 + 预读数据）
         * @param trans 传输层对象指针，所有权将被转移
         * @param preread 预读数据切片，默认为空
         */
        explicit connector(TransmissionPtr trans, std::span<const std::byte> preread = {})
            : trans_(std::move(trans))
        {
            if (!preread.empty())
            {
                preread_buffer_.assign(preread.begin(), preread.end());
            }
        }

        /**
         * @brief 移动构造函数
         * @param other 要移动的适配器对象
         */
        connector(connector &&other) noexcept
            : trans_(std::move(other.trans_)),
              preread_buffer_(std::move(other.preread_buffer_)),
              preread_offset_(other.preread_offset_)
        {
            other.preread_offset_ = 0;
        }

        /**
         * @brief 移动赋值运算符
         * @param other 要移动的适配器对象
         * @return connector& 当前对象的引用
         */
        connector &operator=(connector &&other) noexcept
        {
            if (this != &other)
            {
                trans_ = std::move(other.trans_);
                preread_buffer_ = std::move(other.preread_buffer_);
                preread_offset_ = other.preread_offset_;
                other.preread_offset_ = 0;
            }
            return *this;
        }

        /**
         * @brief 获取执行器
         * @return executor_type 执行器对象
         */
        executor_type get_executor()
        {
            return trans_->executor();
        }

        /**
         * @brief 获取执行器
         * @return executor_type 执行器对象
         */
        executor_type executor()
        {
            return get_executor();
        }

        /**
         * @brief 适配 async_read_some
         * @tparam MutableBufferSequence 可变缓冲区序列类型
         * @tparam CompletionToken 完成令牌类型（协程、回调等）
         * @param buffers 可变缓冲区序列，用于存储读取的数据
         * @param token 完成令牌，用于接收读取结果
         * @return 异步操作结果，类型取决于完成令牌
         */
        template <typename MutableBufferSequence, typename CompletionToken>
        auto async_read_some(const MutableBufferSequence &buffers, CompletionToken &&token)
        {
            if (preread_offset_ < preread_buffer_.size())
            {
                std::size_t bytes_available = preread_buffer_.size() - preread_offset_;
                std::size_t bytes_to_copy = 0;
                auto buf_it = net::buffer_sequence_begin(buffers);
                auto buf_end = net::buffer_sequence_end(buffers);
                for (; buf_it != buf_end && bytes_to_copy < bytes_available; ++buf_it)
                {
                    auto buf = *buf_it;
                    std::size_t buf_size = buf.size();
                    std::size_t copy_size = std::min(buf_size, bytes_available - bytes_to_copy);
                    std::memcpy(buf.data(), preread_buffer_.data() + preread_offset_ + bytes_to_copy, copy_size);
                    bytes_to_copy += copy_size;
                }
                preread_offset_ += bytes_to_copy;
                auto handler = [bytes_to_copy]<typename Callback>(Callback &&handler)
                {
                    boost::system::error_code ec;
                    std::forward<Callback>(handler)(ec, bytes_to_copy);
                };
                return net::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(handler, token);
            }

            return ngx::channel::transport::async_read_some(*trans_, buffers, std::forward<CompletionToken>(token));
        }

        /**
         * @brief 适配 async_write_some
         * @tparam ConstBufferSequence 常量缓冲区序列类型
         * @tparam CompletionToken 完成令牌类型（协程、回调等）
         * @param buffers 常量缓冲区序列，包含要写入的数据
         * @param token 完成令牌，用于接收写入结果
         * @return 异步操作结果，类型取决于完成令牌
         */
        template <typename ConstBufferSequence, typename CompletionToken>
        auto async_write_some(const ConstBufferSequence &buffers, CompletionToken &&token)
        {
            return ngx::channel::transport::async_write_some(*trans_, buffers, std::forward<CompletionToken>(token));
        }

        /**
         * @brief 完整写入操作
         * @details 委托给 transmission 的 async_write 虚函数。
         * 允许子类（如 UDP）自定义完整写入行为。
         * @param buffer 要写入的数据缓冲区
         * @param ec 错误码输出参数，成功时为默认值
         * @return net::awaitable<std::size_t> 协程对象，完成后返回实际写入的总字节数
         */
        auto async_write(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            co_return co_await trans_->async_write(buffer, ec);
        }

        /**
         * @brief 完整读取操作
         * @details 委托给 transmission 的 async_read 虚函数。
         * 允许子类自定义完整读取行为。
         * @param buffer 接收数据的缓冲区
         * @param ec 错误码输出参数，成功时为默认值
         * @return net::awaitable<std::size_t> 协程对象，完成后返回实际读取的总字节数
         */
        auto async_read(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            co_return co_await trans_->async_read(buffer, ec);
        }

        using lowest_layer_type = connector;

        /**
         * @brief 获取底层对象
         * @return lowest_layer_type& 当前对象的引用
         */
        lowest_layer_type &lowest_layer()
        {
            return *this;
        }

        /**
         * @brief 获取底层对象（常量版本）
         * @return const lowest_layer_type& 当前对象的常量引用
         */
        const lowest_layer_type &lowest_layer() const
        {
            return *this;
        }

        /**
         * @brief 获取底层传输层对象
         * @return transmission_type& 传输层对象的引用
         */
        auto &transmission()
        {
            return *trans_;
        }

        /**
         * @brief 释放传输层所有权
         * @return TransmissionPtr 传输层对象指针
         */
        TransmissionPtr release()
        {
            return std::move(trans_);
        }

    private:
        TransmissionPtr trans_;
        memory::vector<std::byte> preread_buffer_;
        std::size_t preread_offset_ = 0;
    };
}
