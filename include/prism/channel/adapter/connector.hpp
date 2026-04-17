/**
 * @file connector.hpp
 * @brief Socket 异步 IO 适配器
 * @details 统一 TCP 和 UDP 的异步读写接口，将 transmission
 * 适配为 Boost.Asio 的 AsyncReadStream/AsyncWriteStream
 * 概念。支持注入预读数据，避免协议检测时丢失数据。
 * @note 预读数据注入必须在协议握手之前完成。
 * @warning 预读数据注入时机不当可能导致协议解析失败。
 */

#pragma once

#include <boost/asio.hpp>
#include <span>
#include <utility>
#include <prism/channel/transport/transmission.hpp>
#include <prism/memory/container.hpp>

namespace psm::channel
{
    namespace net = boost::asio;

    /**
     * @class connector
     * @brief Transmission 适配器
     * @details 将 transmission 接口适配为 Boost.Asio 的
     * AsyncReadStream/AsyncWriteStream 概念。内部使用
     * shared_ptr 持有 transmission，确保异步操作期间
     * 传输对象不会被提前释放。支持注入预读数据，
     * 避免协议检测阶段已读取的数据丢失。
     * @note 预读数据注入必须在协议握手之前完成。
     * @warning 预读数据注入时机不当可能导致协议解析失败。
     * @throws std::bad_alloc 如果内存分配失败
     */
    class connector
    {
    public:
        using executor_type = net::any_io_executor;
        using transmission_ptr = transport::shared_transmission;

        /**
         * @brief 构造函数（传输层指针 + 预读数据）
         * @details 使用传输层指针和可选的预读数据构造适配器。
         * 预读数据将在首次 async_read_some 调用时优先返回，
         * 避免协议检测阶段已读取的数据丢失。
         * @param trans 传输层对象指针，所有权将被转移
         * @param preread 预读数据切片，默认为空
         */
        explicit connector(transmission_ptr trans, std::span<const std::byte> preread = {})
            : trans_(std::move(trans))
        {
            if (!preread.empty())
            {
                preread_buffer_.assign(preread.begin(), preread.end());
            }
        }

        /**
         * @brief 移动构造函数
         * @details 转移传输层指针、预读缓冲区和偏移量的所有权。
         * 移动后源对象的偏移量被重置为零。
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
         * @details 转移传输层指针、预读缓冲区和偏移量的所有权。
         * 移动后源对象的偏移量被重置为零。防止自赋值。
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
         * @details 返回底层传输层关联的执行器，满足 Boost.Asio 的
         * AsyncStream 概念要求。
         * @return executor_type 执行器对象
         */
        executor_type get_executor()
        {
            return trans_->executor();
        }

        /**
         * @brief 获取执行器
         * @details 委托给 get_executor()，提供便捷的执行器访问。
         * @return executor_type 执行器对象
         */
        executor_type executor()
        {
            return get_executor();
        }

        /**
         * @brief 适配 async_read_some
         * @details 将 Boost.Asio 的 async_read_some 调用适配到 transmission 接口。
         * 如果存在未消费的预读数据，优先从预读缓冲区拷贝到用户缓冲区，
         * 避免额外的异步读取操作。预读数据消费完毕后委托给传输层。
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

            return transport::async_read_some(trans_, buffers, std::forward<CompletionToken>(token));
        }

        /**
         * @brief 适配 async_write_some
         * @details 将 Boost.Asio 的 async_write_some 调用直接委托给传输层。
         * @tparam ConstBufferSequence 常量缓冲区序列类型
         * @tparam CompletionToken 完成令牌类型
         * @param buffers 常量缓冲区序列，包含要写入的数据
         * @param token 完成令牌，用于接收写入结果
         * @return 异步操作结果，类型取决于完成令牌
         */
        template <typename ConstBufferSequence, typename CompletionToken>
        auto async_write_some(const ConstBufferSequence &buffers, CompletionToken &&token)
        {
            return transport::async_write_some(trans_, buffers, std::forward<CompletionToken>(token));
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
         * @details 返回 connector 自身的引用，满足 Boost.Asio 的
         * lowest_layer 访问要求。
         * @return lowest_layer_type& 当前对象的引用
         */
        lowest_layer_type &lowest_layer()
        {
            return *this;
        }

        /**
         * @brief 获取底层对象（常量版本）
         * @details 返回 connector 自身的常量引用，满足 Boost.Asio 的
         * lowest_layer 常量访问要求。
         * @return const lowest_layer_type& 当前对象的常量引用
         */
        [[nodiscard]] const lowest_layer_type &lowest_layer() const
        {
            return *this;
        }

        /**
         * @brief 获取底层传输层对象
         * @details 返回内部持有的传输层对象的引用，用于直接操作传输层。
         * @return transport::transmission& 传输层对象的引用
         */
        auto &transmission() const
        {
            return *trans_;
        }

        /**
         * @brief 释放传输层所有权
         * @details 将内部持有的传输层指针移动返回，调用后对象不再持有传输层。
         * @return transmission_ptr 传输层对象指针
         */
        transmission_ptr release()
        {
            return std::move(trans_);
        }

    private:
        transmission_ptr trans_;                   // 传输层对象的共享指针
        memory::vector<std::byte> preread_buffer_; // 预读数据缓冲区
        std::size_t preread_offset_ = 0;           // 预读数据当前消费偏移量
    }; // class connector
} // namespace psm::channel
