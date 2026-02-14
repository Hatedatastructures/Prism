/**
 * @file adaptation.hpp
 * @brief Socket 异步 IO 适配器
 * @details 统一 TCP 和 UDP 的异步读写接口，屏蔽底层 API 差异。
 * 同时也提供将 transmission 接口适配为 Boost.Asio 概念的适配器。
 */
#pragma once

#include <boost/asio.hpp>
#include <span>
#include <utility>
#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/transport/reliable.hpp>
#include <forward-engine/memory/container.hpp>

/**
 * @namespace ngx::transport
 * @brief 传输层 (Data Plane)
 * @details 负责底层的数据搬运、连接管理和协议封装。
 * 包含 IO 适配器、连接池、隧道封装等组件。
 */
namespace ngx::transport
{
    namespace net = boost::asio;

    /**
     * @brief Transmission 适配器
     * @details 将 `transmission` 接口适配为 `Boost.Asio` 的 `AsyncReadStream/AsyncWriteStream` 概念，
     * 以便与 `Boost.Beast`、`Boost.Asio.SSL` 等库协同工作。
     * @tparam TransmissionPtr 传输层指针类型 (通常是 `std::unique_ptr<transmission>`)
     */
    template <typename TransmissionPtr>
    class connector
    {
    public:
        using executor_type = net::any_io_executor;
        using transmission_type = typename TransmissionPtr::element_type;

        explicit connector(TransmissionPtr trans, std::span<const std::byte> preread = {})
            : trans_(std::move(trans))
        {
            if (!preread.empty())
            {
                preread_buffer_.assign(preread.begin(), preread.end());
            }
        }

        // 支持移动构造
        connector(connector &&other) noexcept
            : trans_(std::move(other.trans_)),
              preread_buffer_(std::move(other.preread_buffer_)),
              preread_offset_(other.preread_offset_)
        {
            other.preread_offset_ = 0;
        }

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

        executor_type get_executor()
        {
            return trans_->executor();
        }

        executor_type executor()
        {
            return get_executor();
        }

        /**
         * @brief 适配 async_read_some
         */
        template <typename MutableBufferSequence, typename CompletionToken>
        auto async_read_some(const MutableBufferSequence &buffers, CompletionToken &&token)
        {
            // 如果有预读数据，先从中读取
            if (preread_offset_ < preread_buffer_.size())
            {
                // 复制数据到缓冲区
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
                // 立即完成，返回复制的字节数
                return net::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(
                    [bytes_to_copy](auto &&handler)
                    {
                        boost::system::error_code ec;
                        std::forward<decltype(handler)>(handler)(ec, bytes_to_copy);
                    },
                    token);
            }
            // 否则委托给底层传输
            if (trans_->is_reliable())
            {
                auto *tcp = static_cast<reliable *>(trans_.get());
                return tcp->native_socket().async_read_some(buffers, std::forward<CompletionToken>(token));
            }
            return ngx::transport::async_read_some(*trans_, buffers, std::forward<CompletionToken>(token));
        }

        /**
         * @brief 适配 async_write_some
         */
        template <typename ConstBufferSequence, typename CompletionToken>
        auto async_write_some(const ConstBufferSequence &buffers, CompletionToken &&token)
        {
            if (trans_->is_reliable())
            {
                auto *tcp = static_cast<reliable *>(trans_.get());
                return tcp->native_socket().async_write_some(buffers, std::forward<CompletionToken>(token));
            }
            return ngx::transport::async_write_some(*trans_, buffers, std::forward<CompletionToken>(token));
        }

        // SSL Stream 需要的接口
        using lowest_layer_type = connector;
        
        lowest_layer_type &lowest_layer()
        {
            return *this;
        }

        const lowest_layer_type &lowest_layer() const
        {
            return *this;
        }

        // 获取底层 transmission
        auto &transmission()
        {
            return *trans_;
        }

        /**
         * @brief 释放所有权
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
