/**
 * @file adaptation.hpp
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
#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/gist/compatible.hpp>

/**
 * @namespace ngx::transport
 * @brief 传输层（Data Plane）
 * @details 负责底层的数据搬运、连接管理和协议封装。该命名空间实现了
 * 基于 Boost.Asio 的现代 C++ 异步网络 IO，包含传输抽象 transmission
 * 接口和 reliable、unreliable 实现，连接池 source 类管理到上游服务的
 * 连接复用，IO 适配 connector 模板适配自定义接口到 Boost.Asio 概念，
 * 反向代理 reverse 类实现反向代理的 TCP 隧道。传输层层次为
 * Boost.Asio Socket（tcp::socket, udp::socket）封装为
 * ngx::transport::transmission 抽象接口，具体实现为 reliable（TCP）
 * 和 unreliable（UDP），再通过 connector 适配器连接到
 * Boost.Beast 或 Boost.Asio.SSL。
 * @warning 该命名空间的内容主要用于底层网络 IO，请勿在业务逻辑中直接调用。
 * @throws 传输层操作可能抛出 std::bad_alloc（内存不足）或
 * std::runtime_error（网络错误）。
 */
namespace ngx::transport
{
    namespace net = boost::asio;

    /**
     * @class connector
     * @brief Transmission 适配器
     * @details 将 transmission 接口适配为 Boost.Asio 的
     * AsyncReadStream/AsyncWriteStream 概念，以便与 Boost.Beast、
     * Boost.Asio.SSL 等库协同工作。该适配器是连接传输层和上层协议处理
     * 的关键桥梁。核心职责包括概念适配，实现 AsyncReadStream 和
     * AsyncWriteStream 概念；预读数据存储和提供，避免协议检测时丢失数据；
     * 提供 async_read_some 和 async_write_some 异步方法；支持 reliable
     *（TCP）和 unreliable（UDP）传输层。预读数据管理方面，构造时接收预读数据，
     * 存储在内部缓冲区，async_read_some 优先返回预读数据，维护预读数据偏移量
     * 确保顺序读取，预读数据耗尽后委托给底层 transmission。线程安全性设计方面，
     * 适配器设计为单线程使用，不应在多线程间共享；支持移动构造和移动赋值，
     * 正确处理所有权转移；提供 release 方法释放底层 transmission 所有权。
     * 生命周期安全方面，调用者必须确保 connector 在所有异步操作完成前保持有效。
     * @tparam TransmissionPtr 传输层指针类型，通常是 std::unique_ptr<transmission>
     * @note 该适配器主要用于协议处理阶段，不应在连接管理阶段使用。
     * @warning 预读数据必须与协议检测时读取的数据完全一致，
     * 否则会导致协议解析失败。
     * @warning 调用者必须确保 connector 在所有异步操作完成前保持有效。
     * @throws std::bad_alloc 如果预读缓冲区分配失败
     */
    template <typename TransmissionPtr>
    class connector
    {
    public:
        using executor_type = net::any_io_executor;
        using transmission_type = typename TransmissionPtr::element_type;

        /**
         * @brief 构造函数（传输层指针 + 预读数据）
         * @details 使用传输层指针和可选的预读数据构造适配器。
         * 预读数据存储在内部缓冲区中，后续的 async_read_some
         * 调用将优先返回预读数据。构造流程为传输层接管，接收传输层指针
         * 的所有权；预读存储，如果预读数据非空，存储在内部缓冲区；
         * 偏移初始化，预读数据偏移量初始化为 0。
         * @param trans 传输层对象指针，所有权将被转移
         * @param preread 预读数据切片，默认为空
         * @note 预读数据会复制到内部缓冲区，调用后原始数据可安全销毁。
         * @warning 如果预读数据过大，可能导致内存分配失败。
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
         * @details 从另一个适配器移动构造，转移传输层和预读数据的所有权。
         * @param other 要移动的适配器对象
         * @note 移动后源对象的预读偏移量重置为 0。
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
         * @details 从另一个适配器移动赋值，转移传输层和预读数据的所有权。
         * @param other 要移动的适配器对象
         * @return connector& 当前对象的引用
         * @note 自我赋值检查：如果是同一对象，不执行任何操作。
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
         * @details 返回底层传输层的执行器，用于调度异步操作。
         * @return executor_type 执行器对象
         */
        executor_type get_executor()
        {
            return trans_->executor();
        }

        /**
         * @brief 获取执行器
         * @details 返回底层传输层的执行器，用于调度异步操作。
         * @return executor_type 执行器对象
         */
        executor_type executor()
        {
            return get_executor();
        }

        /**
         * @brief 适配 async_read_some
         * @details 从底层传输层或预读缓冲区读取数据。如果预读缓冲区
         * 有剩余数据，优先返回预读数据；否则委托给底层传输层的
         * async_read_some 方法。读取逻辑为预读检查，检查预读缓冲区
         * 是否有剩余数据；预读返回，如果有预读数据，直接复制到用户
         * 缓冲区并立即完成；传输委托，如果预读数据耗尽，委托给底层
         * 传输层读取；类型适配，根据传输层类型调用不同的读取方法。
         * @tparam MutableBufferSequence 可变缓冲区序列类型
         * @tparam CompletionToken 完成令牌类型（协程、回调等）
         * @param buffers 可变缓冲区序列，用于存储读取的数据
         * @param token 完成令牌，用于接收读取结果
         * @return 异步操作结果，类型取决于完成令牌
         * @note 预读数据会优先返回，确保协议检测时读取的数据不丢失。
         * @warning 读取操作可能阻塞，建议在协程中调用。
         * @warning 调用者必须确保 connector 在异步操作完成前保持有效。
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
                {   // 遍历缓冲区序列，复制数据到用户缓冲区
                    auto buf = *buf_it;
                    std::size_t buf_size = buf.size();
                    std::size_t copy_size = std::min(buf_size, bytes_available - bytes_to_copy);
                    std::memcpy(buf.data(), preread_buffer_.data() + preread_offset_ + bytes_to_copy, copy_size);
                    bytes_to_copy += copy_size;
                }
                preread_offset_ += bytes_to_copy;
                // 调用完成令牌，传递读取到的字节数
                auto handler = [bytes_to_copy]<typename Callback>(Callback &&handler)
                {
                    boost::system::error_code ec;
                    std::forward<Callback>(handler)(ec, bytes_to_copy);
                };
                return net::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(handler,token);
            }

            return ngx::transport::async_read_some(*trans_, buffers, std::forward<CompletionToken>(token));
        }

        /**
         * @brief 适配 async_write_some
         * @details 向底层传输层写入数据。委托给底层传输层的
         * async_write_some 方法。写入逻辑为类型适配，根据传输层类型
         * 调用不同的写入方法；TCP 特化，如果是 reliable（TCP）传输层，
         * 调用原生 socket 的 async_write_some；UDP 委托，如果是
         * unreliable（UDP）传输层，委托给 transmission 接口。
         * @tparam ConstBufferSequence 常量缓冲区序列类型
         * @tparam CompletionToken 完成令牌类型（协程、回调等）
         * @param buffers 常量缓冲区序列，包含要写入的数据
         * @param token 完成令牌，用于接收写入结果
         * @return 异步操作结果，类型取决于完成令牌
         * @note 写入操作会阻塞，建议在协程中调用。
         * @warning 写入操作可能失败，请检查返回的错误码。
         * @warning 调用者必须确保 connector 在异步操作完成前保持有效。
         */
        template <typename ConstBufferSequence, typename CompletionToken>
        auto async_write_some(const ConstBufferSequence &buffers, CompletionToken &&token)
        {
            return ngx::transport::async_write_some(*trans_, buffers, std::forward<CompletionToken>(token));
        }

        // SSL Stream 需要的接口
        using lowest_layer_type = connector;

        /**
         * @brief 获取底层对象
         * @details 返回当前对象的引用，用于 SSL Stream 等需要
         * lowest_layer 接口的场景。
         * @return lowest_layer_type& 当前对象的引用
         */
        lowest_layer_type &lowest_layer()
        {
            return *this;
        }

        /**
         * @brief 获取底层对象（常量版本）
         * @details 返回当前对象的常量引用，用于 SSL Stream 等需要
         * lowest_layer 接口的场景。
         * @return const lowest_layer_type& 当前对象的常量引用
         */
        const lowest_layer_type &lowest_layer() const
        {
            return *this;
        }

        /**
         * @brief 获取底层传输层对象
         * @details 返回底层 transmission 对象的引用，用于直接访问传输层功能。
         * @return transmission_type& 传输层对象的引用
         */
        auto &transmission()
        {
            return *trans_;
        }

        /**
         * @brief 释放传输层所有权
         * @details 释放底层 transmission 对象的所有权，返回给调用者。
         * 释放后适配器不再持有传输层对象，不应再调用其任何方法。
         * 释放流程为所有权转移，将 trans_ 指针的所有权转移给返回值；
         * 指针重置，内部 trans_ 指针被重置为空；适配器失效，
         * 释放后适配器对象处于有效但不可用状态。
         * @return TransmissionPtr 传输层对象指针
         * @note 释放后适配器对象的 async_read_some 和 async_write_some
         * 方法不应再调用。
         * @warning 释放后继续使用适配器可能导致未定义行为。
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
