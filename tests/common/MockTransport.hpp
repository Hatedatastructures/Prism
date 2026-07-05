/**
 * @file MockTransport.hpp
 * @brief 传输层 Mock 实现，用于单元测试
 * @details 提供 MockTransport 类，继承 psm::transport::transmission 抽象接口，
 * 支持预注入读取数据、捕获写入数据、模拟读写错误等测试场景。
 * 内部持有 net::io_context 以提供有效的 executor，适用于需要异步读写的
 * 协议处理器、会话管理等模块的单元测试。
 * @note 该文件仅用于测试代码，不应被生产代码引用。
 * @note 挂起读通过定时器轮询实现，驱动 io_context 即可推进状态。
 */

#pragma once

#include <algorithm>
#include <optional>
#include <span>
#include <system_error>
#include <vector>

#include <prism/foundation/foundation.hpp>
#include <prism/net/transport/transmission.hpp>

namespace psm::testing
{
    namespace net = boost::asio;

    /**
     * @class MockTransport
     * @brief 传输层 Mock 实现
     * @details 继承 transmission 抽象接口，提供可控的读写行为用于单元测试。
     * 支持预注入读取数据队列、捕获所有写入数据、模拟读写错误。
     * 当读取队列为空时，async_read_some 会通过短定时器轮询挂起协程，
     * 驱动 io_context.run() 即可推进挂起的读操作。
     * 使用 PMR 容器保持与项目一致。
     */
    class MockTransport final : public psm::transport::transmission
    {
    public:
        /**
         * @brief 构造 MockTransport
         * @details 初始化内部 io_context 和 PMR 容器。
         */
        MockTransport()
            : read_queue_(&buffer_resource_)
            , written_data_(&buffer_resource_)
        {
        }

        /**
         * @brief 析构时标记关闭
         */
        ~MockTransport() override
        {
            closed_ = true;
        }

        // ── 禁止拷贝和移动 ──

        MockTransport(const MockTransport &) = delete;
        auto operator=(const MockTransport &) -> MockTransport & = delete;
        MockTransport(MockTransport &&) = delete;
        auto operator=(MockTransport &&) -> MockTransport & = delete;

        // ── transmission 接口实现 ──

        /**
         * @brief 获取关联的执行器
         * @return io_context 的 any_io_executor
         */
        [[nodiscard]] auto executor() const -> executor_type override
        {
            return const_cast<net::io_context &>(ioc_).get_executor();
        }

        /**
         * @brief 异步读取部分数据
         * @details 从注入队列中取出数据填入 buffer。如果队列有数据，立即返回；
         * 如果队列为空，通过短定时器轮询挂起协程，直到有数据注入或传输层被关闭。
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取的字节数
         */
        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            // 如果设置了读取错误，直接返回
            if (read_error_.has_value())
            {
                ec = read_error_.value();
                read_error_.reset();
                co_return 0;
            }

            // 如果队列不为空，立即返回数据
            if (!read_queue_.empty())
            {
                auto &chunk = read_queue_.front();
                const auto copy_size = (std::min)(chunk.size(), buffer.size());
                std::copy_n(chunk.data(), copy_size, buffer.data());
                if (copy_size >= chunk.size())
                {
                    // 整块已消费
                    read_queue_.erase(read_queue_.begin());
                }
                else
                {
                    // 部分消费，保留剩余字节
                    chunk.erase(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(copy_size));
                }
                co_return copy_size;
            }

            // 如果已经关闭，返回 eof
            if (closed_)
            {
                ec = psm::fault::code::eof;
                co_return 0;
            }

            // 队列为空，通过短定时器轮询等待数据注入
            while (!closed_ && read_queue_.empty() && !read_error_.has_value())
            {
                auto timer = net::steady_timer(co_await net::this_coro::executor);
                timer.expires_after(std::chrono::microseconds(100));
                co_await timer.async_wait(net::use_awaitable);
            }

            // 被关闭
            if (closed_)
            {
                ec = psm::fault::code::eof;
                co_return 0;
            }

            // 检查错误
            if (read_error_.has_value())
            {
                ec = read_error_.value();
                read_error_.reset();
                co_return 0;
            }

            // 取出数据
            if (!read_queue_.empty())
            {
                auto &chunk = read_queue_.front();
                const auto copy_size = (std::min)(chunk.size(), buffer.size());
                std::copy_n(chunk.data(), copy_size, buffer.data());
                if (copy_size >= chunk.size())
                {
                    read_queue_.erase(read_queue_.begin());
                }
                else
                {
                    chunk.erase(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(copy_size));
                }
                co_return copy_size;
            }

            ec = psm::fault::code::eof;
            co_return 0;
        }

        /**
         * @brief 异步写入部分数据
         * @details 将 buffer 数据追加到 written_data_ 缓冲区。
         * 如果设置了写入错误，直接返回错误。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 实际写入的字节数
         */
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (write_error_.has_value())
            {
                ec = write_error_.value();
                write_error_.reset();
                co_return 0;
            }

            if (closed_)
            {
                ec = psm::fault::code::eof;
                co_return 0;
            }

            const auto old_size = written_data_.size();
            written_data_.insert(written_data_.end(), buffer.begin(), buffer.end());
            co_return written_data_.size() - old_size;
        }

        /**
         * @brief 关闭传输层
         * @details 标记关闭状态，后续读写操作将返回 eof。
         */
        void close() override
        {
            closed_ = true;
        }

        /**
         * @brief 取消所有未完成的异步操作
         * @details 标记取消状态。
         */
        void cancel() override
        {
            cancelled_ = true;
        }

        // ── 测试辅助方法 ──

        /**
         * @brief 预注入读取数据
         * @details 将数据追加到读取队列，挂起的读操作将在下次轮询时获取数据。
         * 必须通过 io_context.run() 或 io_context.poll() 驱动才能被读协程感知。
         * @param data 要注入的数据
         */
        void inject_read(std::vector<std::byte> data)
        {
            read_queue_.push_back(std::move(data));
        }

        /**
         * @brief 通过原始字节指针和长度注入读取数据
         * @details 便捷方法，从原始指针构造 vector 后注入。
         * @param data 数据指针
         * @param size 数据长度
         */
        void inject_read(const std::byte *data, std::size_t size)
        {
            read_queue_.emplace_back(data, data + size);
        }

        /**
         * @brief 获取所有已写入的数据
         * @return 写入数据的 const 引用
         */
        [[nodiscard]] auto written_data() const -> const memory::vector<std::byte> &
        {
            return written_data_;
        }

        /**
         * @brief 清空已写入的数据缓冲区
         */
        void clear_written_data()
        {
            written_data_.clear();
        }

        /**
         * @brief 设置下次读取返回的错误码
         * @param ec 错误码
         */
        void set_read_error(std::error_code ec)
        {
            read_error_ = ec;
        }

        /**
         * @brief 设置下次写入返回的错误码
         * @param ec 错误码
         */
        void set_write_error(std::error_code ec)
        {
            write_error_ = ec;
        }

        /**
         * @brief 检查传输层是否已关闭
         * @return true 表示已关闭
         */
        [[nodiscard]] auto is_closed() const -> bool
        {
            return closed_;
        }

        /**
         * @brief 检查传输层是否已取消
         * @return true 表示已取消
         */
        [[nodiscard]] auto is_cancelled() const -> bool
        {
            return cancelled_;
        }

        /**
         * @brief 获取内部 io_context 引用
         * @details 可用于 io_context.run() 或 io_context.poll() 驱动异步操作完成。
         * @return io_context 的引用
         */
        [[nodiscard]] auto get_io_context() -> net::io_context &
        {
            return ioc_;
        }

    private:
        /** @brief 内部 io_context，提供 executor */
        net::io_context ioc_{1};

        /** @brief PMR 缓冲区内存资源 */
        memory::unsynchronized_pool buffer_resource_;

        /** @brief 读取队列，存储预注入的数据块 */
        memory::vector<std::vector<std::byte>> read_queue_;

        /** @brief 写入数据捕获缓冲区 */
        memory::vector<std::byte> written_data_;

        /** @brief 预设的读取错误码 */
        std::optional<std::error_code> read_error_;

        /** @brief 预设的写入错误码 */
        std::optional<std::error_code> write_error_;

        /** @brief 关闭状态标记 */
        bool closed_ = false;

        /** @brief 取消状态标记 */
        bool cancelled_ = false;
    };

} // namespace psm::testing
