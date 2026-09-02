/**
 * @file ProductionMockTransport.hpp
 * @brief 传输层 Mock 实现，用于单元测试
 * @details 提供 ProductionMockTransport 类，继承
 * psm::transport::transmission 抽象接口，
 * 支持预注入读取数据、捕获写入数据、模拟读写错误等测试场景。
 * 内部持有 net::io_context 以提供有效的 executor，适用于需要异步读写的
 * 协议处理器、会话管理等模块的单元测试。
 * @note 该文件仅用于测试代码，不应被生产代码引用。
 * @note 挂起读通过定时器轮询实现，驱动 io_context 即可推进状态。
 */

#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/net/transport/transmission.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <system_error>
#include <vector>

namespace Psm::Testing
{
    namespace net = boost::asio;

    /**
     * @class ProductionMockTransport
     * @brief 传输层 Mock 实现
     * @details 继承 transmission 抽象接口，提供可控的读写行为用于单元测试。
     * 支持预注入读取数据队列、捕获所有写入数据、模拟读写错误。
     * 当读取队列为空时，async_read_some 会通过短定时器轮询挂起协程，
     * 驱动 io_context.run() 即可推进挂起的读操作。
     * 使用 PMR 容器保持与项目一致。
     */
    class ProductionMockTransport final : public psm::transport::transmission
    {
    public:
        /**
         * @brief 构造 ProductionMockTransport
         * @details 初始化内部 io_context 和 PMR 容器。
         */
        ProductionMockTransport() : ReadQueue_(&BufferResource_), WrittenData_(&BufferResource_)
        {
        }

        /**
         * @brief 析构时标记关闭
         */
        ~ProductionMockTransport() override
        {
            Closed_ = true;
        }

        // ── 禁止拷贝和移动 ──

        ProductionMockTransport(const ProductionMockTransport &) = delete;
        auto operator=(const ProductionMockTransport &) -> ProductionMockTransport & = delete;
        ProductionMockTransport(ProductionMockTransport &&) = delete;
        auto operator=(ProductionMockTransport &&) -> ProductionMockTransport & = delete;

        // ── transmission 接口实现 ──

        /**
         * @brief 获取关联的执行器
         * @return io_context 的 any_io_executor
         */
        [[nodiscard]] auto executor() const -> executor_type override
        {
            return const_cast<net::io_context &>(Ioc_).get_executor();
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
            if (ReadError_.has_value())
            {
                ec = ReadError_.value();
                ReadError_.reset();
                co_return 0;
            }

            // 如果队列不为空，立即返回数据
            if (!ReadQueue_.empty())
            {
                auto &chunk = ReadQueue_.front();
                const auto CopySize = (std::min)(chunk.size(), buffer.size());
                std::copy_n(chunk.data(), CopySize, buffer.data());
                if (CopySize >= chunk.size())
                {
                    // 整块已消费
                    ReadQueue_.erase(ReadQueue_.begin());
                }
                else
                {
                    // 部分消费，保留剩余字节
                    chunk.erase(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(CopySize));
                }
                co_return CopySize;
            }

            // 如果已经关闭或半关闭，返回 eof
            if (Closed_ || Shutdown_)
            {
                ec = psm::fault::code::eof;
                co_return 0;
            }

            // 队列为空，通过短定时器轮询等待数据注入或被取消
            while (!Closed_ && !Shutdown_ && !Cancelled_ && ReadQueue_.empty() && !ReadError_.has_value())
            {
                auto Timer = net::steady_timer(co_await net::this_coro::executor);
                Timer.expires_after(std::chrono::microseconds(100));
                co_await Timer.async_wait(net::use_awaitable);
            }

            // 被取消（一次性语义：cancel() 唤醒后返回 canceled，与 stream_handle 一致）
            if (Cancelled_)
            {
                Cancelled_ = false;
                ec = psm::fault::code::canceled;
                co_return 0;
            }

            // 被关闭或半关闭
            if (Closed_ || Shutdown_)
            {
                ec = psm::fault::code::eof;
                co_return 0;
            }

            // 检查错误
            if (ReadError_.has_value())
            {
                ec = ReadError_.value();
                ReadError_.reset();
                co_return 0;
            }

            // 取出数据
            if (!ReadQueue_.empty())
            {
                auto &chunk = ReadQueue_.front();
                const auto CopySize = (std::min)(chunk.size(), buffer.size());
                std::copy_n(chunk.data(), CopySize, buffer.data());
                if (CopySize >= chunk.size())
                {
                    ReadQueue_.erase(ReadQueue_.begin());
                }
                else
                {
                    chunk.erase(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(CopySize));
                }
                co_return CopySize;
            }

            ec = psm::fault::code::eof;
            co_return 0;
        }

        /**
         * @brief 异步写入部分数据
         * @details 将 buffer 数据追加到 WrittenData_ 缓冲区。
         * 如果设置了写入错误，直接返回错误。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 实际写入的字节数
         */
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            ++WritesDone;
            if (WriteError_.has_value())
            {
                ec = WriteError_.value();
                WriteError_.reset();
                co_return 0;
            }

            if (FailNextWrite || WritesDone == WriteFailAt)
            {
                FailNextWrite = false;
                ec = psm::fault::code::io_error;
                co_return 0;
            }

            if (Closed_)
            {
                ec = psm::fault::code::io_error;
                co_return 0;
            }

            if (OverreportWrite)
            {
                co_return buffer.size() + 1;
            }
            if (ZeroWrite)
            {
                co_return 0;
            }

            std::size_t Limit = MaxWrite;
            if (!WriteLimitSequence.empty())
            {
                Limit = WriteLimitSequence[(WritesDone - 1) % WriteLimitSequence.size()];
            }
            const auto Cap = Limit == 0 ? buffer.size() : (std::min)(buffer.size(), Limit);

            WrittenData_.insert(WrittenData_.end(), buffer.begin(),
                                buffer.begin() + static_cast<std::ptrdiff_t>(Cap));
            co_return Cap;
        }

        /**
         * @brief 半关闭（读端 EOF，写端仍可写）
         * @details 模拟 transmission::shutdown 语义：对端读返回 0，本端仍可写
         */
        void Shutdown()
        {
            Shutdown_ = true;
        }

        /**
         * @brief 关闭传输层
         * @details 标记关闭状态，后续读写操作将返回 eof。
         */
        void close() override
        {
            Closed_ = true;
        }

        /**
         * @brief 取消所有未完成的异步操作
         * @details 置取消标志并唤醒挂起读（返回 canceled，一次性）。
         */
        void cancel() override
        {
            Cancelled_ = true;
        }

        // ── 测试辅助方法 ──

        /**
         * @brief 预注入读取数据
         * @details 将数据追加到读取队列，挂起的读操作将在下次轮询时获取数据。
         * 必须通过 io_context.run() 或 io_context.poll() 驱动才能被读协程感知。
         * @param data 要注入的数据
         */
        void InjectRead(std::vector<std::byte> data)
        {
            ReadQueue_.push_back(std::move(data));
        }

        /**
         * @brief 通过原始字节指针和长度注入读取数据
         * @details 便捷方法，从原始指针构造 vector 后注入。
         * @param data 数据指针
         * @param size 数据长度
         */
        void InjectRead(const std::byte *data, std::size_t size)
        {
            ReadQueue_.emplace_back(data, data + size);
        }

        /**
         * @brief 获取所有已写入的数据
         * @return 写入数据的 const 引用
         */
        [[nodiscard]] auto WrittenData() const -> const psm::memory::vector<std::byte> &
        {
            return WrittenData_;
        }

        /**
         * @brief 清空已写入的数据缓冲区
         */
        void ClearWrittenData()
        {
            WrittenData_.clear();
        }

        /**
         * @brief 设置下次读取返回的错误码
         * @param ec 错误码
         */
        void SetReadError(std::error_code ec)
        {
            ReadError_ = ec;
        }

        /**
         * @brief 设置下次写入返回的错误码
         * @param ec 错误码
         */
        void SetWriteError(std::error_code ec)
        {
            WriteError_ = ec;
        }

        /// 单次写入后自动复位（注入单点写入错误）
        bool FailNextWrite{false};
        /// 第 N 次写入返回 eof（1 起；SIZE_MAX = 禁用）
        std::size_t WriteFailAt{std::numeric_limits<std::size_t>::max()};
        /// 单次写入返回字节数上限（0 = 不限制；>0 模拟半包写）
        std::size_t MaxWrite{0};
        /// 按调用次序变化的写入上限（非空时覆盖 MaxWrite，0 = 不限制）
        std::vector<std::size_t> WriteLimitSequence;
        /// 写入返回 0 且不设置错误（用于验证完整写入层的 zero-progress 处理）
        bool ZeroWrite{false};
        /// 写入返回超过请求长度（用于验证完整写入层的防御性检查）
        bool OverreportWrite{false};
        /// 已执行写入次数
        std::size_t WritesDone{0};

        /**
         * @brief 检查传输层是否已关闭
         * @return true 表示已关闭
         */
        [[nodiscard]] auto IsClosed() const -> bool
        {
            return Closed_;
        }

        /**
         * @brief 检查是否半关闭
         * @return true 表示已半关闭
         */
        [[nodiscard]] auto IsShutdown() const -> bool
        {
            return Shutdown_;
        }

        /**
         * @brief 检查传输层是否已取消
         * @return true 表示已取消
         */
        [[nodiscard]] auto IsCancelled() const -> bool
        {
            return Cancelled_;
        }

        /**
         * @brief 获取内部 io_context 引用
         * @details 可用于 io_context.run() 或 io_context.poll() 驱动异步操作完成。
         * @return io_context 的引用
         */
        [[nodiscard]] auto GetIoContext() -> net::io_context &
        {
            return Ioc_;
        }

    private:
        /** @brief 内部 io_context，提供 executor */
        net::io_context Ioc_{1};

        /** @brief PMR 缓冲区内存资源 */
        psm::memory::unsynchronized_pool BufferResource_;

        /** @brief 读取队列，存储预注入的数据块 */
        psm::memory::vector<std::vector<std::byte>> ReadQueue_;

        /** @brief 写入数据捕获缓冲区 */
        psm::memory::vector<std::byte> WrittenData_;

        /** @brief 预设的读取错误码 */
        std::optional<std::error_code> ReadError_;

        /** @brief 预设的写入错误码 */
        std::optional<std::error_code> WriteError_;

        /** @brief 半关闭标记（读 EOF，写仍可） */
        bool Shutdown_ = false;

        /** @brief 关闭状态标记 */
        bool Closed_ = false;

        /** @brief 取消状态标记 */
        bool Cancelled_ = false;
    };

} // namespace Psm::Testing
