/**
 * @file snapshot.hpp
 * @brief 可回滚的传输层包装器
 * @details 自动捕获所有从内层传输读取的字节，支持 rewind 回到起点重新读取。
 * 用于 TLS 伪装方案的依次尝试：每个 scheme 读取的数据被 snapshot 捕获，
 * 失败时 rewind，下一个 scheme 从同一起点重试。
 *
 * 设计约束：
 * - rewind 仅在未发生写入时有效（wrote_ == false）
 * - 认证阶段是纯读取，安全 rewind
 * - 一旦开始写入（如 TLS 握手），transport 状态不可恢复
 */

#pragma once

#include <cstring>
#include <span>
#include <system_error>

#include <boost/asio.hpp>

#include <prism/transport/transmission.hpp>
#include <prism/memory/container.hpp>

namespace psm::transport
{
    namespace net = boost::asio;

    /**
     * @class snapshot
     * @brief 可回滚的传输层装饰器
     * @details 包装内层传输，自动捕获所有读取的字节到内部缓冲区。
     * 支持 rewind 将读取位置归零，使下一个消费者能从同一起点读取。
     * 写入操作直接委托给内层传输，不缓冲。
     */
    class snapshot final : public transmission
    {
    public:
        /**
         * @brief 构造 snapshot 包装器
         * @param inner 被包装的内层传输
         * @param mr PMR 内存资源，用于 captured_ 缓冲区分配
         */
        explicit snapshot(shared_transmission inner,
                          memory::resource_pointer mr = memory::current_resource())
            : inner_(std::move(inner)), captured_(mr)
        {
        }

        /**
         * @brief 获取传输层类型
         * @details 委托给内层传输
         */
        [[nodiscard]] auto transport_type() const noexcept
            -> type override
        {
            return inner_ ? inner_->transport_type() : type::tcp;
        }

        /**
         * @brief 获取内层传输
         * @return 被包装的内层传输指针
         */
        [[nodiscard]] transmission *next_layer() noexcept override
        {
            return inner_.get();
        }

        [[nodiscard]] const transmission *next_layer() const noexcept override
        {
            return inner_.get();
        }

        /**
         * @brief 获取关联的执行器
         * @return 委托给内层传输
         * @throws std::runtime_error 如果内层传输为空
         */
        [[nodiscard]] executor_type executor() const override
        {
            if (!inner_)
                throw std::runtime_error("snapshot::executor() called on null inner");
            return inner_->executor();
        }

        /**
         * @brief 异步读取数据（带捕获和回放）
         * @details 两阶段读取：
         * 1. 若 captured_ 中有未回放的数据，从 captured_ 复制到 buffer（同步）
         * 2. 否则从内层传输读取，同时追加到 captured_（异步）
         * @param buffer 接收缓冲区
         * @param ec 错误码输出
         * @return 读取的字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!inner_)
            {
                ec = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }

            // Phase 1: 从 captured_ 回放
            if (read_pos_ < captured_.size())
            {
                const auto remaining = captured_.size() - read_pos_;
                const auto n = (std::min)(buffer.size(), remaining);
                std::memcpy(buffer.data(), captured_.data() + read_pos_, n);
                read_pos_ += n;
                ec = {};
                co_return n;
            }

            // Phase 2: 从内层读取并捕获
            const auto n = co_await inner_->async_read_some(buffer, ec);
            if (n > 0 && !ec)
            {
                captured_.insert(captured_.end(),
                                 buffer.data(), buffer.data() + n);
                read_pos_ += n;
            }
            co_return n;
        }

        /**
         * @brief 异步写入数据
         * @details 标记已写入（禁止 rewind），直接委托给内层传输。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出
         * @return 写入的字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            wrote_ = true;
            if (!inner_)
            {
                ec = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }
            co_return co_await inner_->async_write_some(buffer, ec);
        }

        /**
         * @brief 关闭传输层
         * @details 委托给内层传输
         */
        void close() override
        {
            if (inner_)
                inner_->close();
        }

        /**
         * @brief 取消所有未完成的异步操作
         * @details 委托给内层传输
         */
        void cancel() override
        {
            if (inner_)
                inner_->cancel();
        }

        /**
         * @brief 回滚读取位置到起点
         * @details 将 read_pos_ 归零，下次 async_read_some 将从 captured_ 起点回放。
         * 不清空 captured_ 数据。调用前应检查 can_rewind()。
         */
        void rewind() noexcept
        {
            read_pos_ = 0;
        }

        /**
         * @brief 检查是否可以回滚
         * @details 仅在未发生写入时可回滚。一旦写入过，transport 状态不可恢复。
         * @return true 如果可以回滚（未写入过数据）
         */
        [[nodiscard]] bool can_rewind() const noexcept
        {
            return !wrote_;
        }

        /**
         * @brief 获取内层传输
         * @return 内层传输的 shared_ptr
         */
        [[nodiscard]] auto inner() const noexcept
            -> shared_transmission
        {
            return inner_;
        }

    private:
        shared_transmission inner_;
        memory::vector<std::byte> captured_;
        std::size_t read_pos_{0};
        bool wrote_{false};
    };

    /**
     * @brief 创建 snapshot 包装器的工厂函数
     * @param inner 被包装的内层传输
     * @param mr PMR 内存资源
     * @return 包装后的 snapshot 传输
     */
    [[nodiscard]] inline auto make_snapshot(shared_transmission inner, memory::resource_pointer mr = memory::current_resource())
        -> shared_transmission
    {
        return std::make_shared<snapshot>(std::move(inner), mr);
    }

} // namespace psm::transport
