/**
 * @file Snapshot.hpp
 * @brief 可回滚的传输层包装器
 * @details 自动捕获所有从内层传输读取的字节，支持 Rewind 回到起点重新读取。
 * 用于 TLS 伪装方案的依次尝试：每个 scheme 读取的数据被 Snapshot 捕获，
 * 失败时 Rewind，下一个 scheme 从同一起点重试。
 *
 * 设计约束：
 * - Rewind 仅在未发生写入时有效（Wrote_ == false）
 * - 认证阶段是纯读取，安全 Rewind
 * - 一旦开始写入（如 TLS 握手），transport 状态不可恢复
 */

#pragma once

#include <common/Core/Memory/Container.hpp>
#include <common/Core/Transmission.hpp>

#include <boost/asio.hpp>

#include <cstring>
#include <span>
#include <system_error>

namespace Preview::Transport
{

    namespace net = boost::asio;

    /**
     * @class Snapshot
     * @brief 可回滚的传输层装饰器
     * @details 包装内层传输，自动捕获所有读取的字节到内部缓冲区。
     * 支持 Rewind 将读取位置归零，使下一个消费者能从同一起点读取。
     * 写入操作直接委托给内层传输，不缓冲。
     */
    class Snapshot final : public Transmission
    {
    public:
        /**
         * @brief 构造 Snapshot 包装器
         * @param Inner 被包装的内层传输
         * @param mr PMR 内存资源，用于 Captured_ 缓冲区分配
         */
        explicit Snapshot(SharedTransmission Inner, Preview::Memory::ResourcePointer mr = Preview::Memory::CurrentResource())
            : Inner_(std::move(Inner)), Captured_(mr)
        {
        }

        /**
         * @brief 获取传输层类型
         * @details 委托给内层传输
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            if (Inner_)
            {
                return Inner_->TransportType();
            }
            return Type::Tcp;
        }

        /**
         * @brief 获取内层传输
         * @return 被包装的内层传输指针
         */
        [[nodiscard]] Transmission *NextLayer() noexcept override
        {
            return Inner_.get();
        }

        [[nodiscard]] const Transmission *NextLayer() const noexcept override
        {
            return Inner_.get();
        }

        /**
         * @brief 获取关联的执行器
         * @return 委托给内层传输
         * @throws std::runtime_error 如果内层传输为空
         */
        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            if (!Inner_)
            {
                throw std::runtime_error("Snapshot::Executor() called on null Inner");
            }
            return Inner_->Executor();
        }

        /**
         * @brief 异步读取数据（带捕获和回放）
         * @details 两阶段读取：
         * 1. 若 Captured_ 中有未回放的数据，从 Captured_ 复制到 Buffer（同步）
         * 2. 否则从内层传输读取，同时追加到 Captured_（异步）
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出
         * @return 读取的字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!Inner_)
            {
                ec = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }

            // Phase 1: 从 Captured_ 回放
            if (ReadPos_ < Captured_.size())
            {
                const auto Remaining = Captured_.size() - ReadPos_;
                const auto N = (std::min)(Buffer.size(), Remaining);
                std::memcpy(Buffer.data(), Captured_.data() + ReadPos_, N);
                ReadPos_ += N;
                ec = {};
                co_return N;
            }

            // Phase 2: 从内层读取并捕获
            const auto N = co_await Inner_->async_read_some(Buffer, ec);
            if (N > 0 && !ec)
            {
                Captured_.insert(Captured_.end(), Buffer.data(), Buffer.data() + N);
                ReadPos_ += N;
            }
            co_return N;
        }

        /**
         * @brief 异步写入数据
         * @details 标记已写入（禁止 Rewind），直接委托给内层传输。
         * @param Buffer 发送缓冲区
         * @param ec 错误码输出
         * @return 写入的字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            Wrote_ = true;
            if (!Inner_)
            {
                ec = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }
            co_return co_await Inner_->async_write_some(Buffer, ec);
        }

        /**
         * @brief 关闭传输层
         * @details 委托给内层传输
         */
        void Close() override
        {
            if (Inner_)
            {
                Inner_->Close();
            }
        }

        /**
         * @brief 取消所有未完成的异步操作
         * @details 委托给内层传输
         */
        void Cancel() override
        {
            if (Inner_)
            {
                Inner_->Cancel();
            }
        }

        /**
         * @brief 回滚读取位置到起点
         * @details 将 ReadPos_ 归零，下次 async_read_some 将从 Captured_ 起点回放。
         * 不清空 Captured_ 数据。调用前应检查 CanRewind()。
         */
        void Rewind() noexcept
        {
            ReadPos_ = 0;
        }

        /**
         * @brief 检查是否可以回滚
         * @details 仅在未发生写入时可回滚。一旦写入过，transport 状态不可恢复。
         * @return true 如果可以回滚（未写入过数据）
         */
        [[nodiscard]] auto CanRewind() const noexcept -> bool
        {
            return !Wrote_;
        }

        /**
         * @brief 获取内层传输
         * @return 内层传输的 shared_ptr
         */
        [[nodiscard]] auto Inner() const noexcept -> SharedTransmission
        {
            return Inner_;
        }

    private:
        SharedTransmission Inner_;
        Preview::Memory::vector<std::byte> Captured_; ///< 预读捕获缓冲（PMR 分配）
        std::size_t ReadPos_{0};
        bool Wrote_{false};
    };

    /**
     * @brief 创建 Snapshot 包装器的工厂函数
     * @param Inner 被包装的内层传输
     * @param mr PMR 内存资源
     * @return 包装后的 Snapshot 传输
     */
    [[nodiscard]] inline auto MakeSnapshot(SharedTransmission Inner,
                                            Preview::Memory::ResourcePointer mr = Preview::Memory::CurrentResource())
        -> SharedTransmission
    {
        return std::make_shared<Snapshot>(std::move(Inner), mr);
    }

} // namespace Preview::Transport
